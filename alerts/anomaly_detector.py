"""
anomaly_detector.py - ML Anomaly Detection (Phase 4 rewrite)
=============================================================

Keeps the Isolation Forest ML logic from the original ``detector.py``
but integrates with the new :class:`alerts.alert_engine.AlertEngine`
for **all** alert creation.

Key changes from the old ``detector.py``
-----------------------------------------
* Removed ``_is_alert_duplicate()`` — dedup is now in
  :class:`alerts.deduplication.AlertDeduplicator` via ``AlertEngine``.
* Uses ``get_active_device_count()`` from Phase 3 (private-IP only).
* Uses Phase 3 bandwidth / stats queries directly.
* All alerts go through ``AlertEngine.create_alert`` so dedup is enforced
  in one place.
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    import joblib
except ImportError:
    joblib = None  # type: ignore

from config import (
    ISOLATION_FOREST_CONTAMINATION,
    MIN_SAMPLES_FOR_ANOMALY_DETECTION,
    ANOMALY_CHECK_INTERVAL,
    ANOMALY_DETECTION_FEATURES,
    LOG_LEVEL,
)

import os as _os
_MODEL_DIR = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), 'models')
_MODEL_PATH = _os.path.join(_MODEL_DIR, 'anomaly_model.joblib')
_SCALER_PATH = _os.path.join(_MODEL_DIR, 'anomaly_scaler.joblib')

# Import stats collection interval (faster sampling)
try:
    from config import STATS_COLLECTION_INTERVAL
except ImportError:
    STATS_COLLECTION_INTERVAL = 10

from alerts.alert_engine import AlertEngine, SEVERITY_CRITICAL, SEVERITY_WARNING

# Phase 3 database queries
from database.queries.stats_queries import get_realtime_stats
from database.queries.traffic_queries import get_bandwidth_history
from database.queries.device_queries import get_active_device_count

logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))


class AnomalyDetector:
    """
    ML-based anomaly detector for network traffic.

    Uses Isolation Forest to detect unusual patterns in bandwidth,
    packet counts, active connections, protocol distribution, etc.
    """

    def __init__(self, alert_engine: AlertEngine, shutdown_event: Optional["threading.Event"] = None):
        """
        Parameters
        ----------
        alert_engine : AlertEngine
            Shared engine created in main.py and injected here.
        shutdown_event : threading.Event, optional
            If provided, ``run()`` will use ``event.wait()`` instead of
            ``time.sleep()`` so the detector shuts down promptly.
        """
        # ML model — tuned for network traffic anomalies
        self.model = IsolationForest(
            contamination=ISOLATION_FOREST_CONTAMINATION,
            random_state=42,
            n_estimators=200,      # More trees for better accuracy
            max_samples='auto',    # Let sklearn pick optimal sample size
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.last_training_time: Optional[datetime] = None

        # Counters
        self.anomaly_count = 0
        self.check_count = 0

        # Alert engine — single shared instance (dependency injection)
        self.alert_engine = alert_engine

        # Runtime
        self.running = False
        self._shutdown_event = shutdown_event or threading.Event()
        self.lock = threading.Lock()

        # Try to load persisted model from disk
        self._load_model()

        logger.info("AnomalyDetector initialised (persisted_model=%s)", self.is_trained)

    # ──────────────────────────────────────────────────────────────────────
    # Model persistence
    # ──────────────────────────────────────────────────────────────────────

    def _save_model(self) -> None:
        """Persist the trained IsolationForest and StandardScaler to disk."""
        if joblib is None:
            logger.debug("joblib not available — skipping model persistence")
            return
        try:
            _os.makedirs(_MODEL_DIR, exist_ok=True)
            joblib.dump(self.model, _MODEL_PATH)
            joblib.dump(self.scaler, _SCALER_PATH)
            logger.info("Model persisted to %s", _MODEL_PATH)
        except Exception as exc:
            logger.warning("Failed to persist model: %s", exc)

    def _load_model(self) -> None:
        """Reload a previously persisted model from disk (if available).

        If the model was trained with a different major.minor sklearn
        version, discard it and retrain from scratch to avoid silent
        prediction errors.
        """
        if joblib is None:
            return
        try:
            if _os.path.exists(_MODEL_PATH) and _os.path.exists(_SCALER_PATH):
                import warnings
                import sklearn

                # Load with warnings captured
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    loaded_model = joblib.load(_MODEL_PATH)
                    loaded_scaler = joblib.load(_SCALER_PATH)

                # Check if any InconsistentVersionWarning was raised
                version_mismatch = any(
                    issubclass(w.category, UserWarning)
                    and "InconsistentVersionWarning" in str(w.category.__name__)
                    for w in caught
                )

                if version_mismatch:
                    logger.warning(
                        "Persisted model was trained with a different sklearn "
                        "version — discarding and will retrain from scratch "
                        "(current sklearn %s)",
                        sklearn.__version__,
                    )
                    # Delete stale model files so they don't trip again
                    try:
                        _os.remove(_MODEL_PATH)
                        _os.remove(_SCALER_PATH)
                    except OSError:
                        pass
                    return  # leave is_trained = False → will retrain

                self.model = loaded_model
                self.scaler = loaded_scaler
                self.is_trained = True
                self.last_training_time = datetime.fromtimestamp(
                    _os.path.getmtime(_MODEL_PATH)
                )
                logger.info(
                    "Loaded persisted model from %s (trained %s)",
                    _MODEL_PATH,
                    self.last_training_time.strftime('%Y-%m-%d %H:%M:%S'),
                )
        except Exception as exc:
            logger.warning("Failed to load persisted model: %s", exc)

    # ──────────────────────────────────────────────────────────────────────
    # Feature engineering
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _query_traffic_features(cursor, since_ts: str, until_ts: str = None) -> dict:
        """Return all 8 ML features from a single batched SQL query.

        Parameters
        ----------
        cursor : sqlite3.Cursor
            An open cursor on the traffic_summary table.
        since_ts : str
            Lower bound timestamp (inclusive).
        until_ts : str or None
            Upper bound timestamp (exclusive).  When *None* the query has
            no upper bound (used by realtime enrichment).

        Returns
        -------
        dict with keys: active_connections, unique_protocols,
             dns_queries_count, http_requests_count, https_requests_count,
             tcp_retransmit_ratio, icmp_unreachable_rate.
        """
        defaults = {
            "active_connections": 0,
            "unique_protocols": 0,
            "dns_queries_count": 0,
            "http_requests_count": 0,
            "https_requests_count": 0,
            "tcp_retransmit_ratio": 0.0,
            "icmp_unreachable_rate": 0.0,
        }
        try:
            if until_ts:
                where = "WHERE timestamp >= ? AND timestamp < ?"
                params = (since_ts, until_ts)
            else:
                where = "WHERE timestamp >= ?"
                params = (since_ts,)

            cursor.execute(f"""
                SELECT
                    COUNT(DISTINCT source_ip || '-' || dest_ip) AS active_connections,
                    COUNT(DISTINCT protocol)                     AS unique_protocols,
                    SUM(CASE WHEN protocol = 'DNS' THEN 1 ELSE 0 END) AS dns,
                    SUM(CASE WHEN protocol = 'HTTP' THEN 1 ELSE 0 END) AS http,
                    SUM(CASE WHEN protocol IN ('HTTPS','TLS','SSL') THEN 1 ELSE 0 END) AS https,
                    SUM(CASE WHEN protocol = 'TCP' THEN 1 ELSE 0 END) AS tcp_total,
                    SUM(CASE WHEN protocol = 'TCP' AND raw_protocol LIKE '%retransmit%' THEN 1 ELSE 0 END) AS tcp_retransmit,
                    SUM(CASE WHEN protocol = 'ICMP' THEN 1 ELSE 0 END) AS icmp_total,
                    SUM(CASE WHEN protocol = 'ICMP' AND (raw_protocol LIKE '%unreachable%' OR raw_protocol LIKE '%dest-unreach%') THEN 1 ELSE 0 END) AS icmp_unreachable,
                    COUNT(*) AS total_packets
                FROM traffic_summary
                {where}
            """, params)
            row = cursor.fetchone()
            if not row:
                return defaults

            tcp_total = row["tcp_total"] or 0
            tcp_retransmit = row["tcp_retransmit"] or 0
            icmp_unreachable = row["icmp_unreachable"] or 0
            total_packets = row["total_packets"] or 0

            return {
                "active_connections": row["active_connections"] or 0,
                "unique_protocols": row["unique_protocols"] or 0,
                "dns_queries_count": row["dns"] or 0,
                "http_requests_count": row["http"] or 0,
                "https_requests_count": row["https"] or 0,
                "tcp_retransmit_ratio": (tcp_retransmit / tcp_total) if tcp_total > 0 else 0.0,
                "icmp_unreachable_rate": (icmp_unreachable / total_packets) if total_packets > 0 else 0.0,
            }
        except Exception:
            return defaults

    def _enrich_with_features(self, history: list) -> list:
        """
        Enrich bandwidth history entries with all 8 ML features
        computed from a single batched SQL query covering the full
        time range, instead of one query per entry.
        """
        if not history:
            return history

        try:
            from database.connection import get_connection

            # Determine the overall time range from history entries
            timestamps = []
            for entry in history:
                ts = entry.get("timestamp", "")
                if ts:
                    timestamps.append(ts)

            if not timestamps:
                return history

            min_ts = min(timestamps)
            max_ts = max(timestamps)

            with get_connection() as conn:
                cursor = conn.cursor()

                # Single query: compute features across the entire range
                feats = self._query_traffic_features(cursor, since_ts=min_ts)

                enriched = []
                for entry in history:
                    total_bw = entry.get("bytes_per_second", 0) or entry.get("total_bytes", 0)
                    enriched.append({
                        **entry,
                        "total_bandwidth": total_bw,
                        **feats,
                    })

                return enriched

        except Exception as exc:
            logger.warning("Feature enrichment failed: %s — falling back to basic features", exc)
            for entry in history:
                entry.setdefault("total_bandwidth", entry.get("bytes_per_second", 0))
                for f in ANOMALY_DETECTION_FEATURES:
                    entry.setdefault(f, 0)
            return history

    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Convert raw data to feature matrix for the ML model."""
        if data.empty:
            return np.array([]).reshape(0, len(ANOMALY_DETECTION_FEATURES))

        features_list = []
        missing_features = []
        for feature in ANOMALY_DETECTION_FEATURES:
            if feature in data.columns:
                features_list.append(data[feature].values)
            else:
                # Features are enriched upstream — missing ones are rare and expected
                # during startup.  Use debug level to avoid noisy warnings.
                missing_features.append(feature)
                features_list.append(np.zeros(len(data)))
        if missing_features:
            logger.debug("Features filled with defaults: %s", ", ".join(missing_features))

        if not features_list:
            return np.array([]).reshape(0, len(ANOMALY_DETECTION_FEATURES))

        features = np.column_stack(features_list)
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
        return features

    # ──────────────────────────────────────────────────────────────────────
    # Training
    # ──────────────────────────────────────────────────────────────────────

    def train_model(self, data) -> bool:
        """Train / retrain the Isolation Forest on historical data."""
        if isinstance(data, list):
            if not data:
                return False
            data = pd.DataFrame(data)

        if isinstance(data, pd.DataFrame) and data.empty:
            return False

        if len(data) < MIN_SAMPLES_FOR_ANOMALY_DETECTION:
            logger.debug(
                "Insufficient samples: %d < %d",
                len(data), MIN_SAMPLES_FOR_ANOMALY_DETECTION,
            )
            return False

        try:
            features = self.prepare_features(data)
            if features.size == 0:
                return False

            with self.lock:
                scaled = self.scaler.fit_transform(features)
                self.model.fit(scaled)
                self.is_trained = True
                self.last_training_time = datetime.now()

            # Persist to disk for reload on restart
            self._save_model()

            logger.info(
                "Model trained on %d samples at %s",
                len(data), self.last_training_time,
            )
            return True
        except Exception as exc:
            logger.error("Training error: %s", exc, exc_info=True)
            return False

    # ──────────────────────────────────────────────────────────────────────
    # Prediction
    # ──────────────────────────────────────────────────────────────────────

    def detect_anomaly(self, current_stats: Dict) -> Tuple[bool, float]:
        """
        Return ``(is_anomaly, anomaly_score)`` for the current snapshot.
        ``anomaly_score`` is normalized to the 0-1 scale using a sigmoid.
        """
        if not self.is_trained:
            return False, 0.0

        try:
            features_list = [
                float(current_stats.get(f, 0))
                for f in ANOMALY_DETECTION_FEATURES
            ]
            features = np.array(features_list).reshape(1, -1)
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

            with self.lock:
                scaled = self.scaler.transform(features)
                prediction = self.model.predict(scaled)[0]
                raw_score = -self.model.score_samples(scaled)[0]

            # Normalize raw score to 0-1 using sigmoid-like mapping.
            # score_samples returns negative log-likelihood; typical values
            # range ~0.3 (normal) to ~0.7+ (anomalous).  We map through
            # 1 / (1 + exp(-k*(x - x0))) with k=10, x0=0.5 so that
            # 0.5 maps to ~0.5 and values above 0.6 are clearly anomalous.
            normalized_score = 1.0 / (1.0 + np.exp(-10.0 * (raw_score - 0.5)))
            normalized_score = float(np.clip(normalized_score, 0.0, 1.0))

            is_anomaly = prediction == -1
            return is_anomaly, normalized_score
        except Exception as exc:
            logger.error("Anomaly detection error: %s", exc, exc_info=True)
            return False, 0.0

    # ──────────────────────────────────────────────────────────────────────
    # Threshold checks — delegated to AlertEngine
    # ──────────────────────────────────────────────────────────────────────

    def check_thresholds(self, stats: Dict) -> None:
        """Run all threshold checks against the current stats snapshot."""
        # Bandwidth
        current_bps = stats.get("total_bandwidth", 0)
        if current_bps:
            self.alert_engine.check_bandwidth_threshold(current_bps)

        # Device count (Phase 3 accurate count)
        self.alert_engine.check_device_threshold()

        # Health score (if available)
        health = stats.get("health_score")
        if health is not None:
            self.alert_engine.check_health_threshold(health)

    def _enrich_current_stats(self, stats: Dict) -> Dict:
        """
        Enrich current realtime stats with all 8 ML features
        for accurate anomaly detection.  Reuses ``_query_traffic_features``.
        """
        enriched = dict(stats)
        enriched.setdefault("total_bandwidth", stats.get("bandwidth_bps", 0))

        try:
            from database.connection import get_connection

            with get_connection() as conn:
                cursor = conn.cursor()
                since = (datetime.now() - timedelta(seconds=STATS_COLLECTION_INTERVAL)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                feats = self._query_traffic_features(cursor, since_ts=since)
                enriched.update(feats)
        except Exception as exc:
            logger.debug("Stats enrichment error: %s", exc)

        # Set defaults for features that need passive-capture computation
        enriched.setdefault("tcp_retransmit_ratio", 0)
        enriched.setdefault("icmp_unreachable_rate", 0)
        enriched.setdefault("dns_queries_count", 0)
        enriched.setdefault("http_requests_count", 0)
        enriched.setdefault("https_requests_count", 0)
        enriched.setdefault("active_connections", 0)
        enriched.setdefault("unique_protocols", 0)

        return enriched

    # ──────────────────────────────────────────────────────────────────────
    # Main loop
    # ──────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Background loop: train → predict → alert.  Runs in a daemon thread."""
        self.running = True
        logger.info(
            "AnomalyDetector started (min_samples=%d, check_interval=%ds, contamination=%.2f)",
            MIN_SAMPLES_FOR_ANOMALY_DETECTION, ANOMALY_CHECK_INTERVAL,
            ISOLATION_FOREST_CONTAMINATION,
        )
        retraining_interval = timedelta(minutes=30)
        _last_sample_log = 0  # track last logged sample count to reduce noise
        _start_time = time.time()
        # Warmup period: skip threshold alerts (device count, bandwidth, health)
        # for the first 120 seconds.  During warmup the system is initializing
        # interfaces, populating the traffic DB, and stabilizing mode context.
        # Running threshold checks too early produces false-positive alerts
        # (e.g. inflated device counts before mode-aware filtering kicks in).
        _WARMUP_SECONDS = 120

        while self.running and not self._shutdown_event.is_set():
            try:
                self.check_count += 1

                # --- Training / re-training ---
                try:
                    history = get_bandwidth_history()
                    needs_training = (
                        not self.is_trained
                        or self.last_training_time is None
                        or datetime.now() - self.last_training_time > retraining_interval
                    )
                    if needs_training:
                        # Enrich history with all ML features
                        enriched = self._enrich_with_features(history)
                        n_samples = len(enriched)

                        # Log sample collection progress
                        if n_samples < MIN_SAMPLES_FOR_ANOMALY_DETECTION:
                            if n_samples != _last_sample_log:
                                logger.info(
                                    "Collecting samples: %d < %d",
                                    n_samples, MIN_SAMPLES_FOR_ANOMALY_DETECTION,
                                )
                                _last_sample_log = n_samples
                        else:
                            if n_samples >= MIN_SAMPLES_FOR_ANOMALY_DETECTION and _last_sample_log < MIN_SAMPLES_FOR_ANOMALY_DETECTION:
                                logger.info(
                                    "Collecting samples: %d = %d",
                                    n_samples, MIN_SAMPLES_FOR_ANOMALY_DETECTION,
                                )

                        trained = self.train_model(enriched)
                        if trained:
                            _last_sample_log = n_samples
                            logger.info(
                                "Model trained on %d samples at %s",
                                n_samples, self.last_training_time.strftime('%Y-%m-%d %H:%M:%S'),
                            )
                            logger.info("ML model trained successfully")
                except Exception as exc:
                    logger.error("History/training error: %s", exc)

                # --- Current stats ---
                try:
                    current_stats = get_realtime_stats()
                    if current_stats:
                        # Threshold-based alerts — skip during warmup
                        if time.time() - _start_time >= _WARMUP_SECONDS:
                            self.check_thresholds(current_stats)
                        elif self.check_count <= 3:
                            logger.info(
                                "Warmup: skipping threshold checks (%ds remaining)",
                                int(_WARMUP_SECONDS - (time.time() - _start_time)),
                            )

                        # Enrich current stats with ML features for detection
                        enriched_stats = self._enrich_current_stats(current_stats)

                        # Log current monitoring bandwidth
                        bw_bps = current_stats.get("bandwidth_bps", 0)
                        bw_mbps = (bw_bps * 8) / 1_000_000 if bw_bps else 0

                        is_anomaly, score = self.detect_anomaly(enriched_stats)
                        if is_anomaly:
                            self.anomaly_count += 1
                            severity = (
                                SEVERITY_CRITICAL if score > 0.7 else SEVERITY_WARNING
                            )
                            logger.warning(
                                "ANOMALY DETECTED: Unusual pattern - %.1f Mbps "
                                "(score: %.2f, severity: %s)",
                                bw_mbps, score, severity,
                            )
                            self.alert_engine.create_anomaly_alert(
                                anomaly_score=score,
                                severity=severity,
                                details=current_stats,
                            )
                        elif self.is_trained and self.check_count % 10 == 0:
                            # Log periodic monitoring status (every 10 checks)
                            logger.info(
                                "Monitoring bandwidth: %.1f Mbps (normal)",
                                bw_mbps,
                            )
                    else:
                        logger.debug("No current stats available yet")
                except Exception as exc:
                    logger.error("Stats check error: %s", exc, exc_info=True)

            except Exception as exc:
                logger.error("Detector loop error: %s", exc, exc_info=True)

            self._shutdown_event.wait(ANOMALY_CHECK_INTERVAL)

    def stop(self) -> None:
        """Gracefully stop the detector."""
        self.running = False
        self._shutdown_event.set()
        logger.info(
            "AnomalyDetector stopped (checks=%d, anomalies=%d)",
            self.check_count, self.anomaly_count,
        )

    def get_stats(self) -> Dict:
        """Return detector diagnostics."""
        return {
            "is_trained": self.is_trained,
            "last_training_time": (
                self.last_training_time.isoformat()
                if self.last_training_time else None
            ),
            "anomaly_count": self.anomaly_count,
            "check_count": self.check_count,
            "anomaly_rate": (
                self.anomaly_count / self.check_count
                if self.check_count else 0
            ),
            "running": self.running,
        }
