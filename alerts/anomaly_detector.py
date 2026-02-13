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

from config import (
    ISOLATION_FOREST_CONTAMINATION,
    MIN_SAMPLES_FOR_ANOMALY_DETECTION,
    ANOMALY_CHECK_INTERVAL,
    ANOMALY_DETECTION_FEATURES,
    LOG_LEVEL,
)

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

    def __init__(self, alert_engine: Optional[AlertEngine] = None):
        """
        Parameters
        ----------
        alert_engine : AlertEngine, optional
            Shared engine.  A new one is created if not provided.
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

        # Alert engine — single dedup system
        self.alert_engine = alert_engine or AlertEngine()

        # Runtime
        self.running = False
        self.lock = threading.Lock()

        logger.info("AnomalyDetector initialised")

    # ──────────────────────────────────────────────────────────────────────
    # Feature engineering
    # ──────────────────────────────────────────────────────────────────────

    def _enrich_with_features(self, history: list) -> list:
        """
        Enrich bandwidth history entries with all 8 ML features
        computed from the database, eliminating "using zeros" warnings.
        """
        if not history:
            return history

        try:
            from database.connection import get_connection
            from datetime import timedelta

            with get_connection() as conn:
                cursor = conn.cursor()

                enriched = []
                for entry in history:
                    ts = entry.get("timestamp", "")

                    # Compute features for this time bucket
                    total_bw = entry.get("bytes_per_second", 0) or entry.get("total_bytes", 0)

                    # Active connections: unique (src_ip, dst_ip) pairs
                    active_conns = 0
                    try:
                        cursor.execute("""
                            SELECT COUNT(DISTINCT source_ip || '-' || dest_ip) AS cnt
                            FROM traffic_summary
                            WHERE timestamp >= ? AND timestamp < datetime(?, '+1 minute')
                        """, (ts, ts))
                        row = cursor.fetchone()
                        active_conns = (row["cnt"] or 0) if row else 0
                    except Exception:
                        pass

                    # Unique protocols
                    unique_protos = 0
                    try:
                        cursor.execute("""
                            SELECT COUNT(DISTINCT protocol) AS cnt
                            FROM traffic_summary
                            WHERE timestamp >= ? AND timestamp < datetime(?, '+1 minute')
                        """, (ts, ts))
                        row = cursor.fetchone()
                        unique_protos = (row["cnt"] or 0) if row else 0
                    except Exception:
                        pass

                    # Protocol-specific counts
                    dns_count = http_count = https_count = 0
                    try:
                        cursor.execute("""
                            SELECT
                                SUM(CASE WHEN protocol = 'DNS' THEN 1 ELSE 0 END) AS dns,
                                SUM(CASE WHEN protocol = 'HTTP' THEN 1 ELSE 0 END) AS http,
                                SUM(CASE WHEN protocol IN ('HTTPS', 'TLS', 'SSL') THEN 1 ELSE 0 END) AS https
                            FROM traffic_summary
                            WHERE timestamp >= ? AND timestamp < datetime(?, '+1 minute')
                        """, (ts, ts))
                        row = cursor.fetchone()
                        if row:
                            dns_count = row["dns"] or 0
                            http_count = row["http"] or 0
                            https_count = row["https"] or 0
                    except Exception:
                        pass

                    enriched.append({
                        **entry,
                        "total_bandwidth": total_bw,
                        "active_connections": active_conns,
                        "unique_protocols": unique_protos,
                        "packet_loss_rate": 0,      # Cannot measure without ICMP/TCP retransmit data
                        "average_latency": 0,        # Would need RTT measurement
                        "dns_queries_count": dns_count,
                        "http_requests_count": http_count,
                        "https_requests_count": https_count,
                    })

                return enriched

        except Exception as exc:
            logger.warning("Feature enrichment failed: %s — falling back to basic features", exc)
            # Fallback: add basic features
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
            logger.info(
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
        ``anomaly_score`` is between 0 and 1.
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
                score = -self.model.score_samples(scaled)[0]

            is_anomaly = prediction == -1
            return is_anomaly, float(score)
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
        for accurate anomaly detection.
        """
        enriched = dict(stats)
        enriched.setdefault("total_bandwidth", stats.get("bandwidth_bps", 0))

        try:
            from database.connection import get_connection
            from datetime import timedelta

            with get_connection() as conn:
                cursor = conn.cursor()
                since = (datetime.now() - timedelta(seconds=STATS_COLLECTION_INTERVAL)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                # Active connections
                cursor.execute("""
                    SELECT COUNT(DISTINCT source_ip || '-' || dest_ip) AS cnt
                    FROM traffic_summary WHERE timestamp >= ?
                """, (since,))
                row = cursor.fetchone()
                enriched["active_connections"] = (row["cnt"] or 0) if row else 0

                # Unique protocols
                cursor.execute("""
                    SELECT COUNT(DISTINCT protocol) AS cnt
                    FROM traffic_summary WHERE timestamp >= ?
                """, (since,))
                row = cursor.fetchone()
                enriched["unique_protocols"] = (row["cnt"] or 0) if row else 0

                # Protocol-specific counts
                cursor.execute("""
                    SELECT
                        SUM(CASE WHEN protocol = 'DNS' THEN 1 ELSE 0 END) AS dns,
                        SUM(CASE WHEN protocol = 'HTTP' THEN 1 ELSE 0 END) AS http,
                        SUM(CASE WHEN protocol IN ('HTTPS', 'TLS', 'SSL') THEN 1 ELSE 0 END) AS https
                    FROM traffic_summary WHERE timestamp >= ?
                """, (since,))
                row = cursor.fetchone()
                if row:
                    enriched["dns_queries_count"] = row["dns"] or 0
                    enriched["http_requests_count"] = row["http"] or 0
                    enriched["https_requests_count"] = row["https"] or 0

        except Exception as exc:
            logger.debug("Stats enrichment error: %s", exc)

        # Set defaults for unmeasurable features
        enriched.setdefault("packet_loss_rate", 0)
        enriched.setdefault("average_latency", 0)
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

        while self.running:
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
                                "✅ Model trained on %d samples at %s",
                                n_samples, self.last_training_time.strftime('%Y-%m-%d %H:%M:%S'),
                            )
                            logger.info("✅ ML model trained successfully")
                except Exception as exc:
                    logger.error("History/training error: %s", exc)

                # --- Current stats ---
                try:
                    current_stats = get_realtime_stats()
                    if current_stats:
                        # Threshold-based alerts
                        self.check_thresholds(current_stats)

                        # Enrich current stats with ML features for detection
                        enriched_stats = self._enrich_current_stats(current_stats)

                        # Log current monitoring bandwidth
                        bw_bps = current_stats.get("bandwidth_bps", 0)
                        bw_mbps = (bw_bps * 8) / 1_000_000 if bw_bps else 0

                        # ML-based anomaly
                        is_anomaly, score = self.detect_anomaly(enriched_stats)
                        if is_anomaly:
                            self.anomaly_count += 1
                            severity = (
                                SEVERITY_CRITICAL if score > 0.7 else SEVERITY_WARNING
                            )
                            logger.warning(
                                "⚠️  ANOMALY DETECTED: Unusual pattern - %.1f Mbps "
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

            time.sleep(ANOMALY_CHECK_INTERVAL)

    def stop(self) -> None:
        """Gracefully stop the detector."""
        self.running = False
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
