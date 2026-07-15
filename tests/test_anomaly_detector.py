"""
test_anomaly_detector.py - AnomalyDetector Tests (#58)
========================================================

Coverage for ``alerts.anomaly_detector``: initialisation, feature
engineering, model training, and anomaly checks.  All database and
model-persistence calls are mocked.
"""

import sys
import os
from unittest.mock import patch, MagicMock, PropertyMock

import pytest
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def mock_alert_engine():
    """Minimal mock AlertEngine for DI."""
    engine = MagicMock()
    engine.create_alert.return_value = 1
    engine.create_anomaly_alert.return_value = 2
    return engine


@pytest.fixture
def detector(mock_alert_engine):
    """Create an AnomalyDetector with mocked persistence and DB."""
    with patch('alerts.anomaly_detector._os.path.exists', return_value=False):
        from alerts.anomaly_detector import AnomalyDetector
        det = AnomalyDetector(alert_engine=mock_alert_engine)
    return det


# ===================================================================
# Initialisation
# ===================================================================

class TestInit:

    def test_detector_created(self, detector):
        assert detector is not None
        assert detector.is_trained is False

    def test_detector_has_model(self, detector):
        from sklearn.ensemble import IsolationForest
        assert isinstance(detector.model, IsolationForest)

    def test_detector_counters_zero(self, detector):
        assert detector.anomaly_count == 0
        assert detector.check_count == 0


# ===================================================================
# Feature engineering
# ===================================================================

class TestFeatureEngineering:

    def test_prepare_features_empty_df(self, detector):
        df = pd.DataFrame()
        features = detector.prepare_features(df)
        assert features.shape[0] == 0

    def test_prepare_features_with_data(self, detector):
        from config import ANOMALY_DETECTION_FEATURES
        n = 20
        data = {f: np.random.rand(n) for f in ANOMALY_DETECTION_FEATURES}
        df = pd.DataFrame(data)
        features = detector.prepare_features(df)
        assert features.shape == (n, len(ANOMALY_DETECTION_FEATURES))

    def test_prepare_features_missing_columns(self, detector):
        """Missing features should be zero-filled, not crash."""
        df = pd.DataFrame({"total_bandwidth": np.random.rand(5)})
        features = detector.prepare_features(df)
        assert features.shape[0] == 5

    def test_prepare_features_handles_nan(self, detector):
        from config import ANOMALY_DETECTION_FEATURES
        data = {f: [float('nan')] * 3 for f in ANOMALY_DETECTION_FEATURES}
        df = pd.DataFrame(data)
        features = detector.prepare_features(df)
        assert not np.any(np.isnan(features))


# ===================================================================
# Training
# ===================================================================

class TestTraining:

    @patch('alerts.anomaly_detector.get_bandwidth_history')
    def test_train_with_enough_samples(self, mock_history, detector):
        """Training should succeed with enough data points."""
        from config import MIN_SAMPLES_FOR_ANOMALY_DETECTION, ANOMALY_DETECTION_FEATURES

        n = max(MIN_SAMPLES_FOR_ANOMALY_DETECTION, 50)
        rows = []
        for i in range(n):
            row = {"timestamp": f"2024-01-01 00:{i % 60:02d}:00", "bytes_per_second": 1000 * i}
            for f in ANOMALY_DETECTION_FEATURES:
                row[f] = float(i)
            rows.append(row)
        mock_history.return_value = rows

        result = detector.train_model(data=pd.DataFrame(rows))
        assert result is True
        assert detector.is_trained is True

    def test_train_with_too_few_samples(self, detector):
        """Training should fail gracefully with too few samples."""
        result = detector.train_model(data=pd.DataFrame())
        assert result is False


# ===================================================================
# Get stats / status
# ===================================================================

class TestStats:

    def test_get_stats_returns_dict(self, detector):
        stats = detector.get_stats()
        assert isinstance(stats, dict)
        assert "is_trained" in stats
        assert "anomaly_count" in stats
        assert "check_count" in stats
        assert "running" in stats


# ===================================================================
# Feature enrichment (regression: per-bucket variance, #Phase0)
# ===================================================================

class TestEnrichmentPerBucket:
    """Regression tests for _enrich_with_features.

    A previous implementation computed ONE aggregate feature dict over the
    whole history range and copied it to every row, collapsing 7 of the 8
    training features to constants.  These tests assert features are now
    joined per time bucket.
    """

    @staticmethod
    def _make_traffic_db():
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE traffic_summary (
                timestamp TEXT, source_ip TEXT, dest_ip TEXT,
                protocol TEXT, raw_protocol TEXT,
                bytes_transferred INTEGER, direction TEXT, is_control INTEGER
            )
        """)
        rows = []
        # Bucket A (10:00): DNS-heavy minute — 5 DNS + 2 TCP packets
        for i in range(5):
            rows.append(("2026-07-14 10:00:%02d" % (i * 5),
                         "192.168.1.10", "8.8.8.8", "DNS", "udp", 80, "upload", 0))
        for i in range(2):
            rows.append(("2026-07-14 10:00:%02d" % (30 + i),
                         "192.168.1.10", "1.2.3.4", "TCP", "tcp", 1500, "download", 0))
        # Bucket B (10:01): single HTTPS packet
        rows.append(("2026-07-14 10:01:10",
                     "192.168.1.11", "5.6.7.8", "HTTPS", "tls", 4000, "download", 0))
        conn.executemany(
            "INSERT INTO traffic_summary VALUES (?,?,?,?,?,?,?,?)", rows)
        conn.commit()
        return conn

    def _enrich(self, detector, history):
        from contextlib import contextmanager
        conn = self._make_traffic_db()

        @contextmanager
        def fake_get_connection():
            yield conn

        with patch('database.connection.get_connection', fake_get_connection):
            return detector._enrich_with_features(history)

    def test_features_vary_across_buckets(self, detector):
        history = [
            {"timestamp": "2026-07-14 10:00:00", "bytes_per_second": 100.0},
            {"timestamp": "2026-07-14 10:01:00", "bytes_per_second": 200.0},
        ]
        enriched = self._enrich(detector, history)
        assert len(enriched) == 2
        a, b = enriched

        # Bucket-specific counts, not a shared aggregate
        assert a["dns_queries_count"] == 5
        assert b["dns_queries_count"] == 0
        assert a["https_requests_count"] == 0
        assert b["https_requests_count"] == 1
        assert a["active_connections"] == 2
        assert b["active_connections"] == 1

        # The regression itself: rows must not share identical feature dicts
        keys = ["active_connections", "unique_protocols", "dns_queries_count",
                "http_requests_count", "https_requests_count"]
        assert any(a[k] != b[k] for k in keys)

    def test_bucket_without_traffic_gets_defaults(self, detector):
        history = [
            {"timestamp": "2026-07-14 10:00:00", "bytes_per_second": 100.0},
            {"timestamp": "2026-07-14 10:05:00", "bytes_per_second": 0.0},
        ]
        enriched = self._enrich(detector, history)
        quiet = enriched[1]
        assert quiet["dns_queries_count"] == 0
        assert quiet["active_connections"] == 0
        assert quiet["tcp_retransmit_ratio"] == 0.0

    def test_total_bandwidth_preserved(self, detector):
        history = [{"timestamp": "2026-07-14 10:00:00", "bytes_per_second": 123.4}]
        enriched = self._enrich(detector, history)
        assert enriched[0]["total_bandwidth"] == 123.4


# ===================================================================
# Capture-liveness gate (dead capture pipeline is not an anomaly)
# ===================================================================

class TestCaptureLivenessGate:
    """With the capture engine down, threshold and ML checks must pause —
    0 Mbps from a dead pipeline is missing data, not a network anomaly."""

    def _run_one_iteration(self, det, monkeypatch):
        """Drive exactly one pass of the monitor loop, past warmup."""
        det.detect_anomaly = MagicMock(return_value=(False, 0.0))
        det.check_thresholds = MagicMock()
        det._enrich_current_stats = MagicMock(return_value={"total_bandwidth": 0})
        det._enrich_with_features = MagicMock(return_value=[])
        det.train_model = MagicMock(return_value=False)

        stats = {"bandwidth_bps": 0, "device_count": 0}

        def stats_then_stop():
            det._shutdown_event.set()
            return stats

        # Monotonic clock stepping 200s per call: whatever call sets
        # _start_time, every later reading is >=200s past it, so the 120s
        # warmup window has always passed.  (Patching time.time also feeds
        # logging timestamps, so the consumption order is unpredictable.)
        import itertools
        clock = itertools.count(0.0, 200.0)
        monkeypatch.setattr(
            'alerts.anomaly_detector.time.time', lambda: float(next(clock))
        )
        monkeypatch.setattr(
            'alerts.anomaly_detector.get_bandwidth_history', lambda: []
        )
        monkeypatch.setattr(
            'alerts.anomaly_detector.get_realtime_stats', stats_then_stop
        )
        det.run()

    def test_checks_paused_while_capture_down(self, mock_alert_engine, monkeypatch):
        with patch('alerts.anomaly_detector._os.path.exists', return_value=False):
            from alerts.anomaly_detector import AnomalyDetector
            det = AnomalyDetector(
                alert_engine=mock_alert_engine,
                capture_alive_fn=lambda: False,
            )
        self._run_one_iteration(det, monkeypatch)
        det.detect_anomaly.assert_not_called()
        det.check_thresholds.assert_not_called()

    def test_checks_run_while_capture_alive(self, mock_alert_engine, monkeypatch):
        with patch('alerts.anomaly_detector._os.path.exists', return_value=False):
            from alerts.anomaly_detector import AnomalyDetector
            det = AnomalyDetector(
                alert_engine=mock_alert_engine,
                capture_alive_fn=lambda: True,
            )
        self._run_one_iteration(det, monkeypatch)
        det.detect_anomaly.assert_called_once()
        det.check_thresholds.assert_called_once()

    def test_no_gate_when_fn_not_provided(self, mock_alert_engine, monkeypatch):
        with patch('alerts.anomaly_detector._os.path.exists', return_value=False):
            from alerts.anomaly_detector import AnomalyDetector
            det = AnomalyDetector(alert_engine=mock_alert_engine)
        self._run_one_iteration(det, monkeypatch)
        det.detect_anomaly.assert_called_once()
        det.check_thresholds.assert_called_once()
