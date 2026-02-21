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
