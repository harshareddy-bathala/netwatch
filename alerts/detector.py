"""
detector.py - Anomaly Detection Module
=======================================

This module implements machine learning-based anomaly detection
for network traffic using the Isolation Forest algorithm.

OWNER: Member 1 (Project Lead)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from sklearn.ensemble import IsolationForest
   - import pandas as pd
   - import numpy as np
   - from database.db_handler import get_bandwidth_history, get_realtime_stats
   - from alerts.alert_manager import create_alert
   - from config import *

2. AnomalyDetector class with:
   - __init__(self): Initialize the IsolationForest model with configured contamination
   - train_model(self, data): Train/retrain the model on historical bandwidth data
   - detect_anomaly(self, current_stats): Check if current stats are anomalous
   - run(self): Main loop that runs periodically to check for anomalies

3. Helper functions:
   - prepare_features(data): Convert raw data to feature matrix for ML model
   - check_threshold_alerts(stats): Check if stats exceed configured thresholds

4. The detector should:
   - Run in a background thread
   - Check bandwidth data every ANOMALY_CHECK_INTERVAL seconds
   - Create alerts when anomalies are detected
   - Retrain the model periodically as new data comes in

EXAMPLE FUNCTION SIGNATURES:
----------------------------
class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=ISOLATION_FOREST_CONTAMINATION)
        self.is_trained = False
    
    def train_model(self, data: pd.DataFrame) -> bool:
        pass
    
    def detect_anomaly(self, current_stats: dict) -> bool:
        pass
    
    def run(self):
        while True:
            # Check for anomalies
            # Sleep for interval
            pass
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import (
    ISOLATION_FOREST_CONTAMINATION,
    MIN_SAMPLES_FOR_ANOMALY_DETECTION,
    ANOMALY_CHECK_INTERVAL,
    BANDWIDTH_WARNING_THRESHOLD,
    BANDWIDTH_CRITICAL_THRESHOLD,
    DEVICE_COUNT_WARNING,
    DEVICE_COUNT_CRITICAL,
    ANOMALY_DETECTION_FEATURES,
    ALERT_SEVERITY_HIGH,
    ALERT_SEVERITY_CRITICAL,
    ALERT_SEVERITY_MEDIUM,
    ALERT_SEVERITY_MAPPING,
    LOG_LEVEL,
)

# Import these when available - use try/except for graceful degradation
try:
    from database.db_handler import (
        get_bandwidth_history,
        get_realtime_stats,
        get_device_count,
    )
    from alerts import (
        create_alert,
        create_anomaly_alert,
        create_bandwidth_alert,
        create_device_count_alert,
    )
except ImportError as e:
    logging.warning(f"Database or alert modules not yet available: {e}")

# Configure module logger
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL))


class AnomalyDetector:
    """
    Machine learning-based anomaly detector for network traffic.
    
    Uses Isolation Forest algorithm to detect unusual patterns in:
    - Bandwidth usage
    - Packet counts
    - Active connections
    - Protocol distribution
    - And other network metrics
    """

    def __init__(self):
        """Initialize the Isolation Forest model with configured contamination."""
        self.model = IsolationForest(
            contamination=ISOLATION_FOREST_CONTAMINATION,
            random_state=42,
            n_estimators=100,
            n_jobs=-1,  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.last_training_time: Optional[datetime] = None
        self.anomaly_count = 0
        self.check_count = 0
        self.last_anomaly_ids: Dict[str, datetime] = {}  # For deduplication
        self.running = False
        self.lock = threading.Lock()
        
        logger.info("AnomalyDetector initialized")

    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """
        Convert raw data to feature matrix for ML model.
        
        Args:
            data: DataFrame with traffic statistics
            
        Returns:
            Feature matrix as numpy array
        """
        if data.empty:
            logger.warning("Empty data provided to prepare_features")
            return np.array([]).reshape(0, len(ANOMALY_DETECTION_FEATURES))

        features_list = []
        
        for feature in ANOMALY_DETECTION_FEATURES:
            if feature in data.columns:
                features_list.append(data[feature].values)
            else:
                # Use zero for missing features
                logger.warning(f"Feature '{feature}' not found in data, using zeros")
                features_list.append(np.zeros(len(data)))
        
        if not features_list:
            logger.error("No valid features found for anomaly detection")
            return np.array([]).reshape(0, len(ANOMALY_DETECTION_FEATURES))
        
        # Stack features into matrix (samples x features)
        features = np.column_stack(features_list)
        
        # Handle NaN and infinite values
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
        
        return features

    def train_model(self, data: pd.DataFrame) -> bool:
        """
        Train/retrain the model on historical bandwidth data.
        
        Args:
            data: DataFrame or list with historical traffic data
            
        Returns:
            True if training successful, False otherwise
        """
        # Convert list to DataFrame if needed
        if isinstance(data, list):
            if not data:
                logger.warning("Cannot train model: empty dataset")
                return False
            data = pd.DataFrame(data)
        
        if data.empty:
            logger.warning("Cannot train model: empty dataset")
            return False

        if len(data) < MIN_SAMPLES_FOR_ANOMALY_DETECTION:
            logger.info(
                f"Insufficient samples for training: {len(data)} < {MIN_SAMPLES_FOR_ANOMALY_DETECTION}"
            )
            return False

        try:
            # Prepare features
            features = self.prepare_features(data)
            
            if features.size == 0:
                logger.error("Failed to prepare features for training")
                return False

            # Scale features for better model performance
            with self.lock:
                scaled_features = self.scaler.fit_transform(features)
                self.model.fit(scaled_features)
                self.is_trained = True
                self.last_training_time = datetime.now()

            logger.info(
                f"Model trained successfully on {len(data)} samples at {self.last_training_time}"
            )
            return True

        except Exception as e:
            logger.error(f"Error training model: {e}", exc_info=True)
            return False

    def detect_anomaly(self, current_stats: Dict) -> Tuple[bool, float]:
        """
        Check if current stats are anomalous.
        
        Args:
            current_stats: Dictionary with current network statistics
            
        Returns:
            Tuple of (is_anomaly: bool, anomaly_score: float)
                where anomaly_score is between 0 and 1
        """
        if not self.is_trained:
            logger.debug("Model not trained yet, skipping anomaly detection")
            return False, 0.0

        try:
            # Extract features in same order as training
            features_list = []
            for feature in ANOMALY_DETECTION_FEATURES:
                value = current_stats.get(feature, 0)
                features_list.append(float(value))
            
            features = np.array(features_list).reshape(1, -1)
            
            # Handle NaN and infinite values
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

            # Scale using the same scaler as training
            with self.lock:
                scaled_features = self.scaler.transform(features)
                prediction = self.model.predict(scaled_features)[0]
                # Get anomaly score (distance to normal region)
                score = -self.model.score_samples(scaled_features)[0]

            is_anomaly = prediction == -1
            
            logger.debug(f"Anomaly detection: is_anomaly={is_anomaly}, score={score:.4f}")
            return is_anomaly, float(score)

        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}", exc_info=True)
            return False, 0.0

    def check_threshold_alerts(self, stats: Dict) -> None:
        """
        Check if stats exceed configured thresholds and create alerts.
        
        Args:
            stats: Dictionary with current network statistics
        """
        # Check bandwidth thresholds
        current_bandwidth = stats.get("total_bandwidth", 0)
        
        if current_bandwidth >= BANDWIDTH_CRITICAL_THRESHOLD:
            alert_key = f"bandwidth_critical_{int(current_bandwidth)}"
            if not self._is_alert_duplicate(alert_key):
                try:
                    create_bandwidth_alert(
                        current=current_bandwidth,
                        threshold=BANDWIDTH_CRITICAL_THRESHOLD,
                        severity=ALERT_SEVERITY_CRITICAL,
                    )
                    logger.warning(
                        f"Bandwidth critical alert: {current_bandwidth} bytes/s "
                        f">= {BANDWIDTH_CRITICAL_THRESHOLD}"
                    )
                except Exception as e:
                    logger.error(f"Failed to create bandwidth critical alert: {e}")
                    
        elif current_bandwidth >= BANDWIDTH_WARNING_THRESHOLD:
            alert_key = f"bandwidth_warning_{int(current_bandwidth)}"
            if not self._is_alert_duplicate(alert_key):
                try:
                    create_bandwidth_alert(
                        current=current_bandwidth,
                        threshold=BANDWIDTH_WARNING_THRESHOLD,
                        severity=ALERT_SEVERITY_MEDIUM,
                    )
                    logger.warning(
                        f"Bandwidth warning alert: {current_bandwidth} bytes/s "
                        f">= {BANDWIDTH_WARNING_THRESHOLD}"
                    )
                except Exception as e:
                    logger.error(f"Failed to create bandwidth warning alert: {e}")

        # Check device count thresholds
        try:
            device_count = get_device_count()
            
            if device_count >= DEVICE_COUNT_CRITICAL:
                alert_key = f"device_count_critical_{device_count}"
                if not self._is_alert_duplicate(alert_key):
                    try:
                        create_device_count_alert(
                            current=device_count,
                            threshold=DEVICE_COUNT_CRITICAL,
                            severity=ALERT_SEVERITY_HIGH,
                        )
                        logger.warning(
                            f"Device count critical alert: {device_count} devices "
                            f">= {DEVICE_COUNT_CRITICAL}"
                        )
                    except Exception as e:
                        logger.error(f"Failed to create device count critical alert: {e}")
                        
            elif device_count >= DEVICE_COUNT_WARNING:
                alert_key = f"device_count_warning_{device_count}"
                if not self._is_alert_duplicate(alert_key):
                    try:
                        create_device_count_alert(
                            current=device_count,
                            threshold=DEVICE_COUNT_WARNING,
                            severity=ALERT_SEVERITY_MEDIUM,
                        )
                        logger.warning(
                            f"Device count warning alert: {device_count} devices "
                            f">= {DEVICE_COUNT_WARNING}"
                        )
                    except Exception as e:
                        logger.error(f"Failed to create device count warning alert: {e}")
                        
        except Exception as e:
            logger.error(f"Error checking device count thresholds: {e}", exc_info=True)

    def _is_alert_duplicate(self, alert_key: str, cooldown_minutes: int = 5) -> bool:
        """
        Check if same alert was recently created (deduplication).
        
        Args:
            alert_key: Unique identifier for the alert
            cooldown_minutes: Minutes to wait before allowing same alert again
            
        Returns:
            True if this is a duplicate/recent alert, False if it's new
        """
        now = datetime.now()
        cooldown = timedelta(minutes=cooldown_minutes)
        
        if alert_key in self.last_anomaly_ids:
            last_time = self.last_anomaly_ids[alert_key]
            if now - last_time < cooldown:
                return True
        
        self.last_anomaly_ids[alert_key] = now
        return False

    def run(self) -> None:
        """
        Main loop that runs in background thread.
        
        Periodically:
        1. Fetches historical data
        2. Trains/retrains the model if needed
        3. Gets current stats
        4. Checks for anomalies
        5. Creates alerts when anomalies detected
        6. Checks threshold-based alerts
        """
        self.running = True
        logger.info("AnomalyDetector started")
        
        retraining_interval = timedelta(hours=1)  # Retrain every hour
        
        while self.running:
            try:
                self.check_count += 1
                
                # Get historical data and train model if not trained or stale
                try:
                    history_data = get_bandwidth_history()
                    
                    if not self.is_trained or (
                        self.last_training_time is None
                        or datetime.now() - self.last_training_time > retraining_interval
                    ):
                        self.train_model(history_data)
                        
                except Exception as e:
                    logger.error(f"Error fetching/training on historical data: {e}")

                # Get current statistics
                try:
                    current_stats = get_realtime_stats()
                    
                    if current_stats:
                        # Check threshold-based alerts
                        self.check_threshold_alerts(current_stats)
                        
                        # Check ML-based anomalies
                        is_anomaly, anomaly_score = self.detect_anomaly(current_stats)
                        
                        if is_anomaly:
                            self.anomaly_count += 1
                            alert_key = f"ml_anomaly_{int(anomaly_score * 1000)}"
                            
                            if not self._is_alert_duplicate(alert_key):
                                try:
                                    create_anomaly_alert(
                                        severity=ALERT_SEVERITY_HIGH,
                                        anomaly_score=anomaly_score,
                                        details=current_stats,
                                    )
                                    logger.warning(
                                        f"ML Anomaly detected (score={anomaly_score:.4f}): {current_stats}"
                                    )
                                except Exception as e:
                                    logger.error(f"Failed to create anomaly alert: {e}")
                    else:
                        logger.debug("No current stats available yet")
                        
                except Exception as e:
                    logger.error(f"Error checking current stats: {e}", exc_info=True)

            except Exception as e:
                logger.error(f"Unexpected error in anomaly detector loop: {e}", exc_info=True)

            # Sleep before next check
            time.sleep(ANOMALY_CHECK_INTERVAL)

    def stop(self) -> None:
        """Stop the anomaly detector gracefully."""
        self.running = False
        logger.info(
            f"AnomalyDetector stopped (checks: {self.check_count}, "
            f"anomalies: {self.anomaly_count})"
        )

    def get_stats(self) -> Dict:
        """
        Get detector statistics.
        
        Returns:
            Dictionary with current statistics
        """
        return {
            "is_trained": self.is_trained,
            "last_training_time": (
                self.last_training_time.isoformat() if self.last_training_time else None
            ),
            "anomaly_count": self.anomaly_count,
            "check_count": self.check_count,
            "anomaly_rate": (
                self.anomaly_count / self.check_count if self.check_count > 0 else 0
            ),
            "running": self.running,
        }
