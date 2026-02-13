"""
alerts package  (Phase 4)
=========================

Public API:
    AlertEngine          — centralised alert creation with dedup
    AlertDeduplicator    — cooldown-based deduplication
    AnomalyDetector      — ML anomaly detection (requires sklearn)
"""

import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ── Core (always available) ────────────────────────────────────────────
from alerts.deduplication import AlertDeduplicator          # noqa: F401
from alerts.alert_engine import AlertEngine                 # noqa: F401

ALERT_ENGINE_AVAILABLE = True

# ── ML detector (optional — needs pandas + sklearn) ────────────────────
try:
    from alerts.anomaly_detector import AnomalyDetector     # noqa: F401
    DETECTOR_AVAILABLE = True
except ImportError as e:
    logger.warning("AnomalyDetector not available: %s", e)
    AnomalyDetector = None  # type: ignore[assignment,misc]
    DETECTOR_AVAILABLE = False

# ── Backward-compat shims ─────────────────────────────────────────────
# Old code may still do  ``from alerts import create_alert``
try:
    from alerts.alert_engine import AlertEngine as _AE
    _default_engine = _AE()

    def create_alert(alert_type, severity, message, details=None, **kw):
        """Backward-compat wrapper around AlertEngine.create_alert."""
        return _default_engine.create_alert(
            alert_type=alert_type,
            severity=severity,
            title=alert_type.replace("_", " ").title(),
            message=message,
            metadata=details,
        )

    def create_bandwidth_alert(current, threshold, severity="warning"):
        return _default_engine.check_bandwidth_threshold(current)

    def create_anomaly_alert(severity="warning", anomaly_score=0.0, details=None):
        return _default_engine.create_anomaly_alert(anomaly_score, severity, details)

    def create_device_count_alert(current, threshold, severity="warning"):
        return _default_engine.check_device_threshold()

    ALERT_MANAGER_AVAILABLE = True
except Exception as e:
    logger.warning("Alert backward-compat shims unavailable: %s", e)
    create_alert = None
    create_bandwidth_alert = None
    create_anomaly_alert = None
    create_device_count_alert = None
    ALERT_MANAGER_AVAILABLE = False

# Package metadata
__version__ = "2.0.0"
__author__ = "NetWatch Team"
__all__ = [
    # Classes
    "AlertEngine",
    "AlertDeduplicator",
    "AnomalyDetector",
    "DETECTOR_AVAILABLE",
    "ALERT_MANAGER_AVAILABLE",
    
    # Functions
    "create_alert",
    "create_bandwidth_alert",
    "create_anomaly_alert",
    "create_device_count_alert",
]