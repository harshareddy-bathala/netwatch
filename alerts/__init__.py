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
# Old code may still do  ``from alerts import create_alert``.
# Instead of creating a private _default_engine (divergent state),
# these shims use a module-level reference that main.py sets via
# ``set_shared_engine(engine)`` after constructing the single AlertEngine.

_shared_engine: "AlertEngine | None" = None


def set_shared_engine(engine: "AlertEngine") -> None:
    """Set the shared AlertEngine instance (called once from main.py)."""
    global _shared_engine
    _shared_engine = engine


def _get_engine() -> "AlertEngine":
    """Return the shared engine, raising if not yet configured."""
    if _shared_engine is None:
        raise RuntimeError(
            "AlertEngine not initialised — call alerts.set_shared_engine() first"
        )
    return _shared_engine


def get_shared_engine() -> "AlertEngine | None":
    """Return the shared AlertEngine, or None if not yet configured."""
    return _shared_engine


def create_alert(alert_type, severity, message, details=None, **kw):
    """Backward-compat wrapper around AlertEngine.create_alert."""
    return _get_engine().create_alert(
        alert_type=alert_type,
        severity=severity,
        title=alert_type.replace("_", " ").title(),
        message=message,
        metadata=details,
    )


def create_bandwidth_alert(current, threshold, severity="warning"):
    return _get_engine().check_bandwidth_threshold(current)


def create_anomaly_alert(severity="warning", anomaly_score=0.0, details=None):
    return _get_engine().create_anomaly_alert(anomaly_score, severity, details)


def create_device_count_alert(current, threshold, severity="warning"):
    return _get_engine().check_device_threshold()


ALERT_MANAGER_AVAILABLE = True

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
    
    # DI helper
    "set_shared_engine",
    "get_shared_engine",
    
    # Functions
    "create_alert",
    "create_bandwidth_alert",
    "create_anomaly_alert",
    "create_device_count_alert",
]