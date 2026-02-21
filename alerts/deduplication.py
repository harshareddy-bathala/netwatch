"""
deduplication.py - Alert Deduplication System (Phase 4)
========================================================

Single source of truth for alert deduplication.  Replaces the two
conflicting systems that existed previously:
  - ``detector.py`` had ``_is_alert_duplicate()`` using value-specific keys
  - ``alert_manager.py`` had ``_should_throttle_alert()`` using hashed keys

Design principles
-----------------
* **One system** — every alert creation path goes through
  ``AlertDeduplicator``.
* **Key = alert_type:severity** — e.g. ``"device_count:critical"``.
  The *current value* is deliberately excluded so that a sustained
  high-bandwidth condition produces only one alert per cooldown window
  regardless of the exact Mbps reading.
* **Thread-safe** — protected by a ``threading.Lock``.
"""

import time
import threading
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class AlertDeduplicator:
    """
    Prevents duplicate alerts within a configurable cooldown window.

    Usage::

        dedup = AlertDeduplicator(cooldown_seconds=300)

        key = "bandwidth:critical"
        if dedup.should_throttle(key):
            return  # skip creation
        create_alert(...)
        dedup.record_alert(key)
    """

    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown = cooldown_seconds
        self.last_alerts: Dict[str, float] = {}   # key → unix timestamp
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_throttle(self, alert_key: str) -> bool:
        """Return ``True`` if the same alert was recorded within the cooldown."""
        with self._lock:
            self._cleanup_old_records()
            last_time = self.last_alerts.get(alert_key)
            if last_time is None:
                return False
            elapsed = time.time() - last_time
            if elapsed < self.cooldown:
                logger.debug(
                    "Throttled alert %s (%.0fs remaining)",
                    alert_key, self.cooldown - elapsed,
                )
                return True
            return False

    def record_alert(self, alert_key: str) -> None:
        """Record that an alert was just created."""
        with self._lock:
            self.last_alerts[alert_key] = time.time()

    def cleanup_old_records(self) -> int:
        """Public wrapper for manual cleanup.  Returns number of keys removed."""
        with self._lock:
            return self._cleanup_old_records()

    def reset(self) -> None:
        """Clear all recorded alerts (useful for testing)."""
        with self._lock:
            self.last_alerts.clear()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cleanup_old_records(self) -> int:
        """Remove records older than cooldown.  Caller must hold ``_lock``."""
        now = time.time()
        stale_keys = [
            key for key, ts in self.last_alerts.items()
            if now - ts >= self.cooldown
        ]
        for key in stale_keys:
            del self.last_alerts[key]
        if stale_keys:
            logger.debug("Dedup cleanup: removed %d stale keys", len(stale_keys))
        return len(stale_keys)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def make_key(alert_type: str, severity: str) -> str:
        """Build a canonical dedup key.

        For anomaly alerts, severity is preserved so that a critical anomaly
        can still fire even when a lower-severity warning is being suppressed.

        >>> AlertDeduplicator.make_key("bandwidth", "critical")
        'bandwidth:critical'
        >>> AlertDeduplicator.make_key("anomaly", "warning")
        'anomaly:warning'
        >>> AlertDeduplicator.make_key("anomaly", "critical")
        'anomaly:critical'
        """
        return f"{alert_type}:{severity}"

    def __repr__(self) -> str:
        return (
            f"AlertDeduplicator(cooldown={self.cooldown}s, "
            f"tracked={len(self.last_alerts)} keys)"
        )
