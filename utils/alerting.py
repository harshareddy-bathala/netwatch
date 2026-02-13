"""
alerting.py - System Alert Manager
=====================================

Checks collected metrics against configurable thresholds and emits alerts
with a cooldown mechanism to prevent alert fatigue.

Usage::

    from utils.alerting import alert_manager

    alerts = alert_manager.check_thresholds({
        'cpu_percent': 85,
        'memory_mb': 600,
        'error_rate': 0.08,
    })
    for alert in alerts:
        logger.warning(alert['message'])
"""

import time
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Manage system-level alerts with cooldown.

    Thresholds are configurable; alerts are suppressed within a cooldown
    window to avoid flooding.
    """

    DEFAULT_THRESHOLDS: Dict[str, float] = {
        "cpu_percent": 80.0,
        "memory_mb": 500.0,
        "error_rate": 0.05,         # 5 %
        "packet_drop_rate": 0.01,   # 1 %
        "disk_usage_percent": 90.0,
        "db_size_mb": 2000.0,
    }

    def __init__(
        self,
        thresholds: Optional[Dict[str, float]] = None,
        cooldown_seconds: int = 300,
    ):
        self.thresholds = dict(self.DEFAULT_THRESHOLDS)
        if thresholds:
            self.thresholds.update(thresholds)

        self.cooldown_seconds = cooldown_seconds
        self._last_alert: Dict[str, float] = {}
        self._active_alerts: List[dict] = []

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def check_thresholds(self, metrics: dict) -> List[dict]:
        """
        Compare *metrics* against configured thresholds.

        Returns a list of alert dicts (may be empty if within cooldown or
        below thresholds).
        """
        alerts: List[dict] = []

        # CPU
        cpu = metrics.get("cpu_percent", 0)
        if cpu > self.thresholds["cpu_percent"]:
            alert = self._maybe_alert(
                key="high_cpu",
                alert_type="HIGH_CPU",
                severity="WARNING" if cpu < 95 else "CRITICAL",
                message=(
                    f"CPU usage is {cpu:.1f}% "
                    f"(threshold: {self.thresholds['cpu_percent']}%)"
                ),
            )
            if alert:
                alerts.append(alert)

        # Memory
        mem = metrics.get("memory_mb", 0)
        if mem > self.thresholds["memory_mb"]:
            alert = self._maybe_alert(
                key="high_memory",
                alert_type="HIGH_MEMORY",
                severity="WARNING" if mem < 800 else "CRITICAL",
                message=(
                    f"Memory usage is {mem:.1f} MB "
                    f"(threshold: {self.thresholds['memory_mb']} MB)"
                ),
            )
            if alert:
                alerts.append(alert)

        # Error rate
        err = metrics.get("error_rate", 0)
        if err > self.thresholds["error_rate"]:
            alert = self._maybe_alert(
                key="high_error_rate",
                alert_type="HIGH_ERROR_RATE",
                severity="CRITICAL",
                message=(
                    f"Error rate is {err * 100:.1f}% "
                    f"(threshold: {self.thresholds['error_rate'] * 100}%)"
                ),
            )
            if alert:
                alerts.append(alert)

        # Packet drop rate
        drop = metrics.get("packet_drop_rate", 0)
        if drop > self.thresholds["packet_drop_rate"]:
            alert = self._maybe_alert(
                key="high_packet_drop",
                alert_type="HIGH_PACKET_DROP",
                severity="WARNING",
                message=(
                    f"Packet drop rate is {drop * 100:.2f}% "
                    f"(threshold: {self.thresholds['packet_drop_rate'] * 100}%)"
                ),
            )
            if alert:
                alerts.append(alert)

        # Disk usage
        disk = metrics.get("disk_usage_percent", 0)
        if disk > self.thresholds["disk_usage_percent"]:
            alert = self._maybe_alert(
                key="high_disk",
                alert_type="HIGH_DISK_USAGE",
                severity="CRITICAL",
                message=(
                    f"Disk usage is {disk:.1f}% "
                    f"(threshold: {self.thresholds['disk_usage_percent']}%)"
                ),
            )
            if alert:
                alerts.append(alert)

        # Database size
        db = metrics.get("db_size_mb", 0)
        if db > self.thresholds["db_size_mb"]:
            alert = self._maybe_alert(
                key="large_db",
                alert_type="LARGE_DATABASE",
                severity="WARNING",
                message=(
                    f"Database size is {db:.0f} MB "
                    f"(threshold: {self.thresholds['db_size_mb']} MB)"
                ),
            )
            if alert:
                alerts.append(alert)

        # Log emitted alerts
        for a in alerts:
            if a["severity"] == "CRITICAL":
                logger.error("ALERT [%s]: %s", a["type"], a["message"])
            else:
                logger.warning("ALERT [%s]: %s", a["type"], a["message"])

        self._active_alerts = alerts
        return alerts

    def get_active_alerts(self) -> List[dict]:
        """Return the most recent set of alerts."""
        return list(self._active_alerts)

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------

    def _maybe_alert(self, *, key: str, alert_type: str, severity: str,
                     message: str) -> Optional[dict]:
        """Return an alert dict if the cooldown has elapsed, else None."""
        now = time.time()
        last = self._last_alert.get(key, 0)

        if now - last > self.cooldown_seconds:
            self._last_alert[key] = now
            return {
                "type": alert_type,
                "severity": severity,
                "message": message,
                "timestamp": now,
            }
        return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
alert_manager = AlertManager()
