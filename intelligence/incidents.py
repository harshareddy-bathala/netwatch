"""
incidents.py - Alert → Incident Fusion (Phase 2, AI-first)
===========================================================

The alert stream dedups by *type*, so one noisy device produces a wall
of disconnected rows: a port-scan alert, a behavior anomaly, a rogue
device notice — all the same story, told three times.  IncidentManager
fuses them:

* Every persisted alert is offered to :meth:`triage`.
* Alerts carrying the same ``device_mac`` (or none — network-wide) that
  arrive within ``INCIDENT_WINDOW_MINUTES`` of an open incident's last
  activity join that incident; otherwise a new incident opens.
* The incident rolls up: max severity, distinct categories, alert count,
  and a title that names the lead category plus the device.

Triage runs synchronously on the alert path but is exception-safe and
cheap (two indexed queries); a triage failure never blocks the alert.
"""

import logging
import threading
from datetime import datetime, timedelta
from typing import List, Optional

from config import INCIDENT_WINDOW_MINUTES
from database.queries import incident_queries

logger = logging.getLogger(__name__)

_TS_FMT = "%Y-%m-%d %H:%M:%S"

# Alert severities from lowest to highest (matches the alerts CHECK).
_SEVERITY_ORDER = ["info", "low", "medium", "warning", "high", "critical"]

# Human titles per alert category, used for the incident headline.
_CATEGORY_TITLES = {
    "security": "Security threat",
    "anomaly": "Traffic anomaly",
    "bandwidth": "Bandwidth issue",
    "device_count": "Device-count change",
    "health": "Health degradation",
    "protocol": "Protocol issue",
    "connection": "Connection issue",
    "new_device": "New device",
    "custom": "Custom rule",
}


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def _max_severity(a: str, b: str) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else b


class IncidentManager:
    """Fuses alerts into incidents.  One instance per process, attached
    to the shared AlertEngine at startup."""

    def __init__(self, window_minutes: int = INCIDENT_WINDOW_MINUTES):
        self._window = timedelta(minutes=window_minutes)
        self._lock = threading.Lock()
        self.triaged_count = 0
        self.incidents_opened = 0

    # ------------------------------------------------------------------

    def triage(
        self,
        alert_id: int,
        alert_type: str,
        severity: str,
        device_mac: Optional[str] = None,
        message: str = "",
    ) -> Optional[int]:
        """Attach the alert to an open incident or open a new one.

        Returns the incident id, or ``None`` when triage failed (the
        alert itself is unaffected either way).
        """
        try:
            with self._lock:
                return self._triage_locked(
                    alert_id, alert_type, severity, device_mac, message
                )
        except Exception:
            logger.exception("Incident triage failed for alert #%s", alert_id)
            return None

    def _triage_locked(
        self,
        alert_id: int,
        alert_type: str,
        severity: str,
        device_mac: Optional[str],
        message: str,
    ) -> Optional[int]:
        mac = device_mac.lower() if device_mac else None
        window_start = (datetime.now() - self._window).strftime(_TS_FMT)

        incident = incident_queries.find_open_incident(mac, window_start)
        if incident:
            categories = incident.get("categories")
            if not isinstance(categories, list):  # defensive: always decoded
                categories = []
            categories = list(categories)
            if alert_type not in categories:
                categories.append(alert_type)
            merged_severity = _max_severity(
                incident.get("severity") or "info", severity
            )
            if incident_queries.attach_alert(
                incident["id"], alert_id, merged_severity, categories
            ):
                self.triaged_count += 1
                logger.info(
                    "Alert #%d fused into incident #%d (%s, %d alerts)",
                    alert_id, incident["id"], merged_severity,
                    (incident.get("alert_count") or 0) + 1,
                )
                return incident["id"]
            return None

        title = self._make_title(alert_type, mac, message)
        incident_id = incident_queries.create_incident(
            title=title,
            severity=severity,
            device_mac=mac,
            categories=[alert_type],
            summary=message[:300] if message else None,
        )
        if incident_id:
            incident_queries.attach_alert(
                incident_id, alert_id, severity, [alert_type]
            )
            self.triaged_count += 1
            self.incidents_opened += 1
            logger.info(
                "Incident #%d opened for alert #%d [%s/%s]%s",
                incident_id, alert_id, alert_type, severity,
                f" on {mac}" if mac else "",
            )
        return incident_id

    # ------------------------------------------------------------------

    @staticmethod
    def _make_title(alert_type: str, mac: Optional[str], message: str) -> str:
        base = _CATEGORY_TITLES.get(alert_type, alert_type.replace("_", " ").title())
        return f"{base} on {mac}" if mac else base

    def get_stats(self) -> dict:
        return {
            "triaged_count": self.triaged_count,
            "incidents_opened": self.incidents_opened,
            "window_minutes": int(self._window.total_seconds() // 60),
        }
