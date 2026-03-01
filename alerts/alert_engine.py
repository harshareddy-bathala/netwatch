"""
alert_engine.py - Centralized Alert Creation & Threshold Checking (Phase 4)
============================================================================

This module **replaces** the old ``alert_manager.py``.  It provides:

* ``AlertEngine`` — the single entry point for creating alerts.
* Threshold checks for bandwidth, device count, and health score.
* Integration with :class:`alerts.deduplication.AlertDeduplicator` to
  guarantee at most one alert per ``(type, severity)`` per cooldown window.
* Accurate device counts via ``get_active_device_count()`` from Phase 3.

.. note::
   The legacy ``detector.py`` (Isolation Forest AnomalyDetector stub) was
   removed in the Phase 5 cleanup.  All anomaly detection now lives in
   ``anomaly_detector.py``; all threshold alerting lives here.

Alert lifecycle
---------------
1. **Created**   — ``acknowledged=False, resolved=False``  → counts in badge, shows in UI
2. **Acknowledged** — ``acknowledged=True,  resolved=False``  → shows in UI, NOT in badge
3. **Resolved**  — ``resolved=True``                        → hidden from active list

Usage::

    from alerts.alert_engine import AlertEngine

    engine = AlertEngine()
    engine.check_device_threshold()
    engine.check_bandwidth_threshold(current_bps=25_000_000)
    engine.check_health_threshold(health_score=42)
"""

import json
import logging
from typing import Optional, Dict, Any

from config import (
    BANDWIDTH_WARNING_MBPS,
    BANDWIDTH_CRITICAL_MBPS,
    DEVICE_COUNT_WARNING,
    DEVICE_COUNT_CRITICAL,
    HEALTH_SCORE_WARNING,
    HEALTH_SCORE_CRITICAL,
    ALERT_COOLDOWN_SECONDS,
)

from alerts.deduplication import AlertDeduplicator

# Phase 3 database helpers
from database.queries.alert_queries import (
    create_alert as db_create_alert,
    get_alerts as db_get_alerts,
    acknowledge_alert as db_acknowledge_alert,
    resolve_alert as db_resolve_alert,
    count_alerts as db_count_alerts,
    get_alert_summary as db_get_alert_summary,
)
from database.queries.device_queries import get_active_device_count

logger = logging.getLogger(__name__)

# ── Severity / type constants ──────────────────────────────────────────────

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"

ALERT_BANDWIDTH = "bandwidth"
ALERT_ANOMALY = "anomaly"
ALERT_DEVICE_COUNT = "device_count"
ALERT_HEALTH = "health"
ALERT_NEW_DEVICE = "new_device"
ALERT_SECURITY = "security"


class AlertEngine:
    """
    Centralised alert creation with deduplication and threshold checking.

    Every component (anomaly-detector, bandwidth-calculator, …) should
    create alerts *exclusively* through this engine so that dedup is
    enforced in one place.
    """

    def __init__(self, cooldown_seconds: int = ALERT_COOLDOWN_SECONDS):
        self.dedup = AlertDeduplicator(cooldown_seconds=cooldown_seconds)

        # Per-instance mutable state (was incorrectly a class variable)
        self._mac_whitelist: set = set()
        self._known_macs: set = set()
        self._known_ips: set = set()   # IPs belonging to our own machine

        logger.info("AlertEngine initialised (cooldown=%ds)", cooldown_seconds)

    # ──────────────────────────────────────────────────────────────────────
    # Core: create alert with dedup
    # ──────────────────────────────────────────────────────────────────────

    def create_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        """
        Create an alert **if** the deduplicator allows it.

        Parameters
        ----------
        alert_type : str
            One of bandwidth / anomaly / device_count / health.
        severity : str
            One of info / warning / critical.
        title : str
            Short title (displayed in the card header).
        message : str
            Human-readable description.
        metadata : dict, optional
            Extra context stored as JSON in the ``details`` column.

        Returns
        -------
        int or None
            Alert ID if created, ``None`` if throttled or on error.
        """
        dedup_key = AlertDeduplicator.make_key(alert_type, severity)

        if self.dedup.should_throttle(dedup_key):
            logger.debug("Alert throttled: %s", dedup_key)
            return None

        # Build the full message with title prefix when title != message
        full_message = f"{title}: {message}" if title and title != message else message

        # Serialise metadata
        details_str = json.dumps(metadata) if metadata else None

        alert_id = db_create_alert(
            alert_type=alert_type,
            severity=severity,
            message=full_message,
            details=details_str,
        )

        if alert_id:
            self.dedup.record_alert(dedup_key)
            logger.warning(
                "Alert #%d created [%s/%s]: %s", alert_id, alert_type, severity, full_message
            )
            self._push_alerts_to_dashboard()
        else:
            logger.error("Failed to persist alert [%s/%s]: %s", alert_type, severity, full_message)

        return alert_id

    # ──────────────────────────────────────────────────────────────────────
    # Threshold: bandwidth
    # ──────────────────────────────────────────────────────────────────────

    def check_bandwidth_threshold(self, current_bps: float) -> Optional[int]:
        """
        Check bandwidth against configured thresholds.

        Parameters
        ----------
        current_bps : float
            Current bandwidth in **bytes per second** (as reported by
            the bandwidth calculator).

        Returns
        -------
        int or None
            Alert ID if a new alert was created.
        """
        current_mbps = current_bps * 8 / 1_000_000  # bytes/s → megabits/s

        if current_mbps >= BANDWIDTH_CRITICAL_MBPS:
            return self.create_alert(
                alert_type=ALERT_BANDWIDTH,
                severity=SEVERITY_CRITICAL,
                title="Critical Bandwidth Usage",
                message=(
                    f"Bandwidth: {current_mbps:.1f} Mbps "
                    f"(threshold: {BANDWIDTH_CRITICAL_MBPS} Mbps)"
                ),
                metadata={
                    "current_mbps": round(current_mbps, 2),
                    "threshold_mbps": BANDWIDTH_CRITICAL_MBPS,
                    "current_bps": round(current_bps, 0),
                },
            )

        if current_mbps >= BANDWIDTH_WARNING_MBPS:
            return self.create_alert(
                alert_type=ALERT_BANDWIDTH,
                severity=SEVERITY_WARNING,
                title="High Bandwidth Usage",
                message=(
                    f"Bandwidth: {current_mbps:.1f} Mbps "
                    f"(threshold: {BANDWIDTH_WARNING_MBPS} Mbps)"
                ),
                metadata={
                    "current_mbps": round(current_mbps, 2),
                    "threshold_mbps": BANDWIDTH_WARNING_MBPS,
                    "current_bps": round(current_bps, 0),
                },
            )

        return None

    # ──────────────────────────────────────────────────────────────────────
    # Threshold: device count  (uses Phase 3 accurate count!)
    # ──────────────────────────────────────────────────────────────────────

    def check_device_threshold(self) -> Optional[int]:
        """
        Check the active (private-IP) device count against thresholds.

        Uses ``get_active_device_count()`` from Phase 3 which counts only
        unique MACs with private IPs — not public IPs that inflated the
        old count.

        Returns
        -------
        int or None
            Alert ID if a new alert was created.
        """
        try:
            device_count = get_active_device_count()
        except Exception as exc:
            logger.error("Failed to get device count: %s", exc)
            return None

        if device_count >= DEVICE_COUNT_CRITICAL:
            return self.create_alert(
                alert_type=ALERT_DEVICE_COUNT,
                severity=SEVERITY_CRITICAL,
                title="Critical Device Count",
                message=(
                    f"{device_count} devices connected "
                    f"(threshold: {DEVICE_COUNT_CRITICAL})"
                ),
                metadata={
                    "device_count": device_count,
                    "threshold": DEVICE_COUNT_CRITICAL,
                },
            )

        if device_count >= DEVICE_COUNT_WARNING:
            return self.create_alert(
                alert_type=ALERT_DEVICE_COUNT,
                severity=SEVERITY_WARNING,
                title="High Device Count",
                message=(
                    f"{device_count} devices connected "
                    f"(threshold: {DEVICE_COUNT_WARNING})"
                ),
                metadata={
                    "device_count": device_count,
                    "threshold": DEVICE_COUNT_WARNING,
                },
            )

        return None

    # ──────────────────────────────────────────────────────────────────────
    # Threshold: health score
    # ──────────────────────────────────────────────────────────────────────

    def check_health_threshold(self, health_score: float) -> Optional[int]:
        """
        Check the network health score against thresholds.

        Parameters
        ----------
        health_score : float
            Score from 0–100 (higher is healthier).

        Returns
        -------
        int or None
            Alert ID if a new alert was created.
        """
        if health_score <= HEALTH_SCORE_CRITICAL:
            return self.create_alert(
                alert_type=ALERT_HEALTH,
                severity=SEVERITY_CRITICAL,
                title="Critical Network Health",
                message=(
                    f"Health score: {health_score:.0f}/100 "
                    f"(threshold: {HEALTH_SCORE_CRITICAL})"
                ),
                metadata={"health_score": round(health_score, 1)},
            )

        if health_score <= HEALTH_SCORE_WARNING:
            return self.create_alert(
                alert_type=ALERT_HEALTH,
                severity=SEVERITY_WARNING,
                title="Low Network Health",
                message=(
                    f"Health score: {health_score:.0f}/100 "
                    f"(threshold: {HEALTH_SCORE_WARNING})"
                ),
                metadata={"health_score": round(health_score, 1)},
            )

        return None

    # ──────────────────────────────────────────────────────────────────────
    # Security: new device detected (hotspot / LAN)
    # ──────────────────────────────────────────────────────────────────────

    # Instance methods replaced former @classmethod / class-variable pattern.

    def load_mac_whitelist(self, macs: list):
        """Load a list of trusted MAC addresses (case-insensitive)."""
        self._mac_whitelist = {m.lower().replace("-", ":") for m in macs if m}
        logger.info("MAC whitelist loaded: %d entries", len(self._mac_whitelist))

    def add_known_mac(self, mac: str):
        """Mark a MAC (or IP) as known (won't trigger future alerts)."""
        if mac:
            self._known_macs.add(mac.lower().replace("-", ":"))

    def add_known_ip(self, ip: str):
        """Mark an IP as known so self-discoveries don't fire alerts."""
        if ip:
            self._known_ips.add(ip)

    def check_new_device(
        self,
        mac: str,
        ip: str,
        hostname: str = "",
        vendor: str = "",
        mode_name: str = "",
    ) -> Optional[int]:
        """
        Alert when a new, unknown device is seen on the network.

        In hotspot mode this is a SECURITY alert because an unknown device
        has connected to YOUR network.  In other modes it's informational.

        Parameters
        ----------
        mac : str       MAC address of the device.
        ip : str        IP address of the device.
        hostname : str  Resolved hostname (if any).
        vendor : str    OUI-based vendor name (if any).
        mode_name : str Current network mode.

        Returns
        -------
        int or None     Alert ID if created, None if device is already known.
        """
        if not mac:
            return None

        mac_lower = mac.lower().replace("-", ":")

        # Already known (by MAC or IP) — skip
        if mac_lower in self._known_macs or mac_lower in self._mac_whitelist:
            return None
        if ip and ip in self._known_ips:
            self._known_macs.add(mac_lower)  # remember this MAC too
            return None

        # Mark as known for future
        self._known_macs.add(mac_lower)

        # In hotspot mode, unknown devices are a security concern
        is_hotspot = mode_name in ("hotspot",)
        severity = SEVERITY_WARNING if is_hotspot else SEVERITY_INFO
        alert_type = ALERT_SECURITY if is_hotspot else ALERT_NEW_DEVICE

        device_desc = hostname or vendor or ip or "Unknown"
        title = (
            "Unknown Device on Hotspot" if is_hotspot
            else "New Device Detected"
        )
        message = (
            f"{'SECURITY: ' if is_hotspot else ''}"
            f"New device connected — {device_desc} "
            f"(IP: {ip}, MAC: {mac})"
            f"{f', Vendor: {vendor}' if vendor else ''}"
        )

        return self.create_alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            metadata={
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "mode": mode_name,
                "whitelisted": False,
            },
        )

    # ──────────────────────────────────────────────────────────────────────
    # Anomaly helper (used by AnomalyDetector)
    # ──────────────────────────────────────────────────────────────────────

    def create_anomaly_alert(
        self,
        anomaly_score: float,
        severity: str = SEVERITY_WARNING,
        details: Optional[Dict] = None,
    ) -> Optional[int]:
        """
        Create an ML-detected anomaly alert.

        Parameters
        ----------
        anomaly_score : float
            Confidence score from the Isolation Forest (0–1).
        severity : str
            Severity level.
        details : dict, optional
            Current network stats snapshot.
        """
        metadata = {"anomaly_score": round(anomaly_score, 4)}
        if details:
            metadata.update(details)

        # Build a human-readable description of what the anomaly looks like
        description_parts = []
        if details:
            bw_bps = details.get("bandwidth_bps") or details.get("total_bandwidth", 0)
            if bw_bps:
                bw_mbps = bw_bps * 8 / 1_000_000
                description_parts.append(f"bandwidth {bw_mbps:.2f} Mbps")

            active_devices = details.get("active_devices", 0)
            if active_devices:
                description_parts.append(f"{active_devices} active devices")

            active_conns = details.get("active_connections", 0)
            if active_conns:
                description_parts.append(f"{active_conns} active connections")

            dns_count = details.get("dns_queries_count", 0)
            if dns_count and dns_count > 50:
                description_parts.append(f"{dns_count} DNS queries (high)")

            unique_protos = details.get("unique_protocols", 0)
            if unique_protos:
                description_parts.append(f"{unique_protos} protocols seen")

            pps = details.get("packets_per_second", 0)
            if pps:
                description_parts.append(f"{pps:.0f} pkt/s")

        if description_parts:
            detail_str = ", ".join(description_parts)
            message = (
                f"Unusual network activity detected (confidence: {anomaly_score:.1%}). "
                f"Current snapshot: {detail_str}"
            )
        else:
            message = f"ML anomaly detected (confidence: {anomaly_score:.1%})"

        return self.create_alert(
            alert_type=ALERT_ANOMALY,
            severity=severity,
            title="Network Anomaly Detected",
            message=message,
            metadata=metadata,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Convenience wrappers (keep backward compat for callers)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_alerts(**kwargs):
        """Proxy to ``alert_queries.get_alerts``."""
        return db_get_alerts(**kwargs)

    @staticmethod
    def acknowledge_alert(alert_id: int) -> bool:
        """Proxy to ``alert_queries.acknowledge_alert``."""
        return db_acknowledge_alert(alert_id)

    @staticmethod
    def resolve_alert(alert_id: int) -> bool:
        """Proxy to ``alert_queries.resolve_alert``."""
        return db_resolve_alert(alert_id)

    @staticmethod
    def count_alerts(**kwargs) -> int:
        """Proxy to ``alert_queries.count_alerts``."""
        return db_count_alerts(**kwargs)

    @staticmethod
    def get_alert_summary() -> dict:
        """Proxy to ``alert_queries.get_alert_summary``."""
        return db_get_alert_summary()

    def get_stats(self) -> dict:
        """Return engine state for diagnostics."""
        return {
            "cooldown_seconds": self.dedup.cooldown,
            "tracked_keys": len(self.dedup.last_alerts),
        }

    # ──────────────────────────────────────────────────────────────────────
    # Phase 4: push alert state into in-memory dashboard cache
    # ──────────────────────────────────────────────────────────────────────

    def _push_alerts_to_dashboard(self) -> None:
        """Refresh in-memory alert caches after a new alert is created.

        Reads counts and recent alerts from the DB (acceptable overhead
        since this only runs on alert creation, not every SSE tick) and
        pushes them into ``dashboard_state`` so the SSE loop can serve
        alert data without DB queries.
        """
        try:
            from utils.realtime_state import dashboard_state
            counts = db_get_alert_summary()
            recent = db_get_alerts(limit=5, include_resolved=False)
            dashboard_state.set_alerts(counts, recent)
        except Exception as exc:
            logger.debug("_push_alerts_to_dashboard failed: %s", exc)

    def __repr__(self) -> str:
        return f"AlertEngine(dedup={self.dedup!r})"
