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
import operator as _op
from datetime import datetime, timedelta
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
    list_enabled_alert_rules as db_list_enabled_alert_rules,
    mark_alert_rule_triggered as db_mark_alert_rule_triggered,
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
ALERT_CUSTOM = "custom"


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

        # Alert→incident fusion (Phase 2).  Wired at startup; when None
        # (tests, standalone use) alerts are simply not triaged.
        self.incident_manager = None

        logger.info("AlertEngine initialised (cooldown=%ds)", cooldown_seconds)

    def _triage_incident(self, alert_id, alert_type, severity, message, metadata):
        """Offer a persisted alert to the incident manager (never raises)."""
        if self.incident_manager is None:
            return
        try:
            # Alert creators are inconsistent about the key ("device_mac"
            # vs "mac"); accept both so device alerts fuse per-device
            # instead of piling into one network-wide incident.
            meta = metadata or {}
            device_mac = meta.get("device_mac") or meta.get("mac")
            self.incident_manager.triage(
                alert_id=alert_id,
                alert_type=alert_type,
                severity=severity,
                device_mac=device_mac,
                message=message,
            )
        except Exception:
            logger.exception("Incident triage hook failed for alert #%s", alert_id)

    _RULE_OPERATOR_MAP = {
        ">": _op.gt,
        "<": _op.lt,
        ">=": _op.ge,
        "<=": _op.le,
        "==": _op.eq,
    }

    # ──────────────────────────────────────────────────────────────────────
    # Core: create alert with dedup
    # ──────────────────────────────────────────────────────────────────────

    def _create_alert_with_dedup(
        self,
        *,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        dedup_key: Optional[str] = None,
    ) -> Optional[int]:
        """Internal alert creator with optional explicit dedup key."""
        key = dedup_key or AlertDeduplicator.make_key(alert_type, severity)

        if self.dedup.should_throttle(key):
            logger.debug("Alert throttled: %s", key)
            return None

        full_message = f"{title}: {message}" if title and title != message else message
        details_str = json.dumps(metadata) if metadata else None

        alert_id = db_create_alert(
            alert_type=alert_type,
            severity=severity,
            message=full_message,
            details=details_str,
        )

        if alert_id:
            self.dedup.record_alert(key)
            logger.warning(
                "Alert #%d created [%s/%s]: %s", alert_id, alert_type, severity, full_message
            )
            self._triage_incident(alert_id, alert_type, severity, full_message, metadata)
            self._push_alerts_to_dashboard()
        else:
            logger.error("Failed to persist alert [%s/%s]: %s", alert_type, severity, full_message)

        return alert_id

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
        return self._create_alert_with_dedup(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            metadata=metadata,
        )

    @staticmethod
    def _parse_db_timestamp(value: Optional[str]) -> Optional[datetime]:
        """Parse SQLite timestamp formats used by alert_rules."""
        if not value:
            return None
        # sqlite CURRENT_TIMESTAMP is usually "YYYY-MM-DD HH:MM:SS"
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _rule_on_cooldown(self, rule: Dict[str, Any]) -> bool:
        """Return True when the custom rule is still inside cooldown window."""
        cooldown = int(rule.get("cooldown_seconds") or 0)
        if cooldown <= 0:
            return False

        last_triggered = self._parse_db_timestamp(rule.get("last_triggered_at"))
        if not last_triggered:
            return False

        return datetime.now() < (last_triggered + timedelta(seconds=cooldown))

    def _build_rule_metric_snapshot(self, stats: Dict[str, Any], rules: list) -> Dict[str, float]:
        """Build one metric snapshot for all enabled custom rules."""
        if isinstance(stats.get("bandwidth_bps"), (int, float)):
            bandwidth_bps = float(stats.get("bandwidth_bps") or 0.0)
        else:
            # total_bandwidth is bytes/s in anomaly features.
            bandwidth_bps = float(stats.get("total_bandwidth") or 0.0) * 8.0

        metrics: Dict[str, float] = {
            "bandwidth_bps": bandwidth_bps,
            "device_count": float(stats.get("active_devices") or stats.get("device_count") or 0.0),
            "packet_rate": float(stats.get("packets_per_second") or stats.get("packet_rate") or 0.0),
        }

        needs_protocol_bytes = any((r.get("metric") == "protocol_bytes") for r in rules)
        if not needs_protocol_bytes:
            return metrics

        if "protocol_bytes" in stats and isinstance(stats.get("protocol_bytes"), (int, float)):
            metrics["protocol_bytes"] = float(stats.get("protocol_bytes") or 0.0)
            return metrics

        # protocol_bytes = bytes of top protocol in last hour (cached query)
        try:
            from database.queries.traffic_queries import get_protocol_distribution

            dist = get_protocol_distribution(hours=1)
            metrics["protocol_bytes"] = float((dist[0].get("bytes") if dist else 0) or 0)
        except Exception as exc:
            logger.debug("protocol_bytes metric unavailable: %s", exc)
            metrics["protocol_bytes"] = 0.0

        return metrics

    def check_custom_rules(self, stats: Dict[str, Any]) -> int:
        """Evaluate enabled custom alert rules against the current snapshot."""
        try:
            rules = db_list_enabled_alert_rules()
        except Exception as exc:
            logger.error("Failed to load custom alert rules: %s", exc)
            return 0

        if not rules:
            return 0

        metric_values = self._build_rule_metric_snapshot(stats, rules)
        fired = 0

        for rule in rules:
            try:
                metric = (rule.get("metric") or "").strip()
                operator = (rule.get("operator") or "").strip()
                threshold = float(rule.get("threshold"))
                severity = (rule.get("severity") or SEVERITY_WARNING).strip()
                rule_id = int(rule.get("id"))

                if self._rule_on_cooldown(rule):
                    continue

                comparator = self._RULE_OPERATOR_MAP.get(operator)
                if comparator is None:
                    logger.debug("Skipping custom rule %s: unsupported operator %s", rule_id, operator)
                    continue

                current_value = metric_values.get(metric)
                if current_value is None:
                    logger.debug("Skipping custom rule %s: missing metric %s", rule_id, metric)
                    continue

                if not comparator(float(current_value), threshold):
                    continue

                name = (rule.get("name") or f"Rule {rule_id}").strip()
                alert_id = self._create_alert_with_dedup(
                    alert_type=ALERT_CUSTOM,
                    severity=severity,
                    title=f"Custom Rule Triggered: {name}",
                    message=(
                        f"Rule matched: {metric} {operator} {threshold:g} "
                        f"(current: {float(current_value):.2f})"
                    ),
                    metadata={
                        "rule_id": rule_id,
                        "rule_name": name,
                        "metric": metric,
                        "operator": operator,
                        "threshold": threshold,
                        "current_value": round(float(current_value), 4),
                    },
                    # Per-rule dedup key prevents different custom rules
                    # from throttling each other when severities match.
                    dedup_key=f"custom_rule:{rule_id}",
                )
                if alert_id:
                    db_mark_alert_rule_triggered(rule_id)
                    fired += 1
            except Exception as exc:
                logger.error("Custom rule evaluation error: %s", exc)

        return fired

    # ──────────────────────────────────────────────────────────────────────
    # Threshold: bandwidth
    # ──────────────────────────────────────────────────────────────────────

    def check_bandwidth_threshold(self, current_bps: float, control_bps: float = 0.0) -> Optional[int]:
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
        app_bps = max(float(current_bps or 0.0), 0.0)
        control_bps = max(float(control_bps or 0.0), 0.0)

        app_mbps = app_bps * 8 / 1_000_000
        control_mbps = control_bps * 8 / 1_000_000
        combined_bps = app_bps + control_bps
        combined_mbps = app_mbps + control_mbps

        if control_mbps > 0:
            breakdown = (
                f"Bandwidth: {app_mbps:.1f} Mbps app "
                f"(+{control_mbps:.1f} Mbps control, total {combined_mbps:.1f} Mbps)"
            )
        else:
            breakdown = f"Bandwidth: {app_mbps:.1f} Mbps"

        if app_mbps >= BANDWIDTH_CRITICAL_MBPS:
            return self.create_alert(
                alert_type=ALERT_BANDWIDTH,
                severity=SEVERITY_CRITICAL,
                title="Critical Bandwidth Usage",
                message=(
                    f"{breakdown} "
                    f"(threshold: {BANDWIDTH_CRITICAL_MBPS} Mbps app)"
                ),
                metadata={
                    "current_mbps": round(app_mbps, 2),
                    "app_mbps": round(app_mbps, 2),
                    "control_mbps": round(control_mbps, 2),
                    "combined_mbps": round(combined_mbps, 2),
                    "threshold_mbps": BANDWIDTH_CRITICAL_MBPS,
                    "current_bps": round(app_bps, 0),
                    "app_bps": round(app_bps, 0),
                    "control_bps": round(control_bps, 0),
                    "combined_bps": round(combined_bps, 0),
                    "threshold_scope": "app_only",
                },
            )

        if app_mbps >= BANDWIDTH_WARNING_MBPS:
            return self.create_alert(
                alert_type=ALERT_BANDWIDTH,
                severity=SEVERITY_WARNING,
                title="High Bandwidth Usage",
                message=(
                    f"{breakdown} "
                    f"(threshold: {BANDWIDTH_WARNING_MBPS} Mbps app)"
                ),
                metadata={
                    "current_mbps": round(app_mbps, 2),
                    "app_mbps": round(app_mbps, 2),
                    "control_mbps": round(control_mbps, 2),
                    "combined_mbps": round(combined_mbps, 2),
                    "threshold_mbps": BANDWIDTH_WARNING_MBPS,
                    "current_bps": round(app_bps, 0),
                    "app_bps": round(app_bps, 0),
                    "control_bps": round(control_bps, 0),
                    "combined_bps": round(combined_bps, 0),
                    "threshold_scope": "app_only",
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

    def create_behavior_alert(
        self,
        mac: str,
        evidence: list,
        confidence: float,
        hostname: str = "",
        severity: str = SEVERITY_WARNING,
    ) -> Optional[int]:
        """
        Create a per-device behavior anomaly alert (Phase 1, AI-first).

        Deduplicated **per device** (not per alert type), so two different
        devices misbehaving in the same cooldown window both alert.

        Parameters
        ----------
        mac : str
            Device MAC address the anomaly belongs to.
        evidence : list of dict
            Explainable evidence items, each like::

                {"metric": "dns_queries", "observed": 480,
                 "baseline_mean": 12.1, "baseline_std": 8.0,
                 "z_score": 58.5, "hour_of_week": 34}
        confidence : float
            0-1 confidence derived from the strongest deviation.
        hostname : str
            Friendly device name for the message (falls back to MAC).
        """
        label = hostname or mac
        top = max(evidence, key=lambda e: abs(e.get("z_score", 0))) if evidence else {}
        message = (
            f"Device '{label}' is behaving unusually "
            f"(confidence: {confidence:.0%})."
        )
        if top:
            message += (
                f" Strongest signal: {top.get('metric')} = {top.get('observed')}"
                f" vs typical {top.get('baseline_mean', 0):.1f}"
                f" (z={top.get('z_score', 0):.1f})."
            )

        return self._create_alert_with_dedup(
            alert_type="anomaly",
            severity=severity,
            title="Device Behavior Anomaly",
            message=message,
            metadata={
                "device_mac": mac,
                "device_name": hostname,
                "confidence": round(confidence, 4),
                "evidence": evidence,
                "detector": "behavior_baseline",
            },
            dedup_key=f"behavior:{mac.lower()}",
        )

    def create_threat_alert(
        self,
        threat_type: str,
        mac: str,
        message: str,
        evidence: list,
        confidence: float,
        severity: str = SEVERITY_WARNING,
    ) -> Optional[int]:
        """
        Create a named-threat alert (Phase 2 threat detector pack).

        Deduplicated per (threat, device) so a port scan and a beacon from
        the same device raise separately, and two scanning devices both
        alert inside one cooldown window.

        Parameters
        ----------
        threat_type : str
            One of port_scan / beaconing / dns_tunneling / rogue_device /
            lateral_movement.
        mac : str
            Source device the threat originates from.
        message : str
            Human-readable summary built by the detector.
        evidence : list of dict
            Explainable evidence items (signal, counts, samples, window).
        confidence : float
            0-1 confidence assigned by the detector.
        """
        titles = {
            "port_scan": "Port Scan Detected",
            "beaconing": "Beaconing (Possible C2) Detected",
            "dns_tunneling": "DNS Tunneling Suspected",
            "rogue_device": "Unrecognized Device Joined",
            "lateral_movement": "Lateral Movement Detected",
        }
        return self._create_alert_with_dedup(
            alert_type=ALERT_SECURITY,
            severity=severity,
            title=titles.get(threat_type, "Security Threat Detected"),
            message=message,
            metadata={
                "threat_type": threat_type,
                "device_mac": mac,
                "confidence": round(confidence, 4),
                "evidence": evidence,
                "detector": "threat_pack",
            },
            dedup_key=f"threat:{threat_type}:{mac.lower()}",
        )

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
            app_bw_bits = details.get("bandwidth_bps")
            if app_bw_bits is None:
                # total_bandwidth in anomaly features is bytes/s.
                app_bw_bits = float(details.get("total_bandwidth", 0) or 0) * 8.0
            app_bw_bits = float(app_bw_bits or 0)
            control_bw_bits = float(details.get("control_bandwidth_bps", 0) or 0)

            app_bw_mbps = app_bw_bits / 1_000_000
            control_bw_mbps = control_bw_bits / 1_000_000
            combined_bw_mbps = app_bw_mbps + control_bw_mbps

            metadata["app_bandwidth_mbps"] = round(app_bw_mbps, 3)
            metadata["control_bandwidth_mbps"] = round(control_bw_mbps, 3)
            metadata["combined_bandwidth_mbps"] = round(combined_bw_mbps, 3)

            if control_bw_mbps > 0:
                description_parts.append(
                    f"bandwidth {combined_bw_mbps:.2f} Mbps "
                    f"({app_bw_mbps:.2f} app + {control_bw_mbps:.2f} control)"
                )
            elif app_bw_mbps > 0:
                description_parts.append(f"bandwidth {app_bw_mbps:.2f} Mbps app")

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
