"""
realtime_state.py - In-Memory Dashboard State (Phase 4)
=========================================================

Maintains an in-memory snapshot of the data needed by the SSE push loop
so that the hot path does **zero** database queries.  The state is
updated atomically by the ``DatabaseWriter`` thread after each batch.

Thread-safety: all mutations are protected by a ``threading.Lock``.
Since updates are pure Python dict/counter mutations, lock contention
is negligible (sub-microsecond critical sections).

Usage::

    from utils.realtime_state import dashboard_state

    # Writer thread — after each batch:
    dashboard_state.update_from_batch(normalised_packets)

    # SSE / API read (from any thread):
    snapshot = dashboard_state.snapshot()
"""

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from utils.network_utils import is_private_ip

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Lightweight in-memory representation of a device."""
    mac_address: str
    ip_address: str = ""
    device_name: str = ""
    hostname: str = ""
    vendor: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 0
    last_seen: float = 0.0  # time.time()
    first_seen: float = 0.0
    today_bytes: int = 0
    today_sent: int = 0
    today_received: int = 0
    direction: str = ""


class InMemoryDashboardState:
    """
    In-memory hot-path state for the SSE push loop.

    Holds:
    * Active device registry (``Dict[str, DeviceInfo]`` keyed by MAC)
    * Today's byte/packet totals
    * Protocol distribution (rolling last 1 hour)

    Updated by the ``DatabaseWriter`` thread after each batch commit.
    Read by the SSE ``_build_sse_payload()`` function — pure memory,
    zero DB queries.
    """

    # Maximum devices to track in memory
    MAX_DEVICES = 10_000

    def __init__(self):
        self._lock = threading.Lock()

        # Device registry: MAC → DeviceInfo
        self._devices: Dict[str, DeviceInfo] = {}

        # Today's running totals
        self._today_bytes: int = 0
        self._today_packets: int = 0
        self._today_date: str = datetime.now().strftime("%Y-%m-%d")

        # Protocol distribution — rolling window
        # Deque of (timestamp_float, protocol, byte_count) tuples
        # Using deque for O(1) popleft during pruning (critical at high pps)
        self._protocol_records: deque = deque()
        self._protocol_window_seconds: int = 60  # 1 minute — responsive to changes

        # Last update timestamp
        self._last_update: float = 0.0

        # ── Mode-awareness ──────────────────────────────────────────
        # When scope is OWN_TRAFFIC_ONLY, only MACs in _allowed_macs
        # are tracked.  This prevents broadcast/multicast leakage and
        # stale cross-mode entries from inflating the device count.
        self._own_traffic_only: bool = False
        self._allowed_macs: set = set()       # lower-case MACs

        # Host MAC exclusion — applies in ALL modes (incl. hotspot).
        # The host's own adapter MACs (hotspot virtual, etc.) must
        # never be counted as "client devices" in the dashboard.
        # NOTE: In public_network mode the capture interface MAC is
        # removed from this set so the host itself IS tracked.
        self._host_macs: set = set()           # lower-case MACs

        # Gateway MAC exclusion — applies in public_network mode.
        # The router/gateway should not appear as a "device" on the
        # dashboard; only the host itself should be shown.
        self._gateway_macs: set = set()        # lower-case MACs

        # Host IP — used for IP-based host exclusion when MAC detection
        # misses the hotspot virtual adapter.
        self._our_ip: str = ""

        # Host hostname — used to reject device_name values that leaked
        # from the hotspot DNS resolver (Windows hotspot resolves client
        # IPs back to the host machine's name).
        self._our_hostname: str = ""

        # ── Alert & health caches (Phase 4 zero-DB SSE) ──────────────
        # Updated by AlertEngine / HealthMonitor callbacks; read by
        # snapshot() so _build_sse_payload() never hits the DB for these.
        self._alert_counts: dict = {
            "total": 0, "unacknowledged": 0, "critical": 0,
            "warning": 0, "info": 0,
        }
        self._recent_alerts: list = []        # last 5 alert dicts
        self._health_score: dict = {"score": 0, "status": "unknown"}

    # ------------------------------------------------------------------ #
    #  Mode context — called on every mode change
    # ------------------------------------------------------------------ #

    def set_mode_context(
        self,
        our_mac: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        own_traffic_only: bool = False,
        host_macs: Optional[set] = None,
        gateway_mac_exclude: bool = False,
        our_ip: Optional[str] = None,
    ) -> None:
        """Configure per-mode device tracking constraints.

        When *own_traffic_only* is ``True`` (public_network),
        ``update_from_batch`` will only track *our_mac* — the gateway
        MAC is excluded so the router never appears as a device.
        This keeps the active device count at exactly 1.

        *host_macs* (optional set of lower-case MACs) are excluded from
        device tracking in **all** modes.  In hotspot mode the host
        acts as the gateway — its own adapter MACs must not be counted
        as connected client devices.

        When *gateway_mac_exclude* is ``True`` (public_network or hotspot
        mode), the gateway MAC is added to ``_gateway_macs`` and excluded
        from device tracking.

        *our_ip* is the capture interface IP — used to exclude the host
        from device tracking by IP when MAC detection fails (e.g. hotspot
        virtual adapter not detected by psutil).
        """
        with self._lock:
            self._own_traffic_only = own_traffic_only
            allowed: set = set()
            if our_mac:
                allowed.add(our_mac.lower().replace("-", ":"))
            # In own_traffic_only mode with gateway exclusion, do NOT
            # add gateway to allowed_macs — only track self.
            if gateway_mac and not gateway_mac_exclude:
                allowed.add(gateway_mac.lower().replace("-", ":"))
            self._allowed_macs = allowed
            self._host_macs = {m.lower().replace("-", ":") for m in (host_macs or set())}
            # Gateway exclusion set
            if gateway_mac_exclude and gateway_mac:
                self._gateway_macs = {gateway_mac.lower().replace("-", ":")}
            else:
                self._gateway_macs = set()
            # Host IP for IP-based exclusion (hotspot: host = gateway)
            self._our_ip = our_ip or ""
            # Cache local hostname for device_name leak filtering
            try:
                import socket
                self._our_hostname = socket.gethostname()
            except Exception:
                self._our_hostname = ""
        logger.debug(
            "Mode context set: own_traffic_only=%s, allowed_macs=%s, "
            "host_macs=%s, gateway_macs=%s",
            own_traffic_only, self._allowed_macs,
            self._host_macs, self._gateway_macs,
        )

    def set_own_device_info(self, mac: str, hostname: str, ip: str = "") -> None:
        """Pre-seed our own device in the registry with a known hostname.

        Called on mode change for public_network so the device list shows
        the machine's real hostname from the start — before the first packet
        or background resolver gets to it.
        """
        if not mac:
            return
        # Normalize MAC to colon-separated lowercase for consistent keying
        mac = mac.lower().replace("-", ":")
        with self._lock:
            dev = self._devices.get(mac)
            if dev is None:
                dev = DeviceInfo(
                    mac_address=mac,
                    ip_address=ip,
                    device_name=hostname,
                    hostname=hostname,
                    first_seen=time.time(),
                )
                self._devices[mac] = dev
            else:
                dev.hostname = hostname
                if not dev.device_name:
                    dev.device_name = hostname
                if ip:
                    dev.ip_address = ip  # Always prefer authoritative interface IP

    def update_device_hostname(self, ip: str, hostname: str) -> None:
        """Update a device's hostname in the in-memory registry by IP.

        Called by the hostname resolver (passive or background) when a new
        hostname is learned.  Keeps the SSE-served device list in sync with
        the DB-persisted hostname so the dashboard shows real names without
        waiting for a full page reload.
        """
        if not ip or not hostname:
            return
        with self._lock:
            for dev in self._devices.values():
                if dev.ip_address == ip:
                    dev.hostname = hostname
                    if not dev.device_name:
                        dev.device_name = hostname
                    break

    # ------------------------------------------------------------------ #
    #  Alert / health callbacks (Phase 4 zero-DB SSE)
    # ------------------------------------------------------------------ #

    def set_alerts(self, counts: dict, recent: list) -> None:
        """Update cached alert counts and recent alerts list.

        Called by ``AlertEngine`` after each alert creation so that
        ``_build_sse_payload()`` can serve alert data from memory.

        *counts* should have keys: ``total``, ``unacknowledged``,
        ``critical``, ``warning``, ``info``.
        *recent* should be a list of up to 5 alert dicts.
        """
        with self._lock:
            self._alert_counts = dict(counts)
            self._recent_alerts = list(recent[:5])

    def set_health_score(self, health: dict) -> None:
        """Update cached health score dict.

        Called by ``HealthMonitor`` after each collection cycle so that
        ``_build_sse_payload()`` can serve health data from memory.
        """
        with self._lock:
            self._health_score = dict(health)

    # ------------------------------------------------------------------ #
    #  Writer-side: update after each batch
    # ------------------------------------------------------------------ #

    def update_from_batch(self, packets: list) -> None:
        """
        Update in-memory state from a list of normalised packet dicts.

        Called by the ``DatabaseWriter`` thread after ``save_packets_batch()``
        succeeds.  Each packet dict should have keys: ``source_mac``,
        ``dest_mac``, ``source_ip``, ``dest_ip``, ``bytes``,
        ``protocol``, ``device_name``, ``vendor``, ``direction``,
        ``timestamp``.

        This method is intentionally fast: O(n) in batch size with only
        dict lookups and integer additions.
        """
        if not packets:
            return

        now = time.time()

        with self._lock:
            # Roll over today counters at midnight
            today = datetime.now().strftime("%Y-%m-%d")
            if today != self._today_date:
                self._today_bytes = 0
                self._today_packets = 0
                self._today_date = today

            for pkt in packets:
                try:
                    byte_count = pkt.get("bytes", 0) or 0
                    protocol = pkt.get("protocol", "UNKNOWN")
                    direction = pkt.get("direction", "unknown")
                    source_mac = pkt.get("source_mac") or ""
                    dest_mac = pkt.get("dest_mac") or ""
                    source_ip = pkt.get("source_ip") or ""
                    dest_ip = pkt.get("dest_ip") or ""
                    device_name = pkt.get("device_name") or ""
                    vendor = pkt.get("vendor") or ""

                    # Reject device_name if it matches the host's hostname.
                    # Windows hotspot DNS often resolves client IPs back to
                    # the host machine's name, polluting the device list.
                    if (device_name and self._our_hostname
                            and device_name.lower() == self._our_hostname.lower()):
                        device_name = ""

                    # Running totals
                    self._today_bytes += byte_count
                    self._today_packets += 1

                    # Protocol tracking
                    self._protocol_records.append((now, protocol, byte_count))

                    # Source device
                    _src_is_private_v4 = (
                        source_ip and source_ip != "0.0.0.0"
                        and ":" not in source_ip
                        and is_private_ip(source_ip)
                    )
                    # Also allow device creation for IPv6 link-local / ULA
                    # addresses so dual-stack clients are tracked immediately.
                    _src_is_local_ipv6 = (
                        source_ip and ":" in source_ip
                        and source_ip.lower().startswith(("fe80:", "fd", "fc"))
                    )
                    if source_mac and self._is_trackable_mac(source_mac):
                        src_lower = source_mac.lower()
                        if src_lower in self._host_macs:
                            pass  # host's own MAC — never count as a device
                        elif src_lower in self._gateway_macs:
                            pass  # gateway MAC — excluded in public_network/hotspot
                        elif self._own_traffic_only and src_lower not in self._allowed_macs:
                            pass  # not our MAC — skip device tracking
                        elif not self._own_traffic_only and self._our_ip and source_ip == self._our_ip:
                            pass  # host IP — hotspot host = gateway, skip (not in own-traffic mode)
                        else:
                            dev = self._devices.get(source_mac)
                            if dev is None:
                                # Create device for private IPv4 or local IPv6.
                                # Public-IP-only packets must not spawn phantom
                                # device entries.
                                if (_src_is_private_v4 or _src_is_local_ipv6) and len(self._devices) < self.MAX_DEVICES:
                                    dev = DeviceInfo(
                                        mac_address=source_mac,
                                        ip_address=source_ip,
                                        device_name=device_name,
                                        vendor=vendor,
                                        first_seen=now,
                                    )
                                    self._devices[source_mac] = dev
                                else:
                                    dev = None
                            if dev is not None:
                                dev.bytes_sent += byte_count
                                dev.packet_count += 1
                                dev.last_seen = now
                                dev.today_sent += byte_count
                                dev.today_bytes += byte_count
                                if (source_ip and source_ip != "0.0.0.0"
                                        and ":" not in source_ip
                                        and is_private_ip(source_ip)):
                                    dev.ip_address = source_ip
                                if device_name and not dev.device_name:
                                    dev.device_name = device_name
                                if device_name and not dev.hostname:
                                    dev.hostname = device_name
                                if vendor and not dev.vendor:
                                    dev.vendor = vendor

                    # Dest device
                    _dst_is_private_v4 = (
                        dest_ip and dest_ip != "0.0.0.0"
                        and ":" not in dest_ip
                        and is_private_ip(dest_ip)
                    )
                    _dst_is_local_ipv6 = (
                        dest_ip and ":" in dest_ip
                        and dest_ip.lower().startswith(("fe80:", "fd", "fc"))
                    )
                    if dest_mac and self._is_trackable_mac(dest_mac):
                        dst_lower = dest_mac.lower()
                        if dst_lower in self._host_macs:
                            pass  # host's own MAC — never count as a device
                        elif dst_lower in self._gateway_macs:
                            pass  # gateway MAC — excluded in public_network/hotspot
                        elif self._own_traffic_only and dst_lower not in self._allowed_macs:
                            pass  # not our MAC — skip device tracking
                        elif not self._own_traffic_only and self._our_ip and dest_ip == self._our_ip:
                            pass  # host IP — hotspot host = gateway, skip (not in own-traffic mode)
                        else:
                            dev = self._devices.get(dest_mac)
                            if dev is None:
                                if (_dst_is_private_v4 or _dst_is_local_ipv6) and len(self._devices) < self.MAX_DEVICES:
                                    dev = DeviceInfo(
                                        mac_address=dest_mac,
                                        ip_address=dest_ip,
                                        vendor=pkt.get("dest_vendor") or "",
                                        first_seen=now,
                                    )
                                    self._devices[dest_mac] = dev
                                else:
                                    dev = None
                            if dev is not None:
                                dev.bytes_received += byte_count
                                dev.packet_count += 1
                                dev.last_seen = now
                                dev.today_received += byte_count
                                dev.today_bytes += byte_count
                                if (dest_ip and dest_ip != "0.0.0.0"
                                        and ":" not in dest_ip
                                        and is_private_ip(dest_ip)):
                                    dev.ip_address = dest_ip
                                dest_vendor = pkt.get("dest_vendor") or ""
                                if dest_vendor and not dev.vendor:
                                    dev.vendor = dest_vendor

                except Exception:
                    continue  # skip malformed packets

            self._last_update = now

    # ------------------------------------------------------------------ #
    #  Reader-side: snapshot for SSE / API
    # ------------------------------------------------------------------ #

    def snapshot(self) -> dict:
        """
        Return a read-only snapshot of dashboard state.

        Returns dict with keys:
        * ``today_bytes``, ``today_packets``
        * ``active_devices`` — count of devices seen in last 5 min
        * ``protocols`` — list of {name, count, bytes, percentage}
        * ``top_devices`` — list of top 5 devices by total_bytes
        """
        now = time.time()
        five_min_ago = now - 300

        with self._lock:
            # Active device count
            active_count = sum(
                1 for d in self._devices.values()
                if d.last_seen >= five_min_ago
            )

            # Top devices by total bytes (sent + received) in last hour
            one_hour_ago = now - 3600
            active_devices = [
                d for d in self._devices.values()
                if d.last_seen >= one_hour_ago
            ]
            active_devices.sort(
                key=lambda d: d.bytes_sent + d.bytes_received,
                reverse=True,
            )
            top_devices = []
            for d in active_devices[:5]:
                total = d.bytes_sent + d.bytes_received
                top_devices.append({
                    "mac_address": d.mac_address,
                    "ip_address": d.ip_address,
                    "hostname": d.hostname or d.device_name or d.ip_address,
                    "device_name": d.device_name,
                    "vendor": d.vendor,
                    "bytes_sent": d.bytes_sent,
                    "bytes_received": d.bytes_received,
                    "total_bytes": total,
                    "packet_count": d.packet_count,
                    "last_seen": datetime.fromtimestamp(d.last_seen).strftime(
                        "%Y-%m-%d %H:%M:%S") if d.last_seen else "",
                    "today_bytes": d.today_bytes,
                    "today_sent": d.today_sent,
                    "today_received": d.today_received,
                })

            # Protocol distribution (last 1 hour)
            self._prune_protocols(now)
            proto_agg: Dict[str, dict] = {}
            for _ts, proto, byte_count in self._protocol_records:
                if proto not in proto_agg:
                    proto_agg[proto] = {"name": proto, "count": 0, "bytes": 0}
                proto_agg[proto]["count"] += 1
                proto_agg[proto]["bytes"] += byte_count

            proto_list = sorted(proto_agg.values(), key=lambda p: p["bytes"], reverse=True)
            proto_total = sum(p["bytes"] for p in proto_list)
            for p in proto_list:
                p["percentage"] = round(
                    (p["bytes"] / proto_total * 100) if proto_total else 0, 2
                )

            return {
                "today_bytes": self._today_bytes,
                "today_packets": self._today_packets,
                "active_devices": active_count,
                "top_devices": top_devices,
                "protocols": proto_list,
                "last_update": self._last_update,
                "health_score": dict(self._health_score),
                "alert_counts": dict(self._alert_counts),
                "recent_alerts": list(self._recent_alerts),
            }

    def get_top_devices_memory(self, limit: int = 5) -> list:
        """
        Return top *limit* devices by total bytes from memory.

        Used by the SSE push loop instead of ``get_top_devices()``.
        """
        now = time.time()
        one_hour_ago = now - 3600

        with self._lock:
            active = [
                d for d in self._devices.values()
                if d.last_seen >= one_hour_ago
            ]
            active.sort(
                key=lambda d: d.bytes_sent + d.bytes_received,
                reverse=True,
            )
            result = []
            for d in active[:limit]:
                total = d.bytes_sent + d.bytes_received
                result.append({
                    "mac_address": d.mac_address,
                    "ip_address": d.ip_address,
                    "hostname": d.hostname or d.device_name or d.ip_address,
                    "device_name": d.device_name,
                    "vendor": d.vendor,
                    "bytes_sent": d.bytes_sent,
                    "bytes_received": d.bytes_received,
                    "total_bytes": total,
                    "packet_count": d.packet_count,
                    "last_seen": datetime.fromtimestamp(d.last_seen).strftime(
                        "%Y-%m-%d %H:%M:%S") if d.last_seen else "",
                    "today_bytes": d.today_bytes,
                    "today_sent": d.today_sent,
                    "today_received": d.today_received,
                })
            return result

    def get_active_device_count(self, minutes: int = 5) -> int:
        """Return count of devices active within *minutes*."""
        cutoff = time.time() - (minutes * 60)
        with self._lock:
            return sum(1 for d in self._devices.values() if d.last_seen >= cutoff)

    def get_device_by_ip(self, ip: str) -> Optional[dict]:
        """Look up a device by IP address and return a dict snapshot.

        Returns ``None`` if no device with the given IP is tracked.
        Used by the device detail endpoint to merge in-memory ``last_seen``
        into the DB result for real-time consistency.
        """
        if not ip:
            return None
        with self._lock:
            for dev in self._devices.values():
                if dev.ip_address == ip:
                    return {
                        "mac_address": dev.mac_address,
                        "ip_address": dev.ip_address,
                        "hostname": dev.hostname or dev.device_name or "",
                        "device_name": dev.device_name,
                        "vendor": dev.vendor,
                        "bytes_sent": dev.bytes_sent,
                        "bytes_received": dev.bytes_received,
                        "total_bytes": dev.bytes_sent + dev.bytes_received,
                        "packet_count": dev.packet_count,
                        "last_seen": datetime.fromtimestamp(dev.last_seen).strftime(
                            "%Y-%m-%d %H:%M:%S") if dev.last_seen else "",
                        "last_seen_ts": dev.last_seen,
                        "today_bytes": dev.today_bytes,
                        "today_sent": dev.today_sent,
                        "today_received": dev.today_received,
                    }
        return None

    def get_today_totals(self) -> tuple:
        """Return (today_bytes, today_packets)."""
        with self._lock:
            return self._today_bytes, self._today_packets

    def get_protocols(self) -> list:
        """Return protocol distribution list for the last hour."""
        now = time.time()
        with self._lock:
            self._prune_protocols(now)
            proto_agg: Dict[str, dict] = {}
            for _ts, proto, byte_count in self._protocol_records:
                if proto not in proto_agg:
                    proto_agg[proto] = {"name": proto, "count": 0, "bytes": 0}
                proto_agg[proto]["count"] += 1
                proto_agg[proto]["bytes"] += byte_count

            proto_list = sorted(proto_agg.values(), key=lambda p: p["bytes"], reverse=True)
            proto_total = sum(p["bytes"] for p in proto_list)
            for p in proto_list:
                p["percentage"] = round(
                    (p["bytes"] / proto_total * 100) if proto_total else 0, 2
                )
            return proto_list

    def clear(self) -> None:
        """Reset all in-memory state (e.g. on mode change).

        NOTE: does **not** reset ``_own_traffic_only`` / ``_allowed_macs``
        / ``_gateway_macs`` — those are set separately via
        ``set_mode_context()`` because the new mode's MAC info may not
        be available at clear-time.
        """
        with self._lock:
            self._devices.clear()
            self._today_bytes = 0
            self._today_packets = 0
            self._today_date = datetime.now().strftime("%Y-%m-%d")
            self._protocol_records.clear()
            self._last_update = 0.0
        logger.info("InMemoryDashboardState cleared")

    @property
    def device_count(self) -> int:
        """Total tracked devices (for diagnostics)."""
        with self._lock:
            return len(self._devices)

    # ------------------------------------------------------------------ #
    #  Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_trackable_mac(mac: str) -> bool:
        """Return True if *mac* should be tracked.

        Rejects broadcast, zero, and multicast MACs:
        - ff:ff:ff:ff:ff:ff  (broadcast)
        - 00:00:00:00:00:00  (zero / invalid)
        - 01:00:5e:*         (IPv4 multicast)
        - 33:33:*            (IPv6 multicast)
        - 01:80:c2:*         (STP / LLDP)
        """
        if not mac:
            return False
        mac_lower = mac.lower()
        if mac_lower in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""):
            return False
        # Multicast prefixes
        if mac_lower.startswith("01:00:5e:"):   # IPv4 multicast
            return False
        if mac_lower.startswith("33:33:"):       # IPv6 multicast
            return False
        if mac_lower.startswith("01:80:c2:"):   # STP / LLDP
            return False
        return True

    def _prune_protocols(self, now: float) -> None:
        """Remove protocol records older than the window. Must hold _lock."""
        cutoff = now - self._protocol_window_seconds
        # Trim from the front (records are appended chronologically)
        while self._protocol_records and self._protocol_records[0][0] < cutoff:
            self._protocol_records.popleft()

    def prune_stale_devices(self, stale_hours: int = 2) -> int:
        """Remove devices not seen in the last *stale_hours*.

        Called periodically by the cleanup task to prevent unbounded
        memory growth during 24/7 operation.  Returns the number of
        devices evicted.

        Also enforces MAX_DEVICES by evicting oldest devices when the
        limit is reached (LRU eviction).
        """
        now = time.time()
        cutoff = now - (stale_hours * 3600)
        evicted = 0

        with self._lock:
            # 1. Remove stale devices
            stale_macs = [
                mac for mac, dev in self._devices.items()
                if dev.last_seen < cutoff
            ]
            for mac in stale_macs:
                del self._devices[mac]
                evicted += 1

            # 2. Enforce MAX_DEVICES via LRU eviction
            if len(self._devices) > self.MAX_DEVICES:
                # Sort by last_seen (oldest first), evict excess
                sorted_devs = sorted(
                    self._devices.items(),
                    key=lambda kv: kv[1].last_seen,
                )
                excess = len(self._devices) - self.MAX_DEVICES
                for mac, _ in sorted_devs[:excess]:
                    del self._devices[mac]
                    evicted += 1

        if evicted:
            logger.info(
                "Pruned %d stale devices (cutoff=%dh, remaining=%d)",
                evicted, stale_hours, len(self._devices),
            )
        return evicted


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

dashboard_state = InMemoryDashboardState()
