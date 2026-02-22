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
from collections import defaultdict
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
        # List of (timestamp_float, protocol, byte_count) tuples
        self._protocol_records: list = []
        self._protocol_window_seconds: int = 3600  # 1 hour

        # Last update timestamp
        self._last_update: float = 0.0

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

                    # Running totals
                    self._today_bytes += byte_count
                    self._today_packets += 1

                    # Protocol tracking
                    self._protocol_records.append((now, protocol, byte_count))

                    # Source device
                    if source_mac and self._is_trackable_mac(source_mac):
                        dev = self._devices.get(source_mac)
                        if dev is None:
                            if len(self._devices) < self.MAX_DEVICES:
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
                            if source_ip and ":" not in source_ip and is_private_ip(source_ip):
                                dev.ip_address = source_ip
                            if device_name and not dev.device_name:
                                dev.device_name = device_name
                            if vendor and not dev.vendor:
                                dev.vendor = vendor

                    # Dest device
                    if dest_mac and self._is_trackable_mac(dest_mac):
                        dev = self._devices.get(dest_mac)
                        if dev is None:
                            if len(self._devices) < self.MAX_DEVICES:
                                dev = DeviceInfo(
                                    mac_address=dest_mac,
                                    ip_address=dest_ip,
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
                            if dest_ip and ":" not in dest_ip and is_private_ip(dest_ip):
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
        """Reset all in-memory state (e.g. on mode change)."""
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
            self._protocol_records.pop(0)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

dashboard_state = InMemoryDashboardState()
