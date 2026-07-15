"""
twin.py - Network Digital Twin (Phase 1)
=========================================

Maintains a live graph model of the network, built entirely from
event-bus telemetry (passive — no probing of its own):

* ``packet.batch``   → node liveness + communication edges
* ``dns.query``      → per-device recent DNS activity
* ``mode.changed``   → capture-mode timeline / context

Graph model
-----------
Nodes are either **local devices** (keyed ``mac:<addr>``), the
**gateway**, **self** (the capture host), or **external endpoints**
(keyed ``ip:<addr>``, public IPs aggregated per address).  Edges are
directed observed communications with byte/packet/protocol stats.

The twin is intentionally in-memory: durable history already lives in
the ``flows`` table, and the builder re-seeds itself from the DB on
startup.  Snapshot access is thread-safe and size-capped so the
``/api/twin`` endpoint stays cheap.
"""

import logging
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from intelligence.event_bus import event_bus as _default_bus

logger = logging.getLogger(__name__)

try:
    from utils.network_utils import is_private_ip
except ImportError:
    def is_private_ip(ip: str) -> bool:  # fallback for isolated tests
        return ip.startswith(("10.", "192.168.", "172.16.", "172.17.",
                              "172.18.", "172.19.", "172.2", "172.30.",
                              "172.31.", "169.254."))

# Multicast/broadcast MAC prefixes — never twin nodes
_EXCLUDED_MAC_PREFIXES = ("ff:ff:ff", "01:00:5e", "33:33", "01:80:c2")


def _is_noise_ip(ip: str) -> bool:
    """True for multicast/broadcast/loopback/unspecified addresses —
    traffic sinks that must never become twin nodes."""
    if not ip:
        return True
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return (addr.is_multicast or addr.is_loopback
                or addr.is_unspecified or addr.is_reserved
                or ip == "255.255.255.255")
    except ValueError:
        return True

MAX_NODES = 2000
MAX_EDGES = 5000
SNAPSHOT_MAX_EDGES = 500
RECENT_DNS_PER_DEVICE = 20
NODE_STALE_HOURS = 24


def _norm_mac(mac: Optional[str]) -> str:
    return (mac or "").lower().replace("-", ":").strip()


def _is_excluded_mac(mac: str) -> bool:
    return not mac or mac.startswith(_EXCLUDED_MAC_PREFIXES)


class _Node:
    __slots__ = ("node_id", "node_type", "mac", "ip", "hostname", "vendor",
                 "first_seen", "last_seen", "bytes_in", "bytes_out",
                 "packets", "protocols", "recent_dns")

    def __init__(self, node_id: str, node_type: str, mac: str = "", ip: str = ""):
        now = time.time()
        self.node_id = node_id
        self.node_type = node_type      # device | gateway | self | external
        self.mac = mac
        self.ip = ip
        self.hostname = ""
        self.vendor = ""
        self.first_seen = now
        self.last_seen = now
        self.bytes_in = 0
        self.bytes_out = 0
        self.packets = 0
        self.protocols: Counter = Counter()
        self.recent_dns: deque = deque(maxlen=RECENT_DNS_PER_DEVICE)

    def to_dict(self) -> dict:
        return {
            "id": self.node_id,
            "type": self.node_type,
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "packets": self.packets,
            "protocols": [p for p, _ in self.protocols.most_common(5)],
            "recent_dns": list(self.recent_dns),
        }


class _Edge:
    __slots__ = ("source", "target", "first_seen", "last_seen",
                 "bytes", "packets", "protocols")

    def __init__(self, source: str, target: str):
        now = time.time()
        self.source = source
        self.target = target
        self.first_seen = now
        self.last_seen = now
        self.bytes = 0
        self.packets = 0
        self.protocols: Counter = Counter()

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "bytes": self.bytes,
            "packets": self.packets,
            "protocols": [p for p, _ in self.protocols.most_common(3)],
        }


class TwinBuilder:
    """Event-bus consumer that maintains the network digital twin."""

    def __init__(self, shutdown_event: Optional[threading.Event] = None,
                 bus=None, seed_from_db: bool = True):
        self._bus = bus or _default_bus
        self._shutdown_event = shutdown_event or threading.Event()
        self._seed_from_db = seed_from_db

        self._lock = threading.Lock()
        self._nodes: Dict[str, _Node] = {}
        self._edges: Dict[tuple, _Edge] = {}

        # Context (set by main.py at startup; updated on mode changes)
        self._our_mac = ""
        self._our_ip = ""
        self._gateway_mac = ""
        self._gateway_ip = ""
        self._mode = "unknown"
        self._mode_timeline: deque = deque(maxlen=100)

        self._thread: Optional[threading.Thread] = None
        self._sub = None
        self._last_prune = time.monotonic()

        # Diagnostics
        self.events_consumed = 0

    # ------------------------------------------------------------------ #
    #  Context
    # ------------------------------------------------------------------ #

    def set_context(self, our_mac: str = "", our_ip: str = "",
                    gateway_mac: str = "", gateway_ip: str = "",
                    mode: str = "") -> None:
        """Identify self/gateway so their nodes get the right roles."""
        with self._lock:
            self._our_mac = _norm_mac(our_mac)
            self._our_ip = our_ip or ""
            self._gateway_mac = _norm_mac(gateway_mac)
            self._gateway_ip = gateway_ip or ""
            if mode:
                self._mode = mode
            # Re-role any existing nodes
            for node in self._nodes.values():
                node_role = self._role_for(node.mac, node.ip)
                if node_role and node.node_type != node_role:
                    node.node_type = node_role

    def _role_for(self, mac: str, ip: str) -> Optional[str]:
        """Return special role for a local node, or None for plain device."""
        if mac and mac == self._our_mac:
            return "self"
        if ip and ip == self._our_ip:
            return "self"
        if mac and mac == self._gateway_mac:
            return "gateway"
        if ip and ip == self._gateway_ip:
            return "gateway"
        return None

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        if self._seed_from_db:
            try:
                self._seed()
            except Exception as exc:
                logger.warning("Twin seeding failed (starting empty): %s", exc)
        self._sub = self._bus.subscribe(
            ["packet.batch", "dns.query", "mode.changed"],
            name="twin-builder",
        )
        self._thread = threading.Thread(
            target=self._run, name="TwinBuilder", daemon=True,
        )
        self._thread.start()
        logger.info("TwinBuilder started (nodes=%d after seeding)", len(self._nodes))
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._shutdown_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._sub is not None:
            self._bus.unsubscribe(self._sub)

    def _run(self) -> None:
        while not self._shutdown_event.is_set():
            event = self._sub.get(timeout=0.5)
            if event is None:
                continue
            try:
                self.events_consumed += 1
                if event.topic == "packet.batch":
                    self.ingest_packets(event.payload)
                elif event.topic == "dns.query":
                    self.ingest_dns(event.payload)
                elif event.topic == "mode.changed":
                    self.ingest_mode_change(event.payload)
            except Exception as exc:
                logger.error("TwinBuilder event error: %s", exc)

            now = time.monotonic()
            if now - self._last_prune >= 300:
                try:
                    self.prune()
                except Exception as exc:
                    logger.error("Twin prune error: %s", exc)
                self._last_prune = now
        logger.info("TwinBuilder thread exited")

    # ------------------------------------------------------------------ #
    #  Seeding from durable storage
    # ------------------------------------------------------------------ #

    def _seed(self) -> None:
        """Rebuild nodes/edges from the devices table + recent flows."""
        from database.queries.device_queries import get_all_devices
        from database.queries.flow_queries import get_recent_flows

        for d in get_all_devices(limit=500, hours=NODE_STALE_HOURS):
            mac = _norm_mac(d.get("mac_address"))
            if _is_excluded_mac(mac):
                continue
            node = self._get_or_create_local(mac, d.get("ip_address") or
                                             d.get("ipv4_address") or "")
            if node is None:
                continue
            node.hostname = d.get("hostname") or d.get("device_name") or ""
            node.vendor = d.get("vendor") or ""

        since = (datetime.now() - timedelta(hours=NODE_STALE_HOURS)).strftime(
            "%Y-%m-%d %H:%M:%S")
        for f in get_recent_flows(limit=2000, since=since):
            self._fold_communication(
                src_mac=_norm_mac(f.get("source_mac")),
                dst_mac=_norm_mac(f.get("dest_mac")),
                src_ip=f.get("source_ip") or "",
                dst_ip=f.get("dest_ip") or "",
                protocol=f.get("protocol") or "UNKNOWN",
                nbytes=int(f.get("bytes_total") or 0),
                npackets=int(f.get("packets_total") or 0),
                touch_liveness=False,
                direction=f.get("direction") or "",
            )

    # ------------------------------------------------------------------ #
    #  Ingestion
    # ------------------------------------------------------------------ #

    def ingest_packets(self, batch: List[dict]) -> None:
        with self._lock:
            for p in batch:
                self._fold_communication(
                    src_mac=_norm_mac(p.get("source_mac")),
                    dst_mac=_norm_mac(p.get("dest_mac")),
                    src_ip=p.get("source_ip") or "",
                    dst_ip=p.get("dest_ip") or "",
                    protocol=p.get("protocol") or "UNKNOWN",
                    nbytes=int(p.get("bytes") or 0),
                    npackets=1,
                    device_name=p.get("device_name"),
                    vendor=p.get("vendor"),
                    direction=p.get("direction") or "",
                )

    def ingest_dns(self, dns_event: dict) -> None:
        mac = _norm_mac(dns_event.get("source_mac"))
        qname = dns_event.get("qname")
        if _is_excluded_mac(mac) or not qname:
            return
        with self._lock:
            node = self._nodes.get(f"mac:{mac}")
            if node is not None and (not node.recent_dns or node.recent_dns[-1] != qname):
                node.recent_dns.append(qname)

    def ingest_mode_change(self, event: dict) -> None:
        with self._lock:
            self._mode = event.get("new_mode") or self._mode
            self._mode_timeline.append(dict(event))

    # ------------------------------------------------------------------ #
    #  Graph mutation (caller holds lock unless seeding single-threaded)
    # ------------------------------------------------------------------ #

    def _get_or_create_local(self, mac: str, ip: str) -> Optional[_Node]:
        node_id = f"mac:{mac}"
        node = self._nodes.get(node_id)
        if node is None:
            if len(self._nodes) >= MAX_NODES:
                return None
            role = self._role_for(mac, ip) or "device"
            node = _Node(node_id, role, mac=mac, ip=ip)
            self._nodes[node_id] = node
        if ip:
            node.ip = ip
        return node

    def _get_or_create_external(self, ip: str) -> Optional[_Node]:
        node_id = f"ip:{ip}"
        node = self._nodes.get(node_id)
        if node is None:
            if len(self._nodes) >= MAX_NODES:
                return None
            node = _Node(node_id, "external", ip=ip)
            self._nodes[node_id] = node
        return node

    def _endpoint_node(self, mac: str, ip: str,
                       local_hint: bool = False) -> Optional[_Node]:
        """Resolve one side of a communication to a twin node.

        Role (self/gateway MAC) and *local_hint* (from the packet's
        direction) beat IP-based classification: a local device using a
        global IPv6 address must not become an "external" node.
        """
        if ip and _is_noise_ip(ip):
            return None
        if not _is_excluded_mac(mac) and (
            local_hint or self._role_for(mac, "") is not None
        ):
            return self._get_or_create_local(mac, ip)
        if ip and not is_private_ip(ip):
            return self._get_or_create_external(ip)
        if not _is_excluded_mac(mac):
            return self._get_or_create_local(mac, ip)
        return None

    def _fold_communication(self, src_mac: str, dst_mac: str,
                            src_ip: str, dst_ip: str, protocol: str,
                            nbytes: int, npackets: int,
                            device_name: Optional[str] = None,
                            vendor: Optional[str] = None,
                            touch_liveness: bool = True,
                            direction: str = "") -> None:
        # Direction identifies the local side even when its IP is a
        # global IPv6 address: upload → source is local, download → dest.
        src = self._endpoint_node(src_mac, src_ip,
                                  local_hint=(direction == "upload"))
        dst = self._endpoint_node(dst_mac, dst_ip,
                                  local_hint=(direction == "download"))
        if src is None or dst is None or src.node_id == dst.node_id:
            return

        now = time.time()
        src.bytes_out += nbytes
        dst.bytes_in += nbytes
        src.packets += npackets
        dst.packets += npackets
        src.protocols[protocol] += npackets
        if touch_liveness:
            src.last_seen = now
            dst.last_seen = now
        if device_name and src.node_type in ("device", "self") and not src.hostname:
            src.hostname = device_name
        if vendor and not src.vendor:
            src.vendor = vendor

        key = (src.node_id, dst.node_id)
        edge = self._edges.get(key)
        if edge is None:
            if len(self._edges) >= MAX_EDGES:
                return
            edge = _Edge(*key)
            self._edges[key] = edge
        edge.bytes += nbytes
        edge.packets += npackets
        edge.protocols[protocol] += npackets
        if touch_liveness:
            edge.last_seen = now

    # ------------------------------------------------------------------ #
    #  Maintenance & access
    # ------------------------------------------------------------------ #

    def prune(self, stale_hours: float = NODE_STALE_HOURS) -> int:
        """Drop nodes/edges not seen within *stale_hours* (never self/gateway)."""
        cutoff = time.time() - stale_hours * 3600
        removed = 0
        with self._lock:
            stale = [
                nid for nid, n in self._nodes.items()
                if n.last_seen < cutoff and n.node_type not in ("self", "gateway")
            ]
            for nid in stale:
                del self._nodes[nid]
                removed += 1
            if stale:
                stale_set = set(stale)
                self._edges = {
                    k: e for k, e in self._edges.items()
                    if k[0] not in stale_set and k[1] not in stale_set
                }
            # Edge-only staleness
            self._edges = {
                k: e for k, e in self._edges.items() if e.last_seen >= cutoff
            }
        if removed:
            logger.info("Twin prune: removed %d stale nodes", removed)
        return removed

    def snapshot(self, max_edges: int = SNAPSHOT_MAX_EDGES) -> dict:
        """Thread-safe JSON-ready view of the twin (size-capped)."""
        with self._lock:
            edges = sorted(
                self._edges.values(), key=lambda e: e.bytes, reverse=True,
            )[:max_edges]
            keep_ids = {e.source for e in edges} | {e.target for e in edges}
            # Always include local devices even if edge-less (just seeded)
            nodes = [
                n.to_dict() for n in self._nodes.values()
                if n.node_id in keep_ids or n.node_type in ("device", "self", "gateway")
            ]
            return {
                "generated_at": time.time(),
                "mode": self._mode,
                "stats": {
                    "node_count": len(self._nodes),
                    "edge_count": len(self._edges),
                    "device_count": sum(
                        1 for n in self._nodes.values()
                        if n.node_type in ("device", "self")
                    ),
                    "external_count": sum(
                        1 for n in self._nodes.values()
                        if n.node_type == "external"
                    ),
                    "events_consumed": self.events_consumed,
                },
                "mode_timeline": list(self._mode_timeline)[-10:],
                "nodes": nodes,
                "edges": [e.to_dict() for e in edges],
            }

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                "events_consumed": self.events_consumed,
                "mode": self._mode,
                "running": bool(self._thread and self._thread.is_alive()),
            }
