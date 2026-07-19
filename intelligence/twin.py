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

# How recently a device/external node must have been seen to appear in the
# *live* topology snapshot and its counts. Node retention (NODE_STALE_HOURS)
# is a memory bound; this is the "is it on the network right now" window, so
# a client that disconnects drops off the map within minutes rather than
# lingering for a day. self/gateway are structural and never filtered out.
try:
    from config import TWIN_ACTIVE_DEVICE_SECONDS as _ACTIVE_SECS
    TWIN_ACTIVE_SECONDS = float(_ACTIVE_SECS)
except (ImportError, ValueError, TypeError):
    TWIN_ACTIVE_SECONDS = 300.0


def _norm_mac(mac: Optional[str]) -> str:
    return (mac or "").lower().replace("-", ":").strip()


def _is_excluded_mac(mac: str) -> bool:
    return not mac or mac.startswith(_EXCLUDED_MAC_PREFIXES)


class _Node:
    __slots__ = ("node_id", "node_type", "mac", "ip", "hostname", "vendor",
                 "first_seen", "last_seen", "bytes_in", "bytes_out",
                 "packets", "protocols", "recent_dns")

    def __init__(self, node_id: str, node_type: str, mac: str = "", ip: str = "",
                 seen: Optional[float] = None):
        now = seen if seen is not None else time.time()
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

    def __init__(self, source: str, target: str, seen: Optional[float] = None):
        now = seen if seen is not None else time.time()
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
        # Full set of the host's own adapter MACs / IPs — so the host's
        # *other* interfaces (e.g. the pre-hotspot Wi-Fi adapter at
        # 192.168.1.68) are recognized as "self", not counted as devices.
        self._host_macs: set = set()
        self._host_ips: set = set()
        # Current monitored subnet prefix (e.g. "192.168.137"); device
        # nodes whose IPv4 is outside it are stale from a previous network.
        self._subnet_prefix = ""
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
                    mode: str = "", host_macs=None, host_ips=None,
                    subnet: str = "") -> None:
        """Identify self/gateway so their nodes get the right roles.

        *host_macs* / *host_ips* are the monitoring machine's full adapter
        sets (from ``get_all_local_macs`` / ``get_all_local_ips``) so every
        host interface — not just the capture one — is treated as "self".
        *subnet* is the current monitored /24 prefix ("192.168.137") used to
        drop device nodes left over from a previous network.
        """
        with self._lock:
            self._our_mac = _norm_mac(our_mac)
            self._our_ip = our_ip or ""
            self._gateway_mac = _norm_mac(gateway_mac)
            self._gateway_ip = gateway_ip or ""
            if host_macs is not None:
                self._host_macs = {_norm_mac(m) for m in host_macs if m}
            if host_ips is not None:
                self._host_ips = {ip for ip in host_ips if ip}
            if subnet:
                self._subnet_prefix = subnet
            if mode:
                self._mode = mode
            # Re-role any existing nodes and pin authoritative addresses
            for node in self._nodes.values():
                node_role = self._role_for(node.mac, node.ip)
                if node_role and node.node_type != node_role:
                    node.node_type = node_role
                if node.node_type == "self" and self._our_ip:
                    node.ip = self._our_ip
                elif node.node_type == "gateway" and self._gateway_ip:
                    node.ip = self._gateway_ip

    def _role_for(self, mac: str, ip: str) -> Optional[str]:
        """Return special role for a local node, or None for plain device."""
        if mac and mac == self._our_mac:
            return "self"
        if ip and ip == self._our_ip:
            return "self"
        # Any of the host's *other* adapters (e.g. the leftover Wi-Fi NIC in
        # hotspot mode) is still "self", never a client device.
        if mac and mac in self._host_macs:
            return "self"
        if ip and ip in self._host_ips:
            return "self"
        # In hotspot/ICS the host IS the gateway: the same machine at the same
        # address. Emitting a separate "gateway" node drew the host twice on
        # the topology (a blue 192.168.137.1 and an orange 192.168.137.1 joined
        # by a meaningless edge). Collapse them into the single self node.
        host_is_gateway = bool(self._gateway_ip) and self._gateway_ip == self._our_ip
        if mac and mac == self._gateway_mac:
            return "self" if host_is_gateway else "gateway"
        if ip and ip == self._gateway_ip:
            return "self" if host_is_gateway else "gateway"
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

    @staticmethod
    def _parse_ts(value) -> Optional[float]:
        """DB timestamp (str/datetime) → epoch seconds, or None."""
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str) and value:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(value[:19], fmt).timestamp()
                except ValueError:
                    continue
        return None

    def _seed(self) -> None:
        """Rebuild nodes/edges from the devices table + recent flows.

        Seeded nodes keep their *stored* last_seen: stamping them "now"
        would make every device from the last 24h render as live for the
        first TWIN_ACTIVE_SECONDS after a restart.
        """
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
            seen = self._parse_ts(d.get("last_seen"))
            if seen:
                node.last_seen = seen
                node.first_seen = min(
                    node.first_seen, self._parse_ts(d.get("first_seen")) or seen)

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
                seen_at=self._parse_ts(f.get("last_seen")),
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
            old = self._mode
            new = event.get("new_mode") or self._mode
            self._mode = new
            self._mode_timeline.append(dict(event))
            # A mode change means a different network (new subnet/gateway).
            # Keeping the old graph would draw last network's devices and
            # endpoints on top of this one, so start clean; the mode
            # handler re-sets self/gateway context right after.
            if old != new and old != "unknown":
                self._nodes.clear()
                self._edges.clear()
                logger.info("Twin reset for mode change %s -> %s", old, new)

    # ------------------------------------------------------------------ #
    #  Graph mutation (caller holds lock unless seeding single-threaded)
    # ------------------------------------------------------------------ #

    def _get_or_create_local(self, mac: str, ip: str,
                             seen_at: Optional[float] = None) -> Optional[_Node]:
        node_id = f"mac:{mac}"
        node = self._nodes.get(node_id)
        if node is None:
            if len(self._nodes) >= MAX_NODES:
                return None
            role = self._role_for(mac, ip) or "device"
            node = _Node(node_id, role, mac=mac, ip="", seen=seen_at)
            self._nodes[node_id] = node
        self._update_node_ip(node, ip)
        return node

    def _update_node_ip(self, node: _Node, ip: str) -> None:
        """Adopt *ip* as the node's display address only when it is an
        improvement.  Every packet used to overwrite it, so a device
        flapped between IPv4 and fe80::… labels, and one mis-attributed
        packet could relabel the capture host with an external IP."""
        if not ip or ip == node.ip:
            return
        # self/gateway addresses are authoritative context, not inferred.
        if node.node_type == "self" and self._our_ip:
            node.ip = self._our_ip
            return
        if node.node_type == "gateway" and self._gateway_ip:
            node.ip = self._gateway_ip
            return
        if not node.ip:
            node.ip = ip
            return
        is_v4 = "." in ip and ":" not in ip
        had_v4 = "." in node.ip and ":" not in node.ip
        if had_v4 and not is_v4:
            return                       # never replace IPv4 with IPv6
        if ip.lower().startswith(("fe80:", "169.254.")):
            return                       # never adopt link-local over anything
        if had_v4 and is_v4 and is_private_ip(node.ip) and not is_private_ip(ip):
            return                       # keep the private address for local nodes
        node.ip = ip

    def _get_or_create_external(self, ip: str,
                                seen_at: Optional[float] = None) -> Optional[_Node]:
        node_id = f"ip:{ip}"
        node = self._nodes.get(node_id)
        if node is None:
            if len(self._nodes) >= MAX_NODES:
                return None
            node = _Node(node_id, "external", ip=ip, seen=seen_at)
            self._nodes[node_id] = node
        return node

    def _endpoint_node(self, mac: str, ip: str,
                       local_hint: bool = False,
                       seen_at: Optional[float] = None) -> Optional[_Node]:
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
            return self._get_or_create_local(mac, ip, seen_at=seen_at)
        if ip and not is_private_ip(ip):
            return self._get_or_create_external(ip, seen_at=seen_at)
        if not _is_excluded_mac(mac):
            return self._get_or_create_local(mac, ip, seen_at=seen_at)
        return None

    def _fold_communication(self, src_mac: str, dst_mac: str,
                            src_ip: str, dst_ip: str, protocol: str,
                            nbytes: int, npackets: int,
                            device_name: Optional[str] = None,
                            vendor: Optional[str] = None,
                            touch_liveness: bool = True,
                            direction: str = "",
                            seen_at: Optional[float] = None) -> None:
        # Direction identifies the local side even when its IP is a
        # global IPv6 address: upload → source is local, download → dest.
        src = self._endpoint_node(src_mac, src_ip,
                                  local_hint=(direction == "upload"),
                                  seen_at=seen_at)
        dst = self._endpoint_node(dst_mac, dst_ip,
                                  local_hint=(direction == "download"),
                                  seen_at=seen_at)
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
            edge = _Edge(*key, seen=seen_at if not touch_liveness else None)
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
        """Thread-safe JSON-ready view of the twin (size-capped).

        Only *live* nodes are returned: self/gateway are always present
        (structural), while device/external nodes must have been seen within
        ``TWIN_ACTIVE_SECONDS`` — so a client that left the network drops off
        the map (and the counts) promptly instead of lingering for hours.
        """
        with self._lock:
            active_cutoff = time.time() - TWIN_ACTIVE_SECONDS

            def _out_of_subnet(node) -> bool:
                # A device node whose IPv4 is outside the monitored subnet is
                # a leftover from a previous network (e.g. the host's own
                # 192.168.1.68 Wi-Fi adapter while the hotspot is 192.168.137).
                if not self._subnet_prefix or node.node_type != "device":
                    return False
                ip = node.ip or ""
                if not ip or ":" in ip:      # no IPv4 to judge → keep
                    return False
                return not ip.startswith(self._subnet_prefix + ".")

            def _is_live(node) -> bool:
                if node.node_type in ("self", "gateway"):
                    return True
                if _out_of_subnet(node):
                    return False
                return node.last_seen >= active_cutoff

            live_ids = {
                nid for nid, n in self._nodes.items() if _is_live(n)
            }

            # ---- collapse duplicate host nodes ---------------------------
            # The host can produce several nodes: one per adapter, plus the
            # gateway identity (in hotspot the host IS the gateway). They are
            # one machine, so the map must draw one — previously it showed two
            # 192.168.137.1 circles joined by a meaningless self-to-self edge.
            self_ids = {nid for nid in live_ids
                        if self._nodes[nid].node_type == "self"}
            host_id = None
            if len(self_ids) > 1:
                def _host_rank(nid):
                    n = self._nodes[nid]
                    return (n.mac == self._our_mac, n.ip == self._our_ip,
                            n.bytes_in + n.bytes_out)
                host_id = max(self_ids, key=_host_rank)
                live_ids -= (self_ids - {host_id})

            def _canon(nid):
                """Map any host-adapter node id onto the single host node."""
                return host_id if (host_id and nid in self_ids) else nid
            # An edge is live only if both endpoints are live, so we never
            # draw a line to a node that has aged out of the view. The count
            # is over all live edges; the drawn list is additionally capped.
            live_edges = [
                e for e in self._edges.values()
                if _canon(e.source) in live_ids and _canon(e.target) in live_ids
                # A host adapter talking to another host adapter is the machine
                # talking to itself — not a network link worth drawing.
                and _canon(e.source) != _canon(e.target)
            ]
            edges = sorted(
                live_edges, key=lambda e: e.bytes, reverse=True,
            )[:max_edges]
            keep_ids = {_canon(e.source) for e in edges} | \
                       {_canon(e.target) for e in edges}
            nodes = [
                n.to_dict() for n in self._nodes.values()
                if n.node_id in live_ids and (
                    n.node_id in keep_ids
                    or n.node_type in ("device", "self", "gateway")
                )
            ]

            # Counts describe the *live* network. "self" is the capture host,
            # not a client — it is excluded from device_count so this number
            # agrees with the dashboard's active-device count.
            device_count = sum(
                1 for n in self._nodes.values()
                if n.node_type == "device" and n.last_seen >= active_cutoff
                and not _out_of_subnet(n)
            )
            external_count = sum(
                1 for n in self._nodes.values()
                if n.node_type == "external" and n.last_seen >= active_cutoff
            )
            return {
                "generated_at": time.time(),
                "mode": self._mode,
                "stats": {
                    "node_count": len(self._nodes),
                    "edge_count": len(live_edges),
                    "device_count": device_count,
                    "external_count": external_count,
                    "events_consumed": self.events_consumed,
                },
                "mode_timeline": list(self._mode_timeline)[-10:],
                "nodes": nodes,
                "edges": self._serialize_edges(edges, _canon),
            }

    @staticmethod
    def _serialize_edges(edges, canon) -> list:
        """Edge dicts with host-adapter ids collapsed onto the single host node.

        Several adapter nodes can carry edges to the same peer; after collapsing
        they become the same link, so their traffic is merged rather than drawn
        as parallel lines.
        """
        merged = {}
        for e in edges:
            d = e.to_dict()
            d["source"], d["target"] = canon(e.source), canon(e.target)
            key = (d["source"], d["target"])
            prev = merged.get(key)
            if prev is None:
                merged[key] = d
                continue
            prev["bytes"] = (prev.get("bytes") or 0) + (d.get("bytes") or 0)
            prev["packets"] = (prev.get("packets") or 0) + (d.get("packets") or 0)
            protos = set(prev.get("protocols") or []) | set(d.get("protocols") or [])
            prev["protocols"] = sorted(protos)
        return list(merged.values())

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                "events_consumed": self.events_consumed,
                "mode": self._mode,
                "running": bool(self._thread and self._thread.is_alive()),
            }
