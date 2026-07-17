"""
threats.py - Threat Detector Pack (Phase 2)
============================================

Named threat detection on top of the flow/DNS event stream.  Consumes
``flow.completed`` and ``dns.query`` events from the bus — never the
capture hot path.  Every alert carries ``evidence[]`` and ``confidence``
so incidents are explainable, and dedups per (threat, device) through
``AlertEngine.create_threat_alert``.

Detectors
---------
* **port_scan** — one source touching many distinct ports on one host
  (vertical) or one port across many hosts (horizontal) inside a short
  window.
* **beaconing** — flows from one source to the same external
  (host, port) at suspiciously regular intervals (low jitter), the
  classic C2 heartbeat shape.
* **dns_tunneling** — a burst of DNS queries to one registered domain
  with long / high-entropy labels (data smuggled in qnames).
* **rogue_device** — a source MAC that has never been seen on this
  network before (seeded from the devices table).
* **lateral_movement** — one internal source connecting to several
  distinct internal hosts on admin ports (SMB/RDP/SSH/WinRM/VNC).

All state is in-memory sliding windows; nothing here blocks the bus for
long and memory is bounded per detector.
"""

import logging
import math
import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, List, Optional, Set, Tuple

from intelligence.event_bus import event_bus as _default_bus

try:
    from utils.network_utils import is_private_ip
except ImportError:  # isolated tests
    def is_private_ip(ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172.16.", "169.254."))

logger = logging.getLogger(__name__)

try:
    from config import (
        THREAT_PORTSCAN_WINDOW_SECONDS,
        THREAT_PORTSCAN_PORT_THRESHOLD,
        THREAT_PORTSCAN_HOST_THRESHOLD,
        THREAT_BEACON_MIN_OBSERVATIONS,
        THREAT_BEACON_MAX_JITTER_RATIO,
        THREAT_DNS_TUNNEL_WINDOW_SECONDS,
        THREAT_DNS_TUNNEL_QUERY_THRESHOLD,
        THREAT_DNS_TUNNEL_QNAME_LENGTH,
        THREAT_DNS_TUNNEL_ENTROPY,
        THREAT_LATERAL_WINDOW_SECONDS,
        THREAT_LATERAL_HOST_THRESHOLD,
    )
except ImportError:
    THREAT_PORTSCAN_WINDOW_SECONDS = 120
    THREAT_PORTSCAN_PORT_THRESHOLD = 15
    THREAT_PORTSCAN_HOST_THRESHOLD = 10
    THREAT_BEACON_MIN_OBSERVATIONS = 6
    THREAT_BEACON_MAX_JITTER_RATIO = 0.25
    THREAT_DNS_TUNNEL_WINDOW_SECONDS = 300
    THREAT_DNS_TUNNEL_QUERY_THRESHOLD = 25
    THREAT_DNS_TUNNEL_QNAME_LENGTH = 40
    THREAT_DNS_TUNNEL_ENTROPY = 3.8
    THREAT_LATERAL_WINDOW_SECONDS = 300
    THREAT_LATERAL_HOST_THRESHOLD = 3

# Admin/remote-management ports watched by the lateral-movement detector.
LATERAL_PORTS = {22, 23, 135, 139, 445, 3389, 5900, 5985, 5986}

# Vertical-scan port counting ignores the ephemeral range: return traffic
# to a busy client lands on many distinct ephemeral ports and looks
# exactly like a scan otherwise (the classic gateway-"scans"-you FP).
_EPHEMERAL_PORT_START = 32768

# Messaging/web keepalive ports (HTTPS, XMPP push, DoT, NTP…). Mobile
# apps heartbeat on these with 3-5% jitter — indistinguishable from C2 by
# interval alone — so on these ports beaconing needs near-zero jitter.
_BEACON_COMMON_PORTS = {80, 443, 853, 123, 5222, 5223, 4500}
_BEACON_COMMON_PORT_MAX_JITTER = 0.02

# Beacon intervals outside this band are either interactive traffic
# (too fast) or too slow to conclude regularity from a short horizon.
_BEACON_MIN_INTERVAL = 5.0
_BEACON_MAX_INTERVAL = 900.0
_BEACON_HISTORY = 24          # timestamps kept per (src, dst, port)
_MAX_TRACKED_KEYS = 5000      # global guard for per-detector dicts

_EXCLUDED_MAC_PREFIXES = ("ff:ff:ff", "01:00:5e", "33:33", "01:80:c2")

# Registered domains that legitimately emit long, high-entropy subdomain
# bursts (carrier IMS/VoWiFi, some CDNs) — exempt from DNS-tunnel scoring.
_BENIGN_LONG_QNAME_DOMAINS = {
    "3gppnetwork.org",   # ePDG / VoWiFi / IMS APNs
    "aaplimg.com",       # Apple CDN
    "akadns.net",        # Akamai
    "akamaiedge.net",
}


def _norm_mac(mac: Optional[str]) -> str:
    return (mac or "").lower().replace("-", ":").strip()


def _is_excluded_mac(mac: str) -> bool:
    return not mac or mac.startswith(_EXCLUDED_MAC_PREFIXES)


_oui_cache: Dict[str, str] = {}


def _oui_vendor(mac: str) -> str:
    """Best-effort OUI → vendor (cached, lazy, never raises)."""
    if not mac:
        return ""
    if mac in _oui_cache:
        return _oui_cache[mac]
    vendor = ""
    try:
        from mac_vendor_lookup import MacLookup
        vendor = MacLookup().lookup(mac)
    except Exception:
        vendor = ""
    if len(_oui_cache) < 4096:
        _oui_cache[mac] = vendor
    return vendor


def _is_known_consumer_vendor(vendor: str) -> bool:
    try:
        from intelligence.device_fingerprint import is_known_consumer_vendor
        return is_known_consumer_vendor(vendor)
    except Exception:
        return False


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(text))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _registered_domain(qname: str) -> str:
    """Crude eTLD+1: last two labels ('a.b.evil.com' → 'evil.com')."""
    labels = [l for l in (qname or "").lower().rstrip(".").split(".") if l]
    return ".".join(labels[-2:]) if len(labels) >= 2 else (qname or "").lower()


class _SlidingWindow:
    """Timestamped observations pruned to a max age."""

    __slots__ = ("max_age", "items")

    def __init__(self, max_age: float):
        self.max_age = max_age
        self.items: Deque[Tuple[float, object]] = deque()

    def add(self, now: float, value: object) -> None:
        self.items.append((now, value))
        self.prune(now)

    def prune(self, now: float) -> None:
        cutoff = now - self.max_age
        while self.items and self.items[0][0] < cutoff:
            self.items.popleft()

    def values(self) -> List[object]:
        return [v for _, v in self.items]

    def __len__(self) -> int:
        return len(self.items)


class ThreatDetector:
    """Event-bus consumer running the Phase 2 threat detector pack."""

    def __init__(
        self,
        alert_engine=None,
        shutdown_event: Optional[threading.Event] = None,
        bus=None,
        seed_known_macs: bool = True,
        now_fn: Callable[[], float] = time.time,
        portscan_window: float = THREAT_PORTSCAN_WINDOW_SECONDS,
        portscan_port_threshold: int = THREAT_PORTSCAN_PORT_THRESHOLD,
        portscan_host_threshold: int = THREAT_PORTSCAN_HOST_THRESHOLD,
        beacon_min_observations: int = THREAT_BEACON_MIN_OBSERVATIONS,
        beacon_max_jitter: float = THREAT_BEACON_MAX_JITTER_RATIO,
        dns_window: float = THREAT_DNS_TUNNEL_WINDOW_SECONDS,
        dns_query_threshold: int = THREAT_DNS_TUNNEL_QUERY_THRESHOLD,
        dns_qname_length: int = THREAT_DNS_TUNNEL_QNAME_LENGTH,
        dns_entropy: float = THREAT_DNS_TUNNEL_ENTROPY,
        lateral_window: float = THREAT_LATERAL_WINDOW_SECONDS,
        lateral_host_threshold: int = THREAT_LATERAL_HOST_THRESHOLD,
    ):
        self._alert_engine = alert_engine
        self._bus = bus or _default_bus
        self._shutdown_event = shutdown_event or threading.Event()
        self._seed_known = seed_known_macs
        self._now = now_fn

        self._portscan_window = portscan_window
        self._portscan_port_threshold = portscan_port_threshold
        self._portscan_host_threshold = portscan_host_threshold
        self._beacon_min_obs = beacon_min_observations
        self._beacon_max_jitter = beacon_max_jitter
        self._dns_window = dns_window
        self._dns_query_threshold = dns_query_threshold
        self._dns_qname_length = dns_qname_length
        self._dns_entropy = dns_entropy
        self._lateral_window = lateral_window
        self._lateral_host_threshold = lateral_host_threshold

        self._lock = threading.Lock()
        # port_scan: src → window of (dst_ip, dst_port)
        self._scan: Dict[str, _SlidingWindow] = {}
        # beaconing: (src, dst_ip, dst_port) → deque of flow start times
        self._beacons: Dict[tuple, Deque[float]] = {}
        # dns_tunneling: (src, registered_domain) → window of qnames
        self._dns: Dict[tuple, _SlidingWindow] = {}
        # lateral: src → window of (dst_ip, dst_port) on admin ports
        self._lateral: Dict[str, _SlidingWindow] = {}
        # rogue_device: every MAC ever seen (seeded from devices table)
        self._known_macs: Set[str] = set()
        # Our own interfaces + the gateway: their traffic is capture-host
        # plumbing (discovery sweeps, return traffic, NAT forwarding) and
        # must never be scored as an attacker.
        self._ignored_macs: Set[str] = set()
        # (threat_type, key) pairs already alerted — session-scoped dedup
        # on top of AlertEngine's cooldown dedup.
        self._alerted: Set[tuple] = set()

        self._thread: Optional[threading.Thread] = None
        self._sub = None

        # Diagnostics
        self.threats_found = 0
        self.flows_seen = 0
        self.dns_seen = 0

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        if self._seed_known:
            try:
                self._seed_known_macs()
            except Exception as exc:
                logger.warning("Known-MAC seeding failed (cold start): %s", exc)
        self._sub = self._bus.subscribe(
            ["flow.completed", "dns.query"], name="threat-detector",
        )
        self._thread = threading.Thread(
            target=self._run, name="ThreatDetector", daemon=True,
        )
        self._thread.start()
        logger.info(
            "ThreatDetector started (known_macs=%d, detectors=port_scan,"
            "beaconing,dns_tunneling,rogue_device,lateral_movement)",
            len(self._known_macs),
        )
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._shutdown_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._sub is not None:
            self._bus.unsubscribe(self._sub)

    def _run(self) -> None:
        while not self._shutdown_event.is_set():
            event = self._sub.get(timeout=1.0)
            if event is None:
                continue
            try:
                if event.topic == "flow.completed":
                    self.ingest_flow(event.payload)
                elif event.topic == "dns.query":
                    self.ingest_dns(event.payload)
            except Exception as exc:
                logger.error("ThreatDetector ingest error: %s", exc)
        logger.info("ThreatDetector thread exited")

    def set_context(self, local_macs=None, gateway_mac: str = "") -> None:
        """Identify the capture host's own interfaces and the gateway so
        their traffic is exempt from attacker-shaped detections."""
        with self._lock:
            for mac in (local_macs or []):
                m = _norm_mac(mac)
                if m:
                    self._ignored_macs.add(m)
                    self._known_macs.add(m)
            gm = _norm_mac(gateway_mac)
            if gm:
                self._ignored_macs.add(gm)
                self._known_macs.add(gm)

    def _seed_known_macs(self) -> None:
        from database.queries.device_queries import get_all_devices
        for d in get_all_devices(limit=2000, hours=24 * 365):
            mac = _norm_mac(d.get("mac_address"))
            if mac and not _is_excluded_mac(mac):
                self._known_macs.add(mac)

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "running": bool(self._thread and self._thread.is_alive()),
                "known_macs": len(self._known_macs),
                "threats_found": self.threats_found,
                "flows_seen": self.flows_seen,
                "dns_seen": self.dns_seen,
            }

    # ------------------------------------------------------------------ #
    #  Ingestion
    # ------------------------------------------------------------------ #

    def ingest_flow(self, flow: dict) -> None:
        src = _norm_mac(flow.get("source_mac"))
        if _is_excluded_mac(src) or flow.get("is_control"):
            return
        if src in self._ignored_macs:
            # Self/gateway traffic: our own discovery sweeps and forwarded/
            # return traffic would otherwise read as port scans from the
            # network's most trusted MACs.
            return
        dst_ip = flow.get("dest_ip") or ""
        dst_port = flow.get("dest_port")
        if not dst_ip or dst_ip.startswith(("224.", "239.", "255.")):
            return
        now = self._now()
        with self._lock:
            self.flows_seen += 1
            self._check_rogue_device(src, flow)
            if isinstance(dst_port, int) and dst_port > 0:
                self._check_port_scan(now, src, dst_ip, dst_port)
                self._check_beaconing(now, src, dst_ip, dst_port, flow)
                self._check_lateral(now, src, dst_ip, dst_port)

    def ingest_dns(self, dns_event: dict) -> None:
        src = _norm_mac(dns_event.get("source_mac"))
        qname = (dns_event.get("qname") or "").rstrip(".")
        if _is_excluded_mac(src) or not qname:
            return
        now = self._now()
        with self._lock:
            self.dns_seen += 1
            self._check_dns_tunneling(now, src, qname)

    # ------------------------------------------------------------------ #
    #  Detectors (caller holds the lock)
    # ------------------------------------------------------------------ #

    def _check_port_scan(self, now: float, src: str, dst_ip: str,
                         dst_port: int) -> None:
        win = self._scan.get(src)
        if win is None:
            if len(self._scan) >= _MAX_TRACKED_KEYS:
                return
            win = self._scan[src] = _SlidingWindow(self._portscan_window)
        win.add(now, (dst_ip, dst_port))

        pairs = win.values()
        ports_by_host: Dict[str, Set[int]] = {}
        hosts_by_port: Dict[int, Set[str]] = {}
        for ip, port in pairs:
            # Vertical: ephemeral destination ports are response traffic to
            # a client's many outbound connections, not probed services.
            if port < _EPHEMERAL_PORT_START:
                ports_by_host.setdefault(ip, set()).add(port)
            # Horizontal: fanning out to many *external* hosts on one port
            # is just browsing (CDNs); only an internal sweep is a scan.
            if is_private_ip(ip):
                hosts_by_port.setdefault(port, set()).add(ip)

        if not ports_by_host and not hosts_by_port:
            return

        host, ports = (max(ports_by_host.items(), key=lambda kv: len(kv[1]))
                       if ports_by_host else ("", set()))
        if len(ports) >= self._portscan_port_threshold:
            self._raise(
                "port_scan", src, key=(src, host),
                severity="critical",
                message=(
                    f"Port scan: {src} probed {len(ports)} distinct ports "
                    f"on {host} within {int(self._portscan_window)}s."
                ),
                evidence=[{
                    "signal": "vertical_scan", "target": host,
                    "distinct_ports": len(ports),
                    "sample_ports": sorted(ports)[:20],
                    "window_seconds": self._portscan_window,
                }],
                confidence=min(1.0, len(ports) / (2 * self._portscan_port_threshold) + 0.5),
            )
            return

        if not hosts_by_port:
            return
        port, hosts = max(hosts_by_port.items(), key=lambda kv: len(kv[1]))
        if len(hosts) >= self._portscan_host_threshold:
            self._raise(
                "port_scan", src, key=(src, port),
                severity="critical",
                message=(
                    f"Network sweep: {src} probed port {port} on "
                    f"{len(hosts)} hosts within {int(self._portscan_window)}s."
                ),
                evidence=[{
                    "signal": "horizontal_scan", "port": port,
                    "distinct_hosts": len(hosts),
                    "sample_hosts": sorted(hosts)[:20],
                    "window_seconds": self._portscan_window,
                }],
                confidence=min(1.0, len(hosts) / (2 * self._portscan_host_threshold) + 0.5),
            )

    def _check_beaconing(self, now: float, src: str, dst_ip: str,
                         dst_port: int, flow: dict) -> None:
        # Heartbeats to internal infrastructure (gateway DNS, printers…)
        # are normal; C2 beacons call out.
        if is_private_ip(dst_ip):
            return
        key = (src, dst_ip, dst_port)
        times = self._beacons.get(key)
        if times is None:
            if len(self._beacons) >= _MAX_TRACKED_KEYS:
                return
            times = self._beacons[key] = deque(maxlen=_BEACON_HISTORY)
        times.append(now)
        if len(times) < self._beacon_min_obs + 1:
            return
        intervals = [b - a for a, b in zip(times, list(times)[1:])]
        mean = sum(intervals) / len(intervals)
        if not (_BEACON_MIN_INTERVAL <= mean <= _BEACON_MAX_INTERVAL):
            return
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        jitter = math.sqrt(variance) / mean if mean else 1.0
        # Instagram/WhatsApp/push-notification keepalives heartbeat on the
        # common ports with a few percent of jitter — on those ports only a
        # machine-regular interval is suspicious enough to call C2.
        max_jitter = (min(self._beacon_max_jitter, _BEACON_COMMON_PORT_MAX_JITTER)
                      if dst_port in _BEACON_COMMON_PORTS
                      else self._beacon_max_jitter)
        if jitter <= max_jitter:
            self._raise(
                "beaconing", src, key=key,
                severity="warning",
                message=(
                    f"Beaconing: {src} contacts {dst_ip}:{dst_port} every "
                    f"~{mean:.0f}s with {jitter:.0%} jitter "
                    f"({len(intervals)} intervals observed)."
                ),
                evidence=[{
                    "signal": "regular_interval", "destination": dst_ip,
                    "port": dst_port, "mean_interval_seconds": round(mean, 1),
                    "jitter_ratio": round(jitter, 3),
                    "observations": len(times),
                    "protocol": flow.get("protocol"),
                }],
                confidence=min(1.0, 0.6 + (self._beacon_max_jitter - jitter)),
            )

    def _check_dns_tunneling(self, now: float, src: str, qname: str) -> None:
        # Reverse-DNS lookups (PTR) have legitimately long qnames — an
        # IPv6 address spelled nibble-by-nibble under ip6.arpa is ~72
        # chars.  The OS resolver emits bursts of these; never treat the
        # .arpa zone as tunneling.
        if qname.lower().rstrip(".").endswith(".arpa"):
            return
        domain = _registered_domain(qname)
        if not domain:
            return
        # Carrier VoWiFi/IMS (epdg.epc.mncNNN.mccNNN.pub.3gppnetwork.org) and a
        # few other infra domains legitimately emit bursts of long, high-entropy
        # subdomains — they are not tunneling. Real phone on the hotspot tripped
        # this (3gppnetwork.org).
        if domain in _BENIGN_LONG_QNAME_DOMAINS:
            return
        key = (src, domain)
        win = self._dns.get(key)
        if win is None:
            if len(self._dns) >= _MAX_TRACKED_KEYS:
                return
            win = self._dns[key] = _SlidingWindow(self._dns_window)
        win.add(now, qname)
        if len(win) < self._dns_query_threshold:
            return
        qnames = [str(q) for q in win.values()]
        # Only the labels *below* the registered domain can carry data.
        subs = [q[: -(len(domain) + 1)] if q.endswith("." + domain) else ""
                for q in qnames]
        avg_len = sum(len(q) for q in qnames) / len(qnames)
        avg_entropy = (
            sum(_shannon_entropy(s) for s in subs if s)
            / max(1, sum(1 for s in subs if s))
        )
        if avg_len >= self._dns_qname_length or avg_entropy >= self._dns_entropy:
            self._raise(
                "dns_tunneling", src, key=key,
                severity="critical",
                message=(
                    f"Possible DNS tunneling: {src} sent {len(qnames)} queries "
                    f"to '{domain}' in {int(self._dns_window)}s "
                    f"(avg qname {avg_len:.0f} chars, entropy {avg_entropy:.2f})."
                ),
                evidence=[{
                    "signal": "qname_stuffing", "domain": domain,
                    "queries_in_window": len(qnames),
                    "avg_qname_length": round(avg_len, 1),
                    "avg_subdomain_entropy": round(avg_entropy, 2),
                    "sample_qnames": qnames[:5],
                    "window_seconds": self._dns_window,
                }],
                confidence=min(1.0, 0.55 + avg_entropy / 10 + avg_len / 200),
            )

    def _check_rogue_device(self, src: str, flow: dict) -> None:
        if src in self._known_macs:
            return
        self._known_macs.add(src)
        # First flow ever from this MAC.  Local sources only — an external
        # MAC is just the upstream router.
        src_ip = flow.get("source_ip") or ""
        if src_ip and not is_private_ip(src_ip):
            return
        # W4: a recognized consumer device (phone/laptop by OUI) joining is
        # expected — especially on a hotspot, where every client is "new".
        # Keep the visibility but drop the severity so it doesn't read as an
        # intruder and doesn't open a warning-level incident.
        vendor = _oui_vendor(src)
        known = _is_known_consumer_vendor(vendor)
        self._raise(
            "rogue_device", src, key=src,
            severity="info" if known else "warning",
            message=(
                (f"New device joined: {vendor} device {src}"
                 f"{f' ({src_ip})' if src_ip else ''}."
                 if known else
                 f"Unrecognized device joined the network: {src}"
                 f"{f' ({src_ip})' if src_ip else ''} has no history here.")
            ),
            evidence=[{
                "signal": "never_seen_mac", "mac": src, "ip": src_ip,
                "vendor": vendor,
                "first_flow_protocol": flow.get("protocol"),
                "first_flow_destination": flow.get("dest_ip"),
            }],
            confidence=0.3 if known else 0.5,
        )

    def _check_lateral(self, now: float, src: str, dst_ip: str,
                       dst_port: int) -> None:
        if dst_port not in LATERAL_PORTS or not is_private_ip(dst_ip):
            return
        win = self._lateral.get(src)
        if win is None:
            if len(self._lateral) >= _MAX_TRACKED_KEYS:
                return
            win = self._lateral[src] = _SlidingWindow(self._lateral_window)
        win.add(now, (dst_ip, dst_port))
        hosts = {ip for ip, _ in win.values()}
        if len(hosts) >= self._lateral_host_threshold:
            ports = sorted({p for _, p in win.values()})
            self._raise(
                "lateral_movement", src, key=(src, "lateral"),
                severity="critical",
                message=(
                    f"Lateral movement: {src} connected to {len(hosts)} "
                    f"internal hosts on admin ports {ports} within "
                    f"{int(self._lateral_window)}s."
                ),
                evidence=[{
                    "signal": "admin_port_fanout",
                    "distinct_hosts": len(hosts),
                    "hosts": sorted(hosts)[:20], "ports": ports,
                    "window_seconds": self._lateral_window,
                }],
                confidence=min(1.0, 0.6 + len(hosts) * 0.1),
            )

    # ------------------------------------------------------------------ #
    #  Alerting
    # ------------------------------------------------------------------ #

    def _raise(self, threat_type: str, mac: str, key, severity: str,
               message: str, evidence: List[dict], confidence: float) -> None:
        dedup = (threat_type, key)
        if dedup in self._alerted:
            return
        self._alerted.add(dedup)
        self.threats_found += 1
        logger.warning("THREAT [%s] %s", threat_type, message)
        if self._alert_engine is None:
            return
        try:
            self._alert_engine.create_threat_alert(
                threat_type=threat_type,
                mac=mac,
                message=message,
                evidence=evidence,
                confidence=round(min(1.0, max(0.0, confidence)), 4),
                severity=severity,
            )
        except Exception as exc:
            logger.error("Threat alert creation failed: %s", exc)
