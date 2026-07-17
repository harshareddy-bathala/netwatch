"""
vpn_detector.py - VPN / Encrypted-Tunnel Detection & Classification (W3)
========================================================================

Passive capture cannot see *inside* a VPN tunnel — that is a cryptographic
limit, not a NetWatch gap. It can reliably **detect and classify** one:
which device is tunneling, over what protocol, to which provider, and how
much/how long. That is honest and useful ("Nothing-Phone: VPN active
(WireGuard → Proton, 120 MB, 42 min)"); we never claim to show the sites
inside.

Event-bus consumer over ``flow.completed`` (mirrors
``intelligence.threats.ThreatDetector``). Two signals:

* **Protocol signature** — a flow to a classic VPN port (WireGuard 51820,
  OpenVPN 1194, IPsec/IKE 500/4500, L2TP 1701). High confidence.
* **Tunnel-shape heuristic** — sustained high-volume traffic to a single
  external peer whose owner is a known VPN provider (covers WireGuard-on-443
  and commercial "stealth" endpoints). The offline IP→org map classifies the
  provider.

Alerts go through ``AlertEngine.create_vpn_alert`` (category ``connection``,
low severity, deduped per device) and never fuse into security incidents.
"""

import logging
import threading
import time
from typing import Callable, Dict, Optional, Set, Tuple

from intelligence.event_bus import event_bus as _default_bus

try:
    from utils.network_utils import is_private_ip
except ImportError:      # isolated tests
    def is_private_ip(ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172.16.", "169.254."))

logger = logging.getLogger(__name__)

try:
    from config import (
        VPN_MIN_TUNNEL_BYTES, VPN_WINDOW_SECONDS, VPN_MIN_TUNNEL_SECONDS,
    )
except ImportError:
    VPN_MIN_TUNNEL_BYTES = 2_000_000
    VPN_WINDOW_SECONDS = 600
    VPN_MIN_TUNNEL_SECONDS = 120

# Classic VPN protocol ports → protocol label.
_VPN_PORTS = {
    51820: "WireGuard",
    1194: "OpenVPN",
    500: "IPsec/IKE",
    4500: "IPsec/IKE",
    1701: "L2TP/IPsec",
}

_EXCLUDED_MAC_PREFIXES = ("ff:ff:ff", "01:00:5e", "33:33", "01:80:c2")
_MAX_TRACKED = 5000


def _norm_mac(mac: Optional[str]) -> str:
    return (mac or "").lower().replace("-", ":").strip()


def _is_excluded_mac(mac: str) -> bool:
    return not mac or mac.startswith(_EXCLUDED_MAC_PREFIXES)


def _is_carrier_org(org) -> bool:
    """True for a mobile-carrier peer (VoWiFi ePDG), not a consumer VPN."""
    if not org:
        return False
    o = org.lower()
    return "carrier" in o or "mobile" in o or "3gpp" in o


def _fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def _fmt_duration(seconds: float) -> str:
    m = int(seconds // 60)
    if m < 1:
        return f"{int(seconds)}s"
    if m < 60:
        return f"{m} min"
    return f"{m // 60}h {m % 60}m"


class _Tunnel:
    __slots__ = ("first_seen", "last_seen", "bytes", "protocol", "org")

    def __init__(self, now: float, protocol: str, org: Optional[str]):
        self.first_seen = now
        self.last_seen = now
        self.bytes = 0
        self.protocol = protocol
        self.org = org


class VpnDetector:
    """Event-bus consumer that flags and classifies VPN tunnels."""

    def __init__(self, alert_engine=None,
                 shutdown_event: Optional[threading.Event] = None,
                 bus=None, now_fn: Callable[[], float] = time.time,
                 min_bytes: int = VPN_MIN_TUNNEL_BYTES,
                 window: int = VPN_WINDOW_SECONDS,
                 min_seconds: int = VPN_MIN_TUNNEL_SECONDS):
        self._alert_engine = alert_engine
        self._bus = bus or _default_bus
        self._shutdown_event = shutdown_event or threading.Event()
        self._now = now_fn
        self._min_bytes = min_bytes
        self._window = window
        self._min_seconds = min_seconds

        self._lock = threading.Lock()
        # (mac, dst_ip) -> _Tunnel
        self._tunnels: Dict[Tuple[str, str], _Tunnel] = {}
        self._ignored_macs: Set[str] = set()
        self._alerted: Set[str] = set()         # per-device dedup

        self._thread: Optional[threading.Thread] = None
        self._sub = None

        # Public state for the per-device badge (mac -> dict)
        self.active_vpns: Dict[str, dict] = {}
        self.flows_seen = 0
        self.vpns_found = 0

    # ------------------------------------------------------------------ #

    def set_context(self, local_macs=None, gateway_mac: str = "") -> None:
        with self._lock:
            for m in (local_macs or []):
                nm = _norm_mac(m)
                if nm:
                    self._ignored_macs.add(nm)
            gm = _norm_mac(gateway_mac)
            if gm:
                self._ignored_macs.add(gm)

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        self._sub = self._bus.subscribe(["flow.completed"], name="vpn-detector")
        self._thread = threading.Thread(target=self._run, name="VpnDetector",
                                        daemon=True)
        self._thread.start()
        logger.info("VpnDetector started (protocol signatures + tunnel-shape heuristic)")
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
            except Exception as exc:
                logger.error("VpnDetector ingest error: %s", exc)
        logger.info("VpnDetector thread exited")

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "running": bool(self._thread and self._thread.is_alive()),
                "flows_seen": self.flows_seen,
                "vpns_found": self.vpns_found,
                "active_devices": len(self.active_vpns),
            }

    def get_device_vpn(self, mac: str) -> Optional[dict]:
        return self.active_vpns.get(_norm_mac(mac))

    # ------------------------------------------------------------------ #

    def ingest_flow(self, flow: dict) -> None:
        src = _norm_mac(flow.get("source_mac"))
        if _is_excluded_mac(src) or flow.get("is_control"):
            return
        if src in self._ignored_macs:
            return
        dst_ip = flow.get("dest_ip") or ""
        if not dst_ip or is_private_ip(dst_ip):
            return                      # tunnels terminate on an external peer
        dst_port = flow.get("dest_port")
        now = self._now()

        # Classify provider from the destination IP (offline map).
        try:
            from intelligence.ip_org import lookup_org, is_vpn_org
            org = lookup_org(dst_ip)
        except Exception:
            org = None
            is_vpn_org = lambda o: False   # noqa: E731

        proto_label = _VPN_PORTS.get(dst_port) if isinstance(dst_port, int) else None

        with self._lock:
            self.flows_seen += 1
            key = (src, dst_ip)
            tun = self._tunnels.get(key)
            if tun is None:
                if len(self._tunnels) >= _MAX_TRACKED:
                    return
                tun = self._tunnels[key] = _Tunnel(now, proto_label or "", org)
            # accumulate
            tun.last_seen = now
            tun.bytes += int(flow.get("bytes_total") or 0)
            if proto_label and not tun.protocol:
                tun.protocol = proto_label
            if org and not tun.org:
                tun.org = org

            # window prune
            if now - tun.first_seen > self._window:
                tun.first_seen = now - self._window

            duration = tun.last_seen - tun.first_seen

            # WireGuard/OpenVPN ports are unambiguous VPNs. IPsec/IKE and L2TP
            # (500/4500/1701) are ALSO what carrier VoWiFi / Wi-Fi-calling use to
            # the ePDG (3gppnetwork.org) — a phone with Wi-Fi calling would
            # otherwise always read as "VPN". For those ports require the peer to
            # be a real VPN provider (not a mobile carrier) before flagging.
            unambiguous = proto_label in ("WireGuard", "OpenVPN")
            ambiguous = proto_label in ("IPsec/IKE", "L2TP/IPsec")
            carrier = _is_carrier_org(tun.org)
            is_signature = unambiguous or (ambiguous and is_vpn_org(tun.org) and not carrier)
            is_heuristic = (
                tun.bytes >= self._min_bytes
                and duration >= self._min_seconds
                and is_vpn_org(tun.org)
                and not carrier
            )
            if is_signature or is_heuristic:
                self._report(src, dst_ip, tun, duration, is_signature)

    def _report(self, mac: str, dst_ip: str, tun: _Tunnel,
                duration: float, is_signature: bool) -> None:
        provider = tun.org or "unknown provider"
        protocol = tun.protocol or "encrypted tunnel"
        badge = {
            "mac": mac, "provider": provider, "protocol": protocol,
            "dest_ip": dst_ip, "bytes": tun.bytes,
            "duration_seconds": round(duration, 1),
            "since": tun.first_seen,
        }
        self.active_vpns[mac] = badge

        if mac in self._alerted:
            return
        self._alerted.add(mac)
        self.vpns_found += 1
        confidence = 0.9 if is_signature else (0.8 if tun.org else 0.6)
        message = (
            f"VPN active ({protocol}"
            f"{f' → {tun.org}' if tun.org else ''}, "
            f"{_fmt_bytes(tun.bytes)}, {_fmt_duration(duration)}). "
            f"Site-level detail is unavailable inside the tunnel."
        )
        logger.info("VPN [%s] %s", mac, message)
        if self._alert_engine is None:
            return
        try:
            self._alert_engine.create_vpn_alert(
                mac=mac, message=message,
                evidence=[{
                    "signal": "protocol_signature" if is_signature else "tunnel_shape",
                    "protocol": protocol, "provider": tun.org,
                    "destination": dst_ip,
                    "bytes": tun.bytes,
                    "duration_seconds": round(duration, 1),
                }],
                confidence=confidence,
            )
        except Exception as exc:
            logger.error("VPN alert creation failed: %s", exc)
