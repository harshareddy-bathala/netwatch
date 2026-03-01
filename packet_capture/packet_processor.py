"""
packet_processor.py - Mode-Aware Packet Processing
====================================================

Parses raw Scapy packets and produces structured ``PacketData`` objects
with **correct direction detection** based on the active network mode.

Key design decisions
--------------------
* **Direction is determined by the mode, not by "private IP" heuristics.**
  Hotspot mode: FROM a client IP → upload; TO a client IP → download.
  WiFi client / public: FROM our IP → upload; TO our IP → download.
  Ethernet: same as client (our perspective).
  Port mirror: best-effort based on known local IPs.

* **Packet size uses ``len(pkt[IP])``**, which gives the IP datagram size
  (header + payload) and excludes the 14-byte Ethernet header.  The old
  code used ``len(pkt)`` which inflated every measurement by the L2 frame.

* Protocol detection delegates to ``protocols.detect_protocol()`` (which
  already works well) — no need to reinvent it.
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Scapy imports with graceful fallback
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, ARP, DNS, DNSQR, DNSRR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = IPv6 = TCP = UDP = ICMP = Ether = ARP = DNS = DNSQR = DNSRR = Raw = None

# Optional: DHCP layer for Option 12 hostname extraction
try:
    from scapy.all import DHCP as _DHCP, BOOTP as _BOOTP
    _DHCP_AVAILABLE = True
except ImportError:
    _DHCP = _BOOTP = None
    _DHCP_AVAILABLE = False

# Project imports
import os, sys
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from packet_capture.protocols import detect_protocol
from packet_capture.modes.base_mode import BaseMode, ModeName, NetworkScope


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PacketData:
    """
    Structured representation of a parsed packet.

    Every field is populated by ``PacketProcessor.process()``.  This
    replaces the loose ``dict`` returned by the old ``parse_packet()``.
    """
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: str = "UNKNOWN"
    raw_protocol: str = "UNKNOWN"
    bytes: int = 0
    direction: str = "other"         # 'upload', 'download', or 'other'
    source_mac: Optional[str] = None
    dest_mac: Optional[str] = None
    ip_version: int = 4
    ttl: Optional[int] = None
    flags: Optional[str] = None
    device_name: Optional[str] = None
    vendor: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dict compatible with ``save_packet()`` / ``save_packets_batch()``."""
        d = {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "raw_protocol": self.raw_protocol,
            "bytes": self.bytes,
            "direction": self.direction,
            "source_mac": self.source_mac,
            "dest_mac": self.dest_mac,
            "device_name": self.device_name,
            "vendor": self.vendor,
        }
        return d


# =============================================================================
# PACKET PROCESSOR
# =============================================================================

class PacketProcessor:
    """
    Stateless packet processor that is **mode-aware**.

    Constructed once with the active ``BaseMode`` and optionally the set of
    known local IPs.  Call ``process(pkt)`` for each raw Scapy packet.

    Usage::

        proc = PacketProcessor(mode)
        pkt_data = proc.process(raw_scapy_packet)
        if pkt_data:
            print(pkt_data.direction, pkt_data.bytes)
    """

    def __init__(self, mode: BaseMode, local_ips: Optional[Set[str]] = None):
        self._mode = mode
        self._mode_name = mode.get_mode_name()
        self._scope = mode.get_scope()

        # Our own IP (the interface the capture runs on)
        self._our_ip: Optional[str] = mode.interface.ip_address

        # Our own MAC (from interface detection — used as fallback when
        # the Ether layer is missing, which happens on some Windows WiFi
        # captures via Npcap)
        self._our_mac: Optional[str] = mode.interface.mac_address

        # For hotspot mode: the monitored subnet
        self._monitored_subnet: Optional[ipaddress.IPv4Network] = None
        ip_range = mode.get_valid_ip_range()
        if ip_range:
            try:
                self._monitored_subnet = ipaddress.IPv4Network(ip_range, strict=False)
            except (ValueError, TypeError):
                pass

        # Additional known local IPs (e.g. from ARP scan)
        self._local_ips: Set[str] = local_ips or set()
        if self._our_ip:
            self._local_ips.add(self._our_ip)

        # Phase 5: For port mirror / ALL_TRAFFIC scope, populate _local_ips
        # with all local interface IPs so direction detection works correctly
        # even for traffic involving interfaces other than the capture one.
        if self._scope == NetworkScope.ALL_TRAFFIC:
            self._populate_all_local_ips()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def process(self, packet) -> Optional[PacketData]:
        """
        Parse a raw Scapy packet into a ``PacketData`` object.

        Returns ``None`` for non-IP packets or on any parsing error.
        """
        if not SCAPY_AVAILABLE or packet is None:
            return None

        try:
            # --- Extract IPs ------------------------------------------------
            src_ip, dst_ip, ip_version = self._extract_ip(packet)
            if src_ip is None:
                # ARP packets — still useful for device discovery
                if packet.haslayer(ARP):
                    return self._process_arp(packet)
                return None

            # --- MAC addresses (extracted early for direction detection) ------
            src_mac = dst_mac = None
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

            # --- Packet size (IP layer only, excludes Ethernet header) ------
            pkt_bytes = self._get_ip_layer_size(packet)

            # --- Transport info ---------------------------------------------
            src_port, dst_port = self._extract_ports(packet)
            raw_proto = self._get_raw_protocol(packet)
            app_proto = detect_protocol(src_port, dst_port, raw_proto)

            # --- Direction (mode-aware, with MAC fallback for IPv6) ---------
            direction = self._determine_direction(
                src_ip, dst_ip, src_mac=src_mac, dst_mac=dst_mac,
            )

            # Fallback: enrich with our known MAC when Ether layer is
            # missing (Windows WiFi/Npcap) or when the captured MAC is
            # a broadcast/multicast that would be filtered out later.
            # In WiFi-client mode every packet involves our IP, so we
            # know exactly which side is "us".
            if self._our_mac:
                if direction == "upload" or src_ip == self._our_ip:
                    if not src_mac or src_mac == 'ff:ff:ff:ff:ff:ff':
                        src_mac = self._our_mac
                if direction == "download" or dst_ip == self._our_ip:
                    if not dst_mac or dst_mac == 'ff:ff:ff:ff:ff:ff':
                        dst_mac = self._our_mac

            # --- TTL --------------------------------------------------------
            ttl = None
            if packet.haslayer(IP):
                ttl = packet[IP].ttl
            elif packet.haslayer(IPv6):
                ttl = packet[IPv6].hlim

            # --- TCP flags --------------------------------------------------
            flags = None
            if packet.haslayer(TCP):
                flags = self._get_tcp_flags(packet)

            # --- Extra fields -----------------------------------------------
            extra: Dict[str, Any] = {}
            if packet.haslayer(DNS):
                extra["dns"] = True
            # Note: TCP seq/ack intentionally not stored — never persisted,
            # saves ~100 bytes per packet in memory.

            # --- Passive hostname extraction (mDNS, NetBIOS, DNS) -----------
            device_name = self._extract_hostname_from_packet(packet, app_proto, src_ip)

            # Phase 3: use capture-time timestamp stamped by the capture
            # thread (via _capture_ts) instead of datetime.now() so that
            # bandwidth bucketing reflects the real capture instant.
            if hasattr(packet, '_capture_ts') and packet._capture_ts:
                import time as _time_mod
                _ts = datetime.fromtimestamp(packet._capture_ts)
            else:
                _ts = datetime.now()

            return PacketData(
                timestamp=_ts,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=src_port,
                dest_port=dst_port,
                protocol=app_proto,
                raw_protocol=raw_proto,
                bytes=pkt_bytes,
                direction=direction,
                source_mac=src_mac,
                dest_mac=dst_mac,
                ip_version=ip_version,
                ttl=ttl,
                flags=flags,
                device_name=device_name,
                extra=extra,
            )

        except Exception as exc:
            logger.debug("Error processing packet: %s", exc)
            return None

    def process_batch(self, packets: list) -> List[PacketData]:
        """Process a list of raw packets; skip any that fail."""
        results: List[PacketData] = []
        for pkt in packets:
            pd = self.process(pkt)
            if pd is not None:
                results.append(pd)
        return results

    # ------------------------------------------------------------------ #
    #  Direction detection (the key Phase 2 fix)
    # ------------------------------------------------------------------ #

    def _determine_direction(
        self, src_ip: str, dst_ip: str,
        src_mac: Optional[str] = None, dst_mac: Optional[str] = None,
    ) -> str:
        """
        Determine whether the packet is *upload*, *download*, or *other*
        based on the active mode.

        **Hotspot mode** (scope = CONNECTED_CLIENTS):
            We are the gateway.  Traffic FROM a client IP heading to the
            Internet = upload (from the client's perspective, which is
            what the dashboard shows).  Traffic TO a client IP = download.

        **WiFi client / Public / Ethernet** (scope = OWN_TRAFFIC_ONLY
            or LOCAL_NETWORK):
            Traffic FROM our IP = upload.  Traffic TO our IP = download.

        **Port mirror** (scope = ALL_TRAFFIC):
            If we can identify local IPs we do our best; otherwise 'other'.

        **MAC-based fallback (all scopes):**
            When IP-based detection returns 'other' (common for IPv6 traffic
            where ``self._our_ip`` is an IPv4 address), fall back to MAC
            address comparison.  If the source MAC is ours → upload; if the
            destination MAC is ours → download.
        """
        result = self._determine_direction_by_ip(src_ip, dst_ip)
        if result != "other":
            return result

        # ---- MAC-based fallback (critical for IPv6 traffic) ----
        # When IPv6 IPs don't match the monitored IPv4 subnet, fall back to
        # MAC-address comparison to determine direction.
        #
        # IMPORTANT: the semantics differ by scope:
        #
        #   CONNECTED_CLIENTS (hotspot/gateway mode) — "our MAC" is the
        #   *gateway* adapter.  When Windows ICS forwards a download packet
        #   to a client, the Ethernet frame has src_mac=gateway (our_mac).
        #   So src_mac==our_mac means WE (gateway) forwarded it → DOWNLOAD.
        #   When a client sends to/through the gateway, dst_mac==our_mac → UPLOAD.
        #
        #   All other modes — "our MAC" is the end-device.
        #   src_mac==our_mac means WE sent it → UPLOAD.
        #   dst_mac==our_mac means WE received it → DOWNLOAD.
        if self._our_mac:
            our_mac_lower = self._our_mac.lower()
            if self._scope == NetworkScope.CONNECTED_CLIENTS:
                if src_mac and src_mac.lower() == our_mac_lower:
                    return "download"   # gateway forwarding to client
                if dst_mac and dst_mac.lower() == our_mac_lower:
                    return "upload"     # client sending through gateway
            else:
                if src_mac and src_mac.lower() == our_mac_lower:
                    return "upload"
                if dst_mac and dst_mac.lower() == our_mac_lower:
                    return "download"

        return "other"

    def _determine_direction_by_ip(self, src_ip: str, dst_ip: str) -> str:
        """IP-based direction detection (original logic, extracted for clarity)."""
        if self._scope == NetworkScope.CONNECTED_CLIENTS:
            # Hotspot mode — perspective is the client
            if self._is_in_monitored_subnet(src_ip) and src_ip != self._our_ip:
                # Client → Internet (through us) = upload
                return "upload"
            if self._is_in_monitored_subnet(dst_ip) and dst_ip != self._our_ip:
                # Internet → Client (through us) = download
                return "download"
            return "other"

        if self._scope in (NetworkScope.OWN_TRAFFIC_ONLY, NetworkScope.LOCAL_NETWORK):
            if src_ip == self._our_ip:
                return "upload"
            if dst_ip == self._our_ip:
                return "download"
            return "other"

        if self._scope == NetworkScope.ALL_TRAFFIC:
            # Port mirror: best-effort using known local IPs
            src_local = src_ip in self._local_ips or self._is_in_monitored_subnet(src_ip)
            dst_local = dst_ip in self._local_ips or self._is_in_monitored_subnet(dst_ip)
            if src_local and not dst_local:
                return "upload"
            if dst_local and not src_local:
                return "download"
            # Phase D: If _local_ips is empty (psutil unavailable or no
            # interfaces detected) and subnet-based checks both returned
            # False, fall back to RFC-1918 private-address heuristic
            # instead of classifying everything as "other".
            if not self._local_ips and not self._monitored_subnet:
                src_priv = self._is_private_ip(src_ip)
                dst_priv = self._is_private_ip(dst_ip)
                if src_priv and not dst_priv:
                    return "upload"
                if dst_priv and not src_priv:
                    return "download"
            return "other"

        return "other"

    def _is_in_monitored_subnet(self, ip: str) -> bool:
        """Check whether *ip* falls inside the mode's monitored subnet."""
        if not self._monitored_subnet:
            return False
        try:
            return ipaddress.IPv4Address(ip) in self._monitored_subnet
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if *ip* is an RFC-1918 private address.

        Phase D: Used as a last-resort heuristic for port-mirror direction
        detection when ``_local_ips`` is empty and no monitored subnet is
        configured.  Private → local, public → remote.
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except (ValueError, TypeError):
            return False

    def _populate_all_local_ips(self) -> None:
        """Populate ``_local_ips`` with all local interface IPs.

        Phase 5: Called for Port Mirror / ALL_TRAFFIC scope so that
        direction detection can correctly classify traffic as upload
        or download for any local host.
        """
        try:
            import psutil
            for _name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name in ('AF_INET', 'AF_INET6'):
                        ip = addr.address
                        if ip and ip not in ('0.0.0.0', '127.0.0.1', '::1'):
                            self._local_ips.add(ip)
        except ImportError:
            pass
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Low-level extraction helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_ip(packet):
        """Return (src_ip, dst_ip, version) or (None, None, None)."""
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst, 4
        if packet.haslayer(IPv6):
            return packet[IPv6].src, packet[IPv6].dst, 6
        return None, None, None

    @staticmethod
    def _get_ip_layer_size(packet) -> int:
        """
        Return the IP-layer size (IP header + payload), excluding Ethernet.

        **Why ``len(pkt[IP])`` and not ``len(pkt)``?**
        ``len(pkt)`` includes the 14-byte Ethernet header (and any 802.1Q
        tags), which inflates every packet's reported size.  Network
        bandwidth is measured at L3 (IP), so we use ``len(pkt[IP])``.
        For IPv6, use ``len(pkt[IPv6])``.
        """
        try:
            if packet.haslayer(IP):
                return len(packet[IP])
            if packet.haslayer(IPv6):
                return len(packet[IPv6])
        except Exception:
            pass
        # Fallback for non-IP packets (ARP etc.)
        try:
            return len(packet)
        except Exception:
            return 0

    @staticmethod
    def _extract_ports(packet):
        """Return (src_port, dst_port) or (None, None)."""
        if packet.haslayer(TCP):
            return packet[TCP].sport, packet[TCP].dport
        if packet.haslayer(UDP):
            return packet[UDP].sport, packet[UDP].dport
        return None, None

    @staticmethod
    def _get_raw_protocol(packet) -> str:
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(IP):
            proto_num = packet[IP].proto
            proto_map = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
                         47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF"}
            return proto_map.get(proto_num, f"PROTO-{proto_num}")
        return "UNKNOWN"

    @staticmethod
    def _get_tcp_flags(packet) -> Optional[str]:
        if not packet.haslayer(TCP):
            return None
        try:
            f = packet[TCP].flags
            names = []
            if f.F: names.append("FIN")
            if f.S: names.append("SYN")
            if f.R: names.append("RST")
            if f.P: names.append("PSH")
            if f.A: names.append("ACK")
            if f.U: names.append("URG")
            return ",".join(names) if names else "NONE"
        except Exception:
            return None

    @staticmethod
    def _process_arp(packet) -> Optional[PacketData]:
        """Create a minimal PacketData for ARP packets."""
        try:
            return PacketData(
                timestamp=datetime.now(),
                source_ip=packet[ARP].psrc,
                dest_ip=packet[ARP].pdst,
                protocol="ARP",
                raw_protocol="ARP",
                bytes=len(packet),
                direction="other",
                source_mac=packet[Ether].src if packet.haslayer(Ether) else None,
                dest_mac=packet[Ether].dst if packet.haslayer(Ether) else None,
                extra={"arp_op": packet[ARP].op},
            )
        except Exception:
            return None

    @staticmethod
    def _extract_hostname_from_packet(
        packet, app_proto: str, src_ip: str,
    ) -> Optional[str]:
        """
        Extract a hostname from mDNS, NetBIOS-NS, LLMNR, DNS, DHCP,
        SSDP/UPnP, or HTTP packets.

        This enables **passive** hostname learning — no active probing
        needed.  When a device announces its name (mDNS, DHCP Option 12)
        or responds to a name query (DNS / LLMNR / NetBIOS-NS), we
        capture that name and feed it to the hostname resolver's cache.

        Sources (Phase 2 expansion):
        - mDNS/LLMNR PTR and A/AAAA responses
        - DNS A/AAAA query names (the queried name itself is useful)
        - DHCP Option 12 (hostname)
        - SSDP/UPnP NOTIFY and M-SEARCH responses (friendly name)
        - HTTP Host headers

        Returns the hostname string or ``None``.
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            # --- DHCP Option 12 (hostname) ---
            result = PacketProcessor._extract_dhcp_hostname(packet)
            if result:
                return result

            # --- SSDP / UPnP friendly name ---
            result = PacketProcessor._extract_ssdp_hostname(packet)
            if result:
                return result

            # --- HTTP Host header (for device identification) ---
            result = PacketProcessor._extract_http_host(packet, src_ip)
            if result:
                return result

            # --- DNS-based extraction (mDNS, LLMNR, DNS queries + responses) ---
            if not packet.haslayer(DNS):
                return None

            dns_layer = packet[DNS]
            proto_upper = app_proto.upper() if app_proto else ""

            # DNS QUERIES (QR=0): extract the queried name itself
            # A device querying for "myphone.local" is likely named "myphone"
            if dns_layer.qr == 0 and dns_layer.qdcount > 0:
                result = PacketProcessor._extract_dns_query_hostname(
                    dns_layer, proto_upper, src_ip)
                if result:
                    return result

            # DNS RESPONSES (QR=1): extract from answer records
            if dns_layer.qr == 1 and dns_layer.ancount > 0:
                result = PacketProcessor._extract_dns_response_hostname(
                    dns_layer, proto_upper)
                if result:
                    return result

        except Exception:
            pass

        return None

    @staticmethod
    def _extract_dhcp_hostname(packet) -> Optional[str]:
        """Extract hostname from DHCP Option 12 (Hostname)."""
        if not _DHCP_AVAILABLE:
            return None
        try:
            if not packet.haslayer(_DHCP):
                return None
            dhcp_options = packet[_DHCP].options
            for opt in dhcp_options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    if opt[0] == 'hostname':
                        hostname = opt[1]
                        if isinstance(hostname, bytes):
                            hostname = hostname.decode('utf-8', errors='replace')
                        hostname = hostname.strip().rstrip('.')
                        if hostname and hostname.lower() not in ('', 'unknown', 'localhost'):
                            return hostname
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_ssdp_hostname(packet) -> Optional[str]:
        """Extract friendly name from SSDP/UPnP NOTIFY and M-SEARCH responses."""
        try:
            if not packet.haslayer(UDP):
                return None
            # SSDP uses port 1900
            if not (packet.haslayer(UDP) and
                    (packet[UDP].sport == 1900 or packet[UDP].dport == 1900)):
                return None
            if not packet.haslayer(Raw):
                return None

            payload = packet[Raw].load
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='replace')

            # Look for X-FRIENDLY-NAME header which contains the actual device name.
            # NOTE: The SERVER: header is intentionally NOT parsed — it contains
            # software/library identifiers (e.g. "Dalvik/2.1.0", "IpBridge/1.0",
            # "Samsung/1.0") which are NOT device names and pollute the device list.
            for line in payload.split('\r\n'):
                line_upper = line.upper().strip()
                if line_upper.startswith('X-FRIENDLY-NAME:'):
                    name = line.split(':', 1)[1].strip()
                    if name:
                        return name
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_http_host(packet, src_ip: str) -> Optional[str]:
        """Extract hostname from HTTP Host header.

        Only used for device identification (e.g. a device making requests
        reveals what services it talks to). We do NOT return the Host
        header as the device's hostname — instead we return None here
        and let the passive callback handle learning.

        However, if the HTTP request itself is from a device that is
        advertising (e.g. local web UI at src_ip), we can learn its
        server name from the response.
        """
        # Intentionally limited: we don't want to name devices after
        # the websites they visit. HTTP Host extraction is primarily
        # useful for _future_ service mapping, not hostname resolution.
        return None

    @staticmethod
    def _extract_dns_query_hostname(dns_layer, proto_upper: str,
                                     src_ip: str) -> Optional[str]:
        """Extract hostname from DNS/mDNS/LLMNR query names.

        When a device queries for its own name (common in mDNS), the
        query name reveals the device's hostname. For regular DNS queries,
        we don't use the queried name as a hostname since it's just
        what the device is looking up (e.g., google.com).
        """
        try:
            for i in range(dns_layer.qdcount):
                try:
                    qr = dns_layer.qd[i] if dns_layer.qd else None
                    if qr is None:
                        break

                    qname = qr.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='replace')
                    qname = qname.rstrip('.')

                    # Only use query names from mDNS/LLMNR (local protocols)
                    if proto_upper not in ("MDNS", "LLMNR"):
                        continue

                    # mDNS: device querying for "<hostname>.local" A record
                    # is likely the device itself
                    if qr.qtype in (1, 28):  # A or AAAA
                        if '.local' in qname.lower():
                            hostname = qname.split('.')[0]
                            if (hostname and not hostname.startswith('_')
                                    and not hostname[0].isdigit()):
                                return hostname
                except Exception:
                    continue
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_dns_response_hostname(dns_layer, proto_upper: str) -> Optional[str]:
        """Extract hostname from DNS/mDNS/LLMNR response answer records."""
        try:
            for i in range(dns_layer.ancount):
                try:
                    rr = dns_layer.an[i] if dns_layer.an else None
                    if rr is None:
                        break

                    rrname = rr.rrname
                    if isinstance(rrname, bytes):
                        rrname = rrname.decode('utf-8', errors='replace')
                    rrname = rrname.rstrip('.')

                    # mDNS / LLMNR: PTR answers with .local hostnames
                    if rr.type == 12:  # PTR
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode('utf-8', errors='replace')
                        rdata = rdata.rstrip('.')

                        # mDNS PTR: "<hostname>.local" or "<hostname>._tcp.local"
                        if '.local' in rdata.lower():
                            parts = rdata.split('.')
                            if parts:
                                hostname = parts[0]
                                if hostname and not hostname.startswith('_'):
                                    return hostname

                    # A/AAAA record: the queried name itself is the hostname
                    if rr.type in (1, 28) and proto_upper in ("MDNS", "LLMNR"):
                        if '.local' in rrname.lower():
                            hostname = rrname.split('.')[0]
                            if hostname:
                                return hostname
                        elif rrname and not rrname[0].isdigit():
                            return rrname.split('.')[0]
                except Exception:
                    continue
        except Exception:
            pass
        return None
