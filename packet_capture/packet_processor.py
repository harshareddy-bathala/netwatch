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
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, ARP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = IPv6 = TCP = UDP = ICMP = Ether = ARP = DNS = Raw = None

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

            # --- Packet size (IP layer only, excludes Ethernet header) ------
            pkt_bytes = self._get_ip_layer_size(packet)

            # --- Transport info ---------------------------------------------
            src_port, dst_port = self._extract_ports(packet)
            raw_proto = self._get_raw_protocol(packet)
            app_proto = detect_protocol(src_port, dst_port, raw_proto)

            # --- Direction (mode-aware) -------------------------------------
            direction = self._determine_direction(src_ip, dst_ip)

            # --- MAC addresses ----------------------------------------------
            src_mac = dst_mac = None
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

            # Fallback: enrich with our known MAC when Ether layer is
            # missing (Windows WiFi/Npcap) or when the captured MAC is
            # a broadcast/multicast that would be filtered out later.
            # In WiFi-client mode every packet involves our IP, so we
            # know exactly which side is "us".
            if self._our_mac:
                if src_ip == self._our_ip:
                    if not src_mac or src_mac == 'ff:ff:ff:ff:ff:ff':
                        src_mac = self._our_mac
                if dst_ip == self._our_ip:
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
            if packet.haslayer(TCP):
                extra["seq"] = packet[TCP].seq
                extra["ack"] = packet[TCP].ack

            return PacketData(
                timestamp=datetime.now(),
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
                extra=extra,
            )

        except Exception as exc:
            logger.debug(f"Error processing packet: {exc}")
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

    def _determine_direction(self, src_ip: str, dst_ip: str) -> str:
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
        """
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
