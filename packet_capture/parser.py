"""
parser.py - Packet Parsing Logic (LEGACY)
==========================================

.. deprecated:: Phase 2
    New code should use :class:`packet_capture.packet_processor.PacketProcessor`
    which provides mode-aware direction detection, correct IP-layer sizing,
    and structured ``PacketData`` objects.

This module is retained for backward compatibility with code that still
calls ``parse_packet()`` directly.  It delegates to ``protocols.py`` for
protocol detection, which is also used by the new ``PacketProcessor``.
"""

import logging
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
import socket

from utils.network_utils import is_private_ip

# Scapy imports with error handling
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, ARP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Create dummy classes for type hints when scapy not available
    IP = TCP = UDP = ICMP = Ether = ARP = DNS = HTTP = HTTPRequest = HTTPResponse = Raw = IPv6 = None

# MAC vendor lookup library (optional — lazy-loaded to avoid blocking import)
MAC_LOOKUP_AVAILABLE = False
mac_lookup = None
_mac_lookup_init_done = False
_mac_lookup_lock = __import__('threading').Lock()


def _ensure_mac_lookup():
    """Lazily initialise ``MacLookup`` on first use.  Thread-safe."""
    global MAC_LOOKUP_AVAILABLE, mac_lookup, _mac_lookup_init_done
    if _mac_lookup_init_done:
        return
    with _mac_lookup_lock:
        if _mac_lookup_init_done:
            return
        try:
            from mac_vendor_lookup import MacLookup
            mac_lookup = MacLookup()
            try:
                mac_lookup.update_vendors()  # may timeout
            except Exception:
                pass  # stale DB is fine; skip on timeout
            MAC_LOOKUP_AVAILABLE = True
        except Exception:
            MAC_LOOKUP_AVAILABLE = False
            mac_lookup = None
        _mac_lookup_init_done = True

# Import protocol detection
import os
import sys
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from packet_capture.protocols import detect_protocol, get_icmp_type_name

# Setup logging
logger = logging.getLogger(__name__)


# =============================================================================
# MAIN PARSING FUNCTION
# =============================================================================

def parse_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Parse a raw Scapy packet and return structured data.
    
    Args:
        packet: Raw Scapy packet object
    
    Returns:
        dict with packet info or None if not parseable
        
    Structure of returned dict:
        {
            'timestamp': datetime object,
            'source_ip': str,
            'dest_ip': str,
            'source_port': int or None,
            'dest_port': int or None,
            'protocol': str (detected application protocol),
            'raw_protocol': str ('TCP', 'UDP', 'ICMP', etc.),
            'bytes': int (packet length),
            'ttl': int or None,
            'flags': str or None (TCP flags),
            'source_mac': str or None,
            'dest_mac': str or None,
            'ip_version': int (4 or 6),
            'extra': dict (additional protocol-specific info)
        }
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy not available for packet parsing")
        return None
    
    if packet is None:
        return None
    
    try:
        # Initialize result dictionary
        result = {
            'timestamp': datetime.now(),
            'source_ip': None,
            'dest_ip': None,
            'source_port': None,
            'dest_port': None,
            'protocol': 'UNKNOWN',
            'raw_protocol': 'UNKNOWN',
            'bytes': get_packet_size(packet),
            'ttl': None,
            'flags': None,
            'source_mac': None,
            'dest_mac': None,
            'device_name': None,
            'vendor': None,
            'ip_version': None,
            'extra': {}
        }
        
        # Extract Ethernet layer info (MAC addresses)
        if packet.haslayer(Ether):
            result['source_mac'] = packet[Ether].src
            result['dest_mac'] = packet[Ether].dst
        
        # Handle ARP packets
        if packet.haslayer(ARP):
            result['raw_protocol'] = 'ARP'
            result['protocol'] = 'ARP'
            result['source_ip'] = packet[ARP].psrc
            result['dest_ip'] = packet[ARP].pdst
            result['extra']['arp_op'] = packet[ARP].op
            return result
        
        # Check for IP layer (required for most analysis)
        src_ip, dst_ip, ip_version = extract_ip_info(packet)
        
        if src_ip is None:
            # No IP layer - might be a non-IP packet
            # Still return what we have for logging purposes
            if result['source_mac']:
                return result
            return None
        
        result['source_ip'] = src_ip
        result['dest_ip'] = dst_ip
        result['ip_version'] = ip_version
        
        # Get TTL
        result['ttl'] = get_ttl(packet)
        
        # Extract transport layer info (ports, protocol)
        src_port, dst_port = extract_port_info(packet)
        result['source_port'] = src_port
        result['dest_port'] = dst_port
        
        # Determine raw protocol
        raw_protocol = get_raw_protocol(packet)
        result['raw_protocol'] = raw_protocol
        
        # Detect application protocol
        result['protocol'] = detect_protocol(src_port, dst_port, raw_protocol)
        
        # Extract TCP flags if applicable
        if packet.haslayer(TCP):
            result['flags'] = get_tcp_flags(packet)
            result['extra']['seq'] = packet[TCP].seq
            result['extra']['ack'] = packet[TCP].ack
            result['extra']['window'] = packet[TCP].window
        
        # Extract ICMP info
        if packet.haslayer(ICMP):
            result['extra']['icmp_type'] = packet[ICMP].type
            result['extra']['icmp_code'] = packet[ICMP].code
            result['extra']['icmp_type_name'] = get_icmp_type_name(packet[ICMP].type)
        
        # Extract DNS info if available
        if packet.haslayer(DNS):
            dns_info = extract_dns_info(packet)
            if dns_info:
                result['extra']['dns'] = dns_info
        
        # Check for HTTP (if scapy http layer loaded)
        if HTTP is not None and packet.haslayer(HTTP):
            http_info = extract_http_info(packet)
            if http_info:
                result['extra']['http'] = http_info
        
        # Resolve device name and vendor from MAC/IP (source)
        if result['source_mac'] and result['source_ip']:
            # Look up MAC vendor
            result['vendor'] = lookup_mac_vendor(result['source_mac'])
            
            # Resolve device hostname
            result['device_name'] = resolve_device_name(
                result['source_mac'],
                result['source_ip']
            )
        
        # Also lookup destination vendor for gateway/hotspot detection
        if result['dest_mac']:
            result['dest_vendor'] = lookup_mac_vendor(result['dest_mac'])
        
        return result
        
    except Exception as e:
        logger.warning("Error parsing packet: %s", e)
        return None


# =============================================================================
# IP LAYER EXTRACTION
# =============================================================================

def extract_ip_info(packet) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Extract source and destination IP addresses from packet.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Tuple of (source_ip, dest_ip, ip_version) or (None, None, None)
    """
    if not SCAPY_AVAILABLE or packet is None:
        return None, None, None
    
    try:
        # Check for IPv4
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            return ip_layer.src, ip_layer.dst, 4
        
        # Check for IPv6
        if packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            return ipv6_layer.src, ipv6_layer.dst, 6
        
        return None, None, None
        
    except Exception as e:
        logger.debug("Error extracting IP info: %s", e)
        return None, None, None


def get_ttl(packet) -> Optional[int]:
    """
    Get TTL (Time To Live) from packet.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        TTL value or None
    """
    if not SCAPY_AVAILABLE or packet is None:
        return None
    
    try:
        if packet.haslayer(IP):
            return packet[IP].ttl
        if packet.haslayer(IPv6):
            return packet[IPv6].hlim  # Hop Limit for IPv6
        return None
    except Exception:
        return None


# =============================================================================
# TRANSPORT LAYER EXTRACTION
# =============================================================================

def extract_port_info(packet) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract source and destination ports from packet.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Tuple of (source_port, dest_port) or (None, None)
    """
    if not SCAPY_AVAILABLE or packet is None:
        return None, None
    
    try:
        # Check for TCP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return tcp_layer.sport, tcp_layer.dport
        
        # Check for UDP
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            return udp_layer.sport, udp_layer.dport
        
        return None, None
        
    except Exception as e:
        logger.debug("Error extracting port info: %s", e)
        return None, None


def get_raw_protocol(packet) -> str:
    """
    Determine the raw transport protocol.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Protocol name ('TCP', 'UDP', 'ICMP', etc.)
    """
    if not SCAPY_AVAILABLE or packet is None:
        return 'UNKNOWN'
    
    try:
        if packet.haslayer(TCP):
            return 'TCP'
        if packet.haslayer(UDP):
            return 'UDP'
        if packet.haslayer(ICMP):
            return 'ICMP'
        if packet.haslayer(ARP):
            return 'ARP'
        if packet.haslayer(IP):
            # Get protocol number from IP header
            proto_num = packet[IP].proto
            proto_map = {
                1: 'ICMP',
                2: 'IGMP',
                6: 'TCP',
                17: 'UDP',
                41: 'IPv6',
                47: 'GRE',
                50: 'ESP',
                51: 'AH',
                89: 'OSPF',
                132: 'SCTP'
            }
            return proto_map.get(proto_num, f'PROTO-{proto_num}')
        
        return 'UNKNOWN'
        
    except Exception as e:
        logger.debug("Error determining protocol: %s", e)
        return 'UNKNOWN'


def get_tcp_flags(packet) -> Optional[str]:
    """
    Extract TCP flags as a string.
    
    Args:
        packet: Scapy packet object with TCP layer
        
    Returns:
        String representation of TCP flags (e.g., 'SYN', 'ACK', 'FIN')
    """
    if not SCAPY_AVAILABLE or packet is None:
        return None
    
    try:
        if not packet.haslayer(TCP):
            return None
        
        tcp_layer = packet[TCP]
        flags = []
        
        # Check each flag
        if tcp_layer.flags.F:  # FIN
            flags.append('FIN')
        if tcp_layer.flags.S:  # SYN
            flags.append('SYN')
        if tcp_layer.flags.R:  # RST
            flags.append('RST')
        if tcp_layer.flags.P:  # PSH
            flags.append('PSH')
        if tcp_layer.flags.A:  # ACK
            flags.append('ACK')
        if tcp_layer.flags.U:  # URG
            flags.append('URG')
        if tcp_layer.flags.E:  # ECE
            flags.append('ECE')
        if tcp_layer.flags.C:  # CWR
            flags.append('CWR')
        
        return ','.join(flags) if flags else 'NONE'
        
    except Exception as e:
        logger.debug("Error extracting TCP flags: %s", e)
        return None


# =============================================================================
# SIZE AND PAYLOAD
# =============================================================================

def get_packet_size(packet) -> int:
    """
    Get the size of the packet in bytes.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Packet size in bytes
    """
    if packet is None:
        return 0
    
    try:
        return len(packet)
    except Exception:
        return 0


def get_payload_size(packet) -> int:
    """
    Get the size of the packet payload (excluding headers).
    
    Args:
        packet: Scapy packet object
        
    Returns:
        Payload size in bytes
    """
    if not SCAPY_AVAILABLE or packet is None:
        return 0
    
    try:
        if packet.haslayer(Raw):
            return len(packet[Raw].load)
        return 0
    except Exception:
        return 0


def has_payload(packet) -> bool:
    """
    Check if packet has application payload.
    
    Args:
        packet: Scapy packet object
        
    Returns:
        True if packet has payload data
    """
    if not SCAPY_AVAILABLE or packet is None:
        return False
    
    try:
        return packet.haslayer(Raw) and len(packet[Raw].load) > 0
    except Exception:
        return False


# =============================================================================
# DNS EXTRACTION
# =============================================================================

def extract_dns_info(packet) -> Optional[Dict[str, Any]]:
    """
    Extract DNS query/response information.
    
    Args:
        packet: Scapy packet with DNS layer
        
    Returns:
        Dictionary with DNS info or None
    """
    if not SCAPY_AVAILABLE or packet is None:
        return None
    
    try:
        if not packet.haslayer(DNS):
            return None
        
        dns = packet[DNS]
        info = {
            'id': dns.id,
            'qr': dns.qr,  # 0 = query, 1 = response
            'opcode': dns.opcode,
            'is_query': dns.qr == 0,
            'is_response': dns.qr == 1,
            'questions': [],
            'answers': []
        }
        
        # Extract questions
        if dns.qdcount > 0 and dns.qd:
            for i in range(dns.qdcount):
                try:
                    q = dns.qd[i] if hasattr(dns.qd, '__getitem__') else dns.qd
                    info['questions'].append({
                        'name': q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                        'type': q.qtype
                    })
                except Exception:
                    pass
        
        # Extract answers (for responses)
        if dns.ancount > 0 and dns.an:
            for i in range(dns.ancount):
                try:
                    a = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                    answer = {
                        'name': a.rrname.decode() if isinstance(a.rrname, bytes) else str(a.rrname),
                        'type': a.type,
                        'ttl': a.ttl
                    }
                    if hasattr(a, 'rdata'):
                        answer['data'] = str(a.rdata)
                    info['answers'].append(answer)
                except Exception:
                    pass
        
        return info
        
    except Exception as e:
        logger.debug("Error extracting DNS info: %s", e)
        return None


# =============================================================================
# HTTP EXTRACTION
# =============================================================================

def extract_http_info(packet) -> Optional[Dict[str, Any]]:
    """
    Extract HTTP request/response information.
    
    Args:
        packet: Scapy packet with HTTP layer
        
    Returns:
        Dictionary with HTTP info or None
    """
    if not SCAPY_AVAILABLE or packet is None or HTTP is None:
        return None
    
    try:
        if not packet.haslayer(HTTP):
            return None
        
        info = {}
        
        # Check for HTTP Request
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            info['type'] = 'request'
            info['method'] = req.Method.decode() if hasattr(req, 'Method') and req.Method else 'UNKNOWN'
            info['path'] = req.Path.decode() if hasattr(req, 'Path') and req.Path else '/'
            info['host'] = req.Host.decode() if hasattr(req, 'Host') and req.Host else None
            if hasattr(req, 'User_Agent'):
                info['user_agent'] = req.User_Agent.decode() if req.User_Agent else None
        
        # Check for HTTP Response
        elif packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            info['type'] = 'response'
            info['status_code'] = resp.Status_Code.decode() if hasattr(resp, 'Status_Code') and resp.Status_Code else None
            info['reason'] = resp.Reason_Phrase.decode() if hasattr(resp, 'Reason_Phrase') and resp.Reason_Phrase else None
            if hasattr(resp, 'Content_Type'):
                info['content_type'] = resp.Content_Type.decode() if resp.Content_Type else None
        
        return info if info else None
        
    except Exception as e:
        logger.debug("Error extracting HTTP info: %s", e)
        return None


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def is_local_ip(ip: str) -> bool:
    """
    Check if an IP address is a local/private address.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is local/private
    """
    return is_private_ip(ip)


def format_mac_address(mac: str) -> str:
    """
    Format MAC address for display.
    
    Args:
        mac: MAC address string
        
    Returns:
        Formatted MAC address (uppercase, colon-separated)
    """
    if not mac:
        return None
    
    # Already formatted correctly
    if ':' in mac:
        return mac.upper()
    
    # Convert from other formats
    mac_clean = mac.replace('-', '').replace('.', '').upper()
    if len(mac_clean) == 12:
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    
    return mac.upper()


def lookup_mac_vendor(mac_address: str) -> Optional[str]:
    """
    Look up the vendor/manufacturer of a MAC address.
    
    Args:
        mac_address: MAC address in any format (aa:bb:cc:dd:ee:ff or aabbccddeeff)
        
    Returns:
        Vendor name or None if not found
    """
    if not mac_address or mac_address == 'N/A':
        return None
    
    _ensure_mac_lookup()
    try:
        if MAC_LOOKUP_AVAILABLE and mac_lookup:
            vendor = mac_lookup.lookup(mac_address)
            return vendor
    except Exception as e:
        logger.debug("MAC vendor lookup failed for %s: %s", mac_address, e)
    
    return None


# Rate-limiter for nbtstat subprocess calls (prevent fork-bomb).
_nbtstat_cache: Dict[str, Any] = {}   # ip -> (result, timestamp)
_NBTSTAT_CACHE_TTL = 300              # seconds
_NBTSTAT_CACHE_MAX_SIZE = 1024        # max cached entries
_NBTSTAT_MAX_PENDING = 5
_nbtstat_pending = 0
_nbtstat_lock = __import__('threading').Lock()


def resolve_device_name(mac_address: str, ip_address: str) -> Optional[str]:
    """
    Resolve device name from MAC address and/or IP address.
    
    Uses multiple methods:
    1. Reverse DNS lookup (gethostbyaddr)
    2. Windows NetBIOS name lookup
    3. MAC vendor as fallback
    
    Args:
        mac_address: Device MAC address
        ip_address: Device IP address
        
    Returns:
        Device name/hostname or None
    """
    if not ip_address or ip_address == 'N/A':
        return None
    
    # Method 1: Try reverse DNS lookup
    try:
        hostname_tuple = socket.gethostbyaddr(ip_address)
        if hostname_tuple and hostname_tuple[0]:
            hostname = hostname_tuple[0]
            # Return just the hostname (before first dot)
            if '.' in hostname:
                return hostname.split('.')[0]
            return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        pass
    except Exception as e:
        logger.debug("Hostname lookup failed for %s: %s", ip_address, e)
    
    # Method 2: Try NetBIOS name lookup (Windows only) — rate-limited
    try:
        import sys
        if sys.platform == 'win32':
            import subprocess
            import time as _time

            # Check nbtstat cache first
            cached = _nbtstat_cache.get(ip_address)
            if cached is not None:
                result_val, ts = cached
                if _time.monotonic() - ts < _NBTSTAT_CACHE_TTL:
                    if result_val:
                        return result_val
                    # Cached miss — skip to vendor fallback
                    raise StopIteration("cached miss")

            # Rate-limit concurrent nbtstat subprocesses
            global _nbtstat_pending
            with _nbtstat_lock:
                if _nbtstat_pending >= _NBTSTAT_MAX_PENDING:
                    raise StopIteration("rate limited")
                _nbtstat_pending += 1
            try:
                result = subprocess.run(
                    ['nbtstat', '-A', ip_address],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                netbios_name = None
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '<00>' in line and 'UNIQUE' in line:
                            parts = line.split()
                            if parts:
                                name = parts[0].strip()
                                if name and name != '__MSBROWSE__':
                                    netbios_name = name
                                    break
                # Evict oldest entries when cache is full
                if len(_nbtstat_cache) >= _NBTSTAT_CACHE_MAX_SIZE:
                    oldest_ip = min(_nbtstat_cache, key=lambda k: _nbtstat_cache[k][1])
                    del _nbtstat_cache[oldest_ip]
                _nbtstat_cache[ip_address] = (netbios_name, _time.monotonic())
                if netbios_name:
                    return netbios_name
            finally:
                with _nbtstat_lock:
                    _nbtstat_pending -= 1
    except StopIteration:
        pass  # Skip to vendor fallback
    except Exception as e:
        logger.debug("NetBIOS lookup failed for %s: %s", ip_address, e)
    
    # Method 3: Fallback to MAC vendor
    if mac_address and mac_address != 'N/A':
        vendor = lookup_mac_vendor(mac_address)
        if vendor:
            return f"{vendor} Device"
    
    return None


def summarize_packet(packet_data: Dict[str, Any]) -> str:
    """
    Create a one-line summary of parsed packet data.
    
    Args:
        packet_data: Dictionary from parse_packet()
        
    Returns:
        Summary string
    """
    if not packet_data:
        return "Invalid packet"
    
    parts = []
    
    # Protocol
    parts.append(packet_data.get('protocol', 'UNKNOWN'))
    
    # Source
    src_ip = packet_data.get('source_ip', '?')
    src_port = packet_data.get('source_port')
    if src_port:
        parts.append(f"{src_ip}:{src_port}")
    else:
        parts.append(src_ip)
    
    parts.append("->")
    
    # Destination
    dst_ip = packet_data.get('dest_ip', '?')
    dst_port = packet_data.get('dest_port')
    if dst_port:
        parts.append(f"{dst_ip}:{dst_port}")
    else:
        parts.append(dst_ip)
    
    # Size
    size = packet_data.get('bytes', 0)
    parts.append(f"({size} bytes)")
    
    return ' '.join(parts)
