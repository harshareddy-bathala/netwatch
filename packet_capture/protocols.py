"""
protocols.py - Protocol Detection
===================================

This module detects application-layer protocols based on port numbers.
Provides comprehensive protocol identification for network traffic analysis.
"""

import os
import sys

# Get config
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import PROTOCOL_PORTS


# =============================================================================
# EXTENDED PROTOCOL PORT MAPPINGS
# =============================================================================

# Additional ports not in config (merged with PROTOCOL_PORTS)
EXTENDED_PORTS = {
    # Web
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8000: "HTTP-ALT",
    8888: "HTTP-ALT",
    
    # Email
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
    
    # File Transfer
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    69: "TFTP",
    115: "SFTP",
    989: "FTPS-DATA",
    990: "FTPS",
    
    # DNS & Network Services
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    161: "SNMP",
    162: "SNMP-TRAP",
    500: "ISAKMP",
    514: "SYSLOG",
    5353: "mDNS",
    5355: "LLMNR",
    1900: "SSDP",
    
    # Remote Access
    23: "TELNET",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    
    # Databases
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    
    # Messaging & Communication
    5222: "XMPP",
    5269: "XMPP",
    6667: "IRC",
    1883: "MQTT",
    5672: "AMQP",
    
    # Streaming & Media
    554: "RTSP",
    1935: "RTMP",
    
    # Security
    636: "LDAPS",
    389: "LDAP",
    88: "Kerberos",
    
    # VoIP / WebRTC / STUN / TURN
    3478: "STUN",
    3479: "STUN",
    5060: "SIP",
    5061: "SIP-TLS",
    19302: "STUN",
    19305: "STUN",
    
    # VPN / Tunnel
    1194: "OpenVPN",
    1701: "L2TP",
    1723: "PPTP",
    4500: "IPsec-NAT",
    51820: "WireGuard",
    
    # Windows / Local Discovery
    135: "RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    445: "SMB",
    3702: "WSD",
    
    # Other Common
    1080: "SOCKS",
    3128: "HTTP-PROXY",
    8081: "HTTP-PROXY",
    8008: "HTTP-ALT",
    9443: "HTTPS-ALT",

    # Cloudflare & CDN HTTPS ports
    2053: "HTTPS",
    2083: "HTTPS",
    2087: "HTTPS",
    2096: "HTTPS",
    2052: "HTTP",
    2082: "HTTP",
    2086: "HTTP",
    2095: "HTTP",
}

# Merge with config PROTOCOL_PORTS (config takes precedence)
ALL_PROTOCOL_PORTS = {**EXTENDED_PORTS, **PROTOCOL_PORTS}


# =============================================================================
# PROTOCOL CATEGORIES
# =============================================================================

PROTOCOL_CATEGORIES = {
    'web': ['HTTP', 'HTTPS', 'HTTP-ALT', 'HTTPS-ALT', 'HTTP-PROXY', 'QUIC'],
    'email': ['SMTP', 'SMTPS', 'POP3', 'POP3S', 'IMAP', 'IMAPS'],
    'file_transfer': ['FTP', 'FTP-DATA', 'FTPS', 'FTPS-DATA', 'SFTP', 'TFTP', 'SMB'],
    'remote_access': ['SSH', 'TELNET', 'RDP', 'VNC'],
    'database': ['MySQL', 'PostgreSQL', 'MSSQL', 'ORACLE', 'Redis', 'MongoDB', 'Elasticsearch'],
    'network_services': ['DNS', 'DHCP', 'NTP', 'SNMP', 'SNMP-TRAP', 'SYSLOG', 'LDAP', 'LDAPS', 'STUN'],
    'messaging': ['XMPP', 'IRC', 'MQTT', 'AMQP'],
    'streaming': ['RTSP', 'RTMP'],
    'security': ['Kerberos', 'ISAKMP'],
    'legacy': ['NetBIOS-NS', 'NetBIOS-DGM', 'NetBIOS-SSN', 'RPC']
}

# Reverse mapping: protocol -> category
PROTOCOL_TO_CATEGORY = {}
for category, protocols in PROTOCOL_CATEGORIES.items():
    for protocol in protocols:
        PROTOCOL_TO_CATEGORY[protocol] = category


# =============================================================================
# MAIN PROTOCOL DETECTION FUNCTIONS
# =============================================================================

def detect_protocol(src_port: int = None, dst_port: int = None, 
                    raw_protocol: str = 'TCP') -> str:
    """
    Detect application-layer protocol from port numbers.
    
    Transport-layer aware: distinguishes QUIC (UDP/443) from HTTPS
    (TCP/443), and identifies common UDP services that would otherwise
    fall through to the generic "UDP" label.
    
    **Priority logic:** When both ports match different protocols, the
    *lower* port wins (more likely to be the server/service port).
    Well-known encrypted ports (443, 8443, etc.) are always classified
    as HTTPS regardless of the other port.
    
    Args:
        src_port: Source port number (can be None)
        dst_port: Destination port number (can be None)
        raw_protocol: Transport protocol ('TCP', 'UDP', 'ICMP')
    
    Returns:
        Protocol name string (e.g., 'HTTP', 'HTTPS', 'QUIC', 'DNS', 'TCP')
    """
    is_udp = raw_protocol and raw_protocol.upper() == "UDP"

    # ── HTTP/3 over QUIC (UDP on port 443) ─────────────────────
    # Modern browsers use QUIC (HTTP/3) over UDP/443 for most websites.
    # From the user's perspective this IS HTTPS — just a faster transport.
    if is_udp and (dst_port == 443 or src_port == 443):
        return "HTTPS"

    # HTTPS-alt ports over UDP — also HTTP/3
    if is_udp and (dst_port == 8443 or src_port == 8443):
        return "HTTPS"

    # ── Explicitly classify HTTPS ports (prevent ephemeral collisions) ──
    # If EITHER port is a known HTTPS port, classify as HTTPS immediately.
    # This prevents response packets (src=443, dst=ephemeral) from being
    # miscategorised when the ephemeral port accidentally matches a
    # lower-priority service in the port map.
    _HTTPS_PORTS = {443, 8443, 9443, 2053, 2083, 2087, 2096}
    for port in (dst_port, src_port):
        if port is not None and port in _HTTPS_PORTS:
            return "HTTPS"

    # ── Standard port-based lookup (prefer the lower / service port) ────
    # Server ports are typically in the well-known (0-1023) or registered
    # (1024-49151) range.  Ephemeral (client) ports are >= 49152.
    # Checking the lower port first prevents ephemeral port collisions.
    ports_to_check = [p for p in (dst_port, src_port) if p is not None]
    ports_to_check.sort()  # lower port first = more likely server port

    for port in ports_to_check:
        if port in ALL_PROTOCOL_PORTS:
            return ALL_PROTOCOL_PORTS[port]

    # ── Heuristic: well-known ephemeral ranges ─────────────────────
    if is_udp:
        for port in (dst_port, src_port):
            if port is not None:
                # Google STUN/TURN relay ports (WebRTC)
                if 19302 <= port <= 19309:
                    return "STUN"
                # HTTP/3 on non-standard high ports used by some CDNs
                if port == 4433 or port == 4434:
                    return "HTTPS"
    
    # Fall back to raw protocol
    if raw_protocol:
        return raw_protocol.upper()
    
    return 'UNKNOWN'


def get_protocol_by_port(port: int) -> str:
    """
    Look up protocol by port number.
    
    Args:
        port: Port number to look up
        
    Returns:
        Protocol name or None if not found
    """
    if port is None:
        return None
    return ALL_PROTOCOL_PORTS.get(port)


def get_port_by_protocol(protocol_name: str) -> list:
    """
    Get all ports associated with a protocol name.
    
    Args:
        protocol_name: Protocol name (e.g., 'HTTP')
        
    Returns:
        List of port numbers for the protocol
    """
    protocol_upper = protocol_name.upper()
    ports = []
    for port, proto in ALL_PROTOCOL_PORTS.items():
        if proto.upper() == protocol_upper:
            ports.append(port)
    return sorted(ports)


# =============================================================================
# TRAFFIC CLASSIFICATION HELPERS
# =============================================================================

def is_http_traffic(src_port: int = None, dst_port: int = None) -> bool:
    """
    Check if traffic is HTTP/HTTPS.
    
    Args:
        src_port: Source port number
        dst_port: Destination port number
        
    Returns:
        True if traffic is HTTP or HTTPS
    """
    http_ports = {80, 443, 8080, 8443, 8000, 8888, 3128, 8081}
    
    if src_port is not None and src_port in http_ports:
        return True
    if dst_port is not None and dst_port in http_ports:
        return True
    
    return False


def is_encrypted_traffic(src_port: int = None, dst_port: int = None) -> bool:
    """
    Check if traffic is likely encrypted (SSL/TLS).
    
    Args:
        src_port: Source port number
        dst_port: Destination port number
        
    Returns:
        True if traffic is likely encrypted
    """
    encrypted_ports = {443, 465, 636, 989, 990, 993, 995, 8443}
    
    if src_port is not None and src_port in encrypted_ports:
        return True
    if dst_port is not None and dst_port in encrypted_ports:
        return True
    
    return False


def is_dns_traffic(src_port: int = None, dst_port: int = None) -> bool:
    """
    Check if traffic is DNS.
    
    Args:
        src_port: Source port number
        dst_port: Destination port number
        
    Returns:
        True if traffic is DNS
    """
    return src_port == 53 or dst_port == 53


def is_database_traffic(src_port: int = None, dst_port: int = None) -> bool:
    """
    Check if traffic is to/from a database.
    
    Args:
        src_port: Source port number
        dst_port: Destination port number
        
    Returns:
        True if traffic appears to be database traffic
    """
    db_ports = {1433, 1521, 3306, 5432, 6379, 27017, 9200}
    
    if src_port is not None and src_port in db_ports:
        return True
    if dst_port is not None and dst_port in db_ports:
        return True
    
    return False


def is_well_known_port(port: int) -> bool:
    """
    Check if port is in the well-known range (0-1023).
    
    Args:
        port: Port number
        
    Returns:
        True if port is in well-known range
    """
    if port is None:
        return False
    return 0 <= port <= 1023


def is_registered_port(port: int) -> bool:
    """
    Check if port is in the registered range (1024-49151).
    
    Args:
        port: Port number
        
    Returns:
        True if port is in registered range
    """
    if port is None:
        return False
    return 1024 <= port <= 49151


def is_ephemeral_port(port: int) -> bool:
    """
    Check if port is in the ephemeral/dynamic range (49152-65535).
    
    Args:
        port: Port number
        
    Returns:
        True if port is in ephemeral range
    """
    if port is None:
        return False
    return 49152 <= port <= 65535


# =============================================================================
# CATEGORY FUNCTIONS
# =============================================================================

def get_protocol_category(protocol_name: str) -> str:
    """
    Get the category for a protocol.
    
    Args:
        protocol_name: Protocol name (e.g., 'HTTP', 'SSH')
        
    Returns:
        Category name (e.g., 'web', 'remote_access') or 'other'
    """
    if protocol_name is None:
        return 'other'
    
    protocol_upper = protocol_name.upper()
    
    # Handle raw protocols
    if protocol_upper in ('TCP', 'UDP', 'ICMP'):
        return 'transport'
    
    return PROTOCOL_TO_CATEGORY.get(protocol_name, 'other')


def get_protocols_by_category(category: str) -> list:
    """
    Get all protocols in a category.
    
    Args:
        category: Category name (e.g., 'web', 'email')
        
    Returns:
        List of protocol names in the category
    """
    return PROTOCOL_CATEGORIES.get(category.lower(), [])


def get_all_categories() -> list:
    """
    Get all available protocol categories.
    
    Returns:
        List of category names
    """
    return list(PROTOCOL_CATEGORIES.keys())


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_protocol_info(protocol_name: str) -> dict:
    """
    Get comprehensive information about a protocol.
    
    Args:
        protocol_name: Protocol name
        
    Returns:
        Dictionary with protocol information
    """
    ports = get_port_by_protocol(protocol_name)
    category = get_protocol_category(protocol_name)
    
    return {
        'name': protocol_name,
        'category': category,
        'ports': ports,
        'is_encrypted': protocol_name in ['HTTPS', 'SMTPS', 'POP3S', 'IMAPS', 
                                           'FTPS', 'FTPS-DATA', 'LDAPS', 'SSH'],
        'is_well_known': any(is_well_known_port(p) for p in ports) if ports else False
    }


def get_all_known_ports() -> dict:
    """
    Get all known port mappings.
    
    Returns:
        Dictionary of port -> protocol mappings
    """
    return ALL_PROTOCOL_PORTS.copy()


def format_protocol_display(protocol: str, src_port: int = None, 
                            dst_port: int = None) -> str:
    """
    Format protocol for display with port info.
    
    Args:
        protocol: Protocol name
        src_port: Source port (optional)
        dst_port: Destination port (optional)
        
    Returns:
        Formatted string like "HTTPS (443)"
    """
    if protocol in ('TCP', 'UDP', 'UNKNOWN'):
        if dst_port:
            return f"{protocol}:{dst_port}"
        elif src_port:
            return f"{protocol}:{src_port}"
        return protocol
    
    return protocol


# =============================================================================
# ICMP TYPE MAPPINGS
# =============================================================================

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply"
}


def get_icmp_type_name(icmp_type: int) -> str:
    """
    Get human-readable name for ICMP type.
    
    Args:
        icmp_type: ICMP type number
        
    Returns:
        Human-readable ICMP type name
    """
    return ICMP_TYPES.get(icmp_type, f"ICMP Type {icmp_type}")
