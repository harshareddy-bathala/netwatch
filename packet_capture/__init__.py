"""
NetWatch Packet Capture Package
================================

This package provides network packet capture and analysis functionality.

Phase 2 architecture (preferred):
    from packet_capture.capture_engine import CaptureEngine
    from packet_capture.packet_processor import PacketProcessor, PacketData
    from packet_capture.bandwidth_calculator import BandwidthCalculator
    from packet_capture.filter_manager import FilterManager

Legacy (still functional):
    from packet_capture import NetworkMonitor
    from packet_capture.parser import parse_packet
    from packet_capture.protocols import detect_protocol
"""

# --- Phase 2 imports (new architecture) ---
from packet_capture.capture_engine import CaptureEngine
from packet_capture.packet_processor import PacketProcessor, PacketData
from packet_capture.bandwidth_calculator import BandwidthCalculator
from packet_capture.filter_manager import FilterManager

# --- Scapy availability flag ---
try:
    from scapy.all import conf as _scapy_conf  # noqa: F401
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from packet_capture.parser import (
    parse_packet,
    extract_ip_info,
    extract_port_info,
    get_packet_size,
    get_raw_protocol,
    get_tcp_flags,
    is_local_ip,
    summarize_packet
)

from packet_capture.protocols import (
    detect_protocol,
    get_protocol_by_port,
    get_port_by_protocol,
    is_http_traffic,
    is_encrypted_traffic,
    is_dns_traffic,
    is_database_traffic,
    get_protocol_category,
    get_protocols_by_category,
    get_all_categories,
    get_protocol_info,
    get_all_known_ports,
    PROTOCOL_CATEGORIES,
    ALL_PROTOCOL_PORTS
)

__all__ = [
    # Phase 2 (new architecture)
    'CaptureEngine',
    'PacketProcessor',
    'PacketData',
    'BandwidthCalculator',
    'FilterManager',
    
    # Scapy
    'SCAPY_AVAILABLE',
    
    # Parser
    'parse_packet',
    'extract_ip_info',
    'extract_port_info',
    'get_packet_size',
    'get_raw_protocol',
    'get_tcp_flags',
    'is_local_ip',
    'summarize_packet',
    
    # Protocols
    'detect_protocol',
    'get_protocol_by_port',
    'get_port_by_protocol',
    'is_http_traffic',
    'is_encrypted_traffic',
    'is_dns_traffic',
    'is_database_traffic',
    'get_protocol_category',
    'get_protocols_by_category',
    'get_all_categories',
    'get_protocol_info',
    'get_all_known_ports',
    'PROTOCOL_CATEGORIES',
    'ALL_PROTOCOL_PORTS'
]
