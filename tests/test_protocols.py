"""
test_protocols.py - Protocol Detection Tests (#58)
====================================================

Coverage for ``packet_capture.protocols``: detection functions,
classification helpers, category lookups, and edge cases.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.protocols import (
    detect_protocol,
    get_protocol_by_port,
    get_port_by_protocol,
    is_http_traffic,
    is_encrypted_traffic,
    is_dns_traffic,
    is_database_traffic,
    is_well_known_port,
    is_registered_port,
    is_ephemeral_port,
    get_protocol_category,
    get_protocols_by_category,
    get_all_categories,
    get_protocol_info,
    get_all_known_ports,
    format_protocol_display,
    get_icmp_type_name,
    ALL_PROTOCOL_PORTS,
    PROTOCOL_CATEGORIES,
)


# ===================================================================
# detect_protocol
# ===================================================================

class TestDetectProtocol:
    """Comprehensive tests for the main detect_protocol function."""

    def test_https_tcp(self):
        assert detect_protocol(dst_port=443, raw_protocol="TCP") == "HTTPS"

    def test_https_udp_quic(self):
        """UDP/443 should be classified as HTTPS (HTTP/3 / QUIC)."""
        assert detect_protocol(dst_port=443, raw_protocol="UDP") == "HTTPS"

    def test_https_source_port(self):
        """Response packets with src=443 should be HTTPS."""
        assert detect_protocol(src_port=443, dst_port=58123, raw_protocol="TCP") == "HTTPS"

    def test_http(self):
        assert detect_protocol(dst_port=80, raw_protocol="TCP") == "HTTP"

    def test_dns(self):
        assert detect_protocol(dst_port=53, raw_protocol="UDP") == "DNS"

    def test_ssh(self):
        assert detect_protocol(dst_port=22, raw_protocol="TCP") == "SSH"

    def test_rdp(self):
        assert detect_protocol(dst_port=3389, raw_protocol="TCP") == "RDP"

    def test_mysql(self):
        assert detect_protocol(dst_port=3306, raw_protocol="TCP") == "MySQL"

    def test_postgres(self):
        assert detect_protocol(dst_port=5432, raw_protocol="TCP") == "PostgreSQL"

    def test_lower_port_wins(self):
        """When both ports match different protocols, lower (server) wins."""
        result = detect_protocol(src_port=80, dst_port=3306, raw_protocol="TCP")
        assert result == "HTTP"  # port 80 < port 3306

    def test_fallback_to_raw_protocol(self):
        """Unrecognised ports fall back to raw transport protocol."""
        assert detect_protocol(src_port=60000, dst_port=60001, raw_protocol="TCP") == "TCP"

    def test_none_ports(self):
        assert detect_protocol(src_port=None, dst_port=None, raw_protocol="UDP") == "UDP"

    def test_unknown_fallback(self):
        assert detect_protocol(src_port=None, dst_port=None, raw_protocol=None) == "UNKNOWN"

    def test_stun_google_port_range(self):
        """Google STUN ports (19302-19309) over UDP should be STUN."""
        assert detect_protocol(dst_port=19302, raw_protocol="UDP") == "STUN"

    def test_https_alt_ports(self):
        for port in (8443, 9443, 2053, 2083, 2087, 2096):
            assert detect_protocol(dst_port=port, raw_protocol="TCP") == "HTTPS", f"Port {port}"

    def test_smb(self):
        assert detect_protocol(dst_port=445, raw_protocol="TCP") == "SMB"


# ===================================================================
# Lookup helpers
# ===================================================================

class TestLookupHelpers:

    def test_get_protocol_by_known_port(self):
        assert get_protocol_by_port(22) == "SSH"

    def test_get_protocol_by_unknown_port(self):
        assert get_protocol_by_port(60000) is None

    def test_get_protocol_by_none(self):
        assert get_protocol_by_port(None) is None

    def test_get_port_by_protocol_http(self):
        ports = get_port_by_protocol("HTTP")
        assert 80 in ports

    def test_get_port_by_protocol_unknown(self):
        assert get_port_by_protocol("NONEXISTENT") == []


# ===================================================================
# Traffic classification booleans
# ===================================================================

class TestTrafficClassification:

    def test_http_traffic_port_80(self):
        assert is_http_traffic(dst_port=80) is True

    def test_http_traffic_port_443(self):
        assert is_http_traffic(dst_port=443) is True

    def test_http_traffic_no_match(self):
        assert is_http_traffic(dst_port=22) is False

    def test_encrypted_traffic_443(self):
        assert is_encrypted_traffic(dst_port=443) is True

    def test_encrypted_traffic_993(self):
        assert is_encrypted_traffic(dst_port=993) is True

    def test_encrypted_traffic_no_match(self):
        assert is_encrypted_traffic(dst_port=80) is False

    def test_dns_traffic(self):
        assert is_dns_traffic(dst_port=53) is True
        assert is_dns_traffic(src_port=53) is True
        assert is_dns_traffic(dst_port=80) is False

    def test_database_traffic(self):
        assert is_database_traffic(dst_port=5432) is True
        assert is_database_traffic(dst_port=80) is False


# ===================================================================
# Port range checks
# ===================================================================

class TestPortRanges:

    def test_well_known(self):
        assert is_well_known_port(80) is True
        assert is_well_known_port(1023) is True
        assert is_well_known_port(1024) is False
        assert is_well_known_port(None) is False

    def test_registered(self):
        assert is_registered_port(3306) is True
        assert is_registered_port(80) is False
        assert is_registered_port(None) is False

    def test_ephemeral(self):
        assert is_ephemeral_port(50000) is True
        assert is_ephemeral_port(1024) is False
        assert is_ephemeral_port(None) is False


# ===================================================================
# Category functions
# ===================================================================

class TestCategories:

    def test_get_category_http(self):
        assert get_protocol_category("HTTP") == "web"

    def test_get_category_ssh(self):
        assert get_protocol_category("SSH") == "remote_access"

    def test_get_category_tcp_transport(self):
        assert get_protocol_category("TCP") == "transport"

    def test_get_category_unknown(self):
        assert get_protocol_category("FOOBAR") == "other"

    def test_get_category_none(self):
        assert get_protocol_category(None) == "other"

    def test_get_protocols_by_category_web(self):
        protocols = get_protocols_by_category("web")
        assert "HTTP" in protocols
        assert "HTTPS" in protocols

    def test_get_all_categories(self):
        cats = get_all_categories()
        assert "web" in cats
        assert "email" in cats
        assert len(cats) >= 5


# ===================================================================
# Utility functions
# ===================================================================

class TestUtilFunctions:

    def test_get_protocol_info(self):
        info = get_protocol_info("HTTPS")
        assert info["name"] == "HTTPS"
        assert info["category"] == "web"
        assert info["is_encrypted"] is True
        assert 443 in info["ports"]

    def test_get_all_known_ports(self):
        ports = get_all_known_ports()
        assert isinstance(ports, dict)
        assert 80 in ports

    def test_format_protocol_display_named(self):
        assert format_protocol_display("HTTPS") == "HTTPS"

    def test_format_protocol_display_tcp_with_port(self):
        assert format_protocol_display("TCP", dst_port=12345) == "TCP:12345"

    def test_format_protocol_display_unknown(self):
        result = format_protocol_display("UNKNOWN", dst_port=9999)
        assert "9999" in result

    def test_icmp_type_echo_request(self):
        assert get_icmp_type_name(8) == "Echo Request"

    def test_icmp_type_unknown(self):
        assert "ICMP Type" in get_icmp_type_name(255)
