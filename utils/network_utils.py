"""
network_utils.py - Shared Network Utility Functions
=====================================================

Consolidates duplicated network utility functions that were previously
copy-pasted across:
  - ``packet_capture/geoip.py``  (``_is_private()``)
  - ``packet_capture/parser.py`` (``is_local_ip()``)
  - ``packet_capture/network_discovery.py`` (``_is_local_ip()``)
  - ``database/queries/device_queries.py`` (``is_private_ip()``)

Now all modules should import from here for consistent behaviour.

Usage::

    from utils.network_utils import is_private_ip, is_valid_device_ip
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def is_private_ip(ip_address: str) -> bool:
    """
    Return *True* if *ip_address* belongs to a private/local/non-routable range.

    Accepted ranges:
    - ``10.0.0.0/8``        (RFC 1918)
    - ``172.16.0.0/12``     (RFC 1918, 172.16.x – 172.31.x)
    - ``192.168.0.0/16``    (RFC 1918)
    - ``127.0.0.0/8``       (Loopback)
    - ``0.0.0.0/8``         (This network)
    - ``169.254.0.0/16``    (Link-local / APIPA)
    - ``localhost``
    - IPv6 link-local ``fe80::/10``, loopback ``::1``, ULA ``fd00::/8``
    """
    if not ip_address:
        return False

    if ip_address == "localhost":
        return True

    # IPv6
    if ":" in ip_address:
        lower = ip_address.lower()
        if lower.startswith("fe80:"):
            return True
        if lower == "::1":
            return True
        if lower.startswith("fd") or lower.startswith("fc"):
            return True  # ULA
        return False

    # IPv4
    if ip_address.startswith("10."):
        return True
    if ip_address.startswith("192.168."):
        return True
    if ip_address.startswith("172."):
        try:
            second_octet = int(ip_address.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (ValueError, IndexError):
            pass
    if ip_address.startswith("127."):
        return True
    if ip_address.startswith("0."):
        return True
    if ip_address.startswith("169.254."):
        return True

    return False


def is_valid_device_ip(ip_address: str) -> bool:
    """
    Return *True* if *ip_address* looks like a real device
    (not broadcast / multicast / loopback / link-local / unknown).
    """
    if not ip_address or ip_address == "unknown":
        return False

    ip_lower = ip_address.lower()

    # IPv6 special addresses
    if ":" in ip_address:
        if ip_lower.startswith("ff"):
            return False
        if ip_lower.startswith("fe80:"):
            return False
        if ip_address == "::1":
            return False
        return True

    try:
        parts = ip_address.split(".")
        if len(parts) != 4:
            return False
        first_octet = int(parts[0])
        last_octet = int(parts[3])
    except (ValueError, IndexError):
        return False

    if ip_address == "255.255.255.255":
        return False
    if last_octet == 255:
        return False
    if last_octet == 0:
        return False
    if 224 <= first_octet <= 239:           # Multicast
        return False
    if first_octet == 127:                  # Loopback
        return False
    if ip_address.startswith("169.254."):   # Link-local
        return False
    if first_octet == 0:
        return False

    return True


def normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase colon-separated format (xx:xx:xx:xx:xx:xx).

    Handles both dash-separated (Windows style) and colon-separated formats.
    """
    if not mac:
        return ""
    return mac.lower().replace("-", ":")


def is_valid_mac(mac: Optional[str]) -> bool:
    """Quick check that *mac* is a real unicast MAC."""
    if not mac or mac == "":
        return False
    mac_lower = mac.lower()
    if mac_lower == "ff:ff:ff:ff:ff:ff":
        return False
    if mac_lower == "00:00:00:00:00:00":
        return False
    if mac_lower.startswith("01:00:5e:"):       # IPv4 multicast
        return False
    if mac_lower.startswith("33:33:"):           # IPv6 multicast
        return False
    return True


def get_subnet_prefix(ip_address: str) -> Optional[str]:
    """
    Extract the first 3 octets from an IPv4 address.

    Returns:
        Subnet prefix like "10.234.255" or None if invalid.
    """
    if not ip_address or ":" in ip_address:
        return None
    parts = ip_address.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None
