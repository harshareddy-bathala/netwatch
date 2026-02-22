"""
device_queries.py - Device CRUD Operations
=============================================

Contains the **single source of truth** for device counting via
``get_active_device_count()``.  Every part of the application
(dashboard, alerts, health score, API) MUST use this function
so that device numbers are consistent everywhere.

Key principles:
* MAC address is the primary device identifier.
* Only **private** IPs are stored in the devices table.
* Broadcast / multicast / loopback addresses are excluded.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from database.connection import get_connection, dict_from_row
from utils.query_cache import time_query, TTLCache
from utils.network_utils import is_private_ip as _shared_is_private_ip
from utils.network_utils import is_valid_device_ip as _shared_is_valid_device_ip
from utils.network_utils import is_valid_mac as _shared_is_valid_mac

logger = logging.getLogger(__name__)

# Cache for expensive device queries (5s TTL — slightly longer than the
# dashboard's 3s TTL so that sub-queries are usually served from cache
# when the dashboard rebuilds).
_device_cache = TTLCache(ttl_seconds=5)

# ---------------------------------------------------------------------------
# Subnet detection helpers
# ---------------------------------------------------------------------------

_cached_subnet: Optional[str] = None
_cached_our_ip: Optional[str] = None


# The name of the capture interface, set by main.py at startup.
_capture_interface_name: Optional[str] = None


def set_capture_interface(iface_name: str):
    """Set the capture interface name so _detect_our_ip() uses it."""
    global _capture_interface_name
    _capture_interface_name = iface_name


def _detect_our_ip() -> str:
    """Detect this machine's local IP address.

    Prefers ``netifaces.ifaddresses()`` on the capture interface so that
    Docker / VPN adapters don't shadow the real address.  Falls back to
    the ``socket.connect('8.8.8.8')`` trick only when *netifaces* is not
    available or yields no result.
    """
    global _cached_our_ip
    if _cached_our_ip:
        return _cached_our_ip

    # 1. Try netifaces on the configured capture interface
    try:
        import netifaces
        iface = _capture_interface_name
        if iface:
            addrs = netifaces.ifaddresses(iface)
            ipv4_list = addrs.get(netifaces.AF_INET, [])
            for entry in ipv4_list:
                ip = entry.get('addr', '')
                if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                    _cached_our_ip = ip
                    return ip
        # No capture interface set — try the default gateway's interface
        gws = netifaces.gateways()
        default_gw = gws.get('default', {}).get(netifaces.AF_INET)
        if default_gw:
            gw_iface = default_gw[1]
            addrs = netifaces.ifaddresses(gw_iface)
            ipv4_list = addrs.get(netifaces.AF_INET, [])
            for entry in ipv4_list:
                ip = entry.get('addr', '')
                if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                    _cached_our_ip = ip
                    return ip
    except Exception:
        pass

    # 2. Fallback: socket trick
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        _cached_our_ip = ip
        return ip
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# MAC address detection (for IPv6 → device attribution)
# ---------------------------------------------------------------------------

_cached_our_mac: Optional[str] = None


def _detect_our_mac() -> str:
    """Detect this machine's MAC address on the capture interface.

    Used to attribute IPv6 traffic to the local device's IPv4 record
    in the ``devices`` table.
    """
    global _cached_our_mac
    if _cached_our_mac:
        return _cached_our_mac

    try:
        import netifaces
        iface = _capture_interface_name
        if iface:
            addrs = netifaces.ifaddresses(iface)
            link_addrs = addrs.get(netifaces.AF_LINK, [])
            for entry in link_addrs:
                mac = entry.get('addr', '')
                if mac and mac.lower() not in ('', '00:00:00:00:00:00'):
                    _cached_our_mac = mac.lower()
                    return _cached_our_mac
        # Fallback: try default gateway interface
        gws = netifaces.gateways()
        default_gw = gws.get('default', {}).get(netifaces.AF_INET)
        if default_gw:
            gw_iface = default_gw[1]
            addrs = netifaces.ifaddresses(gw_iface)
            link_addrs = addrs.get(netifaces.AF_LINK, [])
            for entry in link_addrs:
                mac = entry.get('addr', '')
                if mac and mac.lower() not in ('', '00:00:00:00:00:00'):
                    _cached_our_mac = mac.lower()
                    return _cached_our_mac
    except Exception:
        pass
    return ""


def _build_mac_to_ipv4(cursor) -> dict:
    """Build a MAC → IPv4 lookup from the ``devices`` table.

    Used at the start of ``save_packets_batch()`` to attribute IPv6
    traffic to known local devices.  Always includes our own device
    mapping so we don't depend on the ``devices`` table having been
    populated yet.
    """
    result: dict = {}
    try:
        cursor.execute("""
            SELECT LOWER(mac_address) AS mac,
                   COALESCE(ipv4_address, ip_address) AS ip
            FROM devices
            WHERE mac_address IS NOT NULL AND mac_address != ''
                  AND (ipv4_address IS NOT NULL AND ipv4_address != ''
                       OR ip_address IS NOT NULL AND ip_address != '')
        """)
        for row in cursor.fetchall():
            result[row["mac"]] = row["ip"]
    except Exception:
        pass
    # Always include our own mapping (might not be in devices table yet)
    our_mac = _detect_our_mac()
    our_ip = _detect_our_ip()
    if our_mac and our_ip:
        result[our_mac] = our_ip
    return result


def _detect_subnet() -> str:
    """Get current subnet prefix (e.g. '10.234.255')."""
    global _cached_subnet
    if _cached_subnet:
        return _cached_subnet
    ip = _detect_our_ip()
    if ip:
        parts = ip.split('.')
        if len(parts) == 4:
            _cached_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
            return _cached_subnet
    return ""


def reset_subnet_cache():
    """Reset cached subnet (call when interface changes)."""
    global _cached_subnet, _cached_our_ip, _cached_our_mac, _cached_gateway_ip, _gateway_cache_time
    _cached_subnet = None
    _cached_our_ip = None
    _cached_our_mac = None
    _cached_gateway_ip = None
    _gateway_cache_time = None


# Current network mode name — set by main.py on startup and mode changes
_current_mode_name: Optional[str] = None
_cached_gateway_ip: Optional[str] = None
_gateway_cache_time: Optional[float] = None


def set_gateway_ip(gw_ip: str):
    """
    Explicitly set the gateway IP from mode detection.

    Called by main.py on mode changes, using the gateway already detected
    by the mode detector.  This avoids re-parsing ``ipconfig`` and ensures
    the correct adapter's gateway is used on multi-adapter systems.
    """
    global _cached_gateway_ip
    if gw_ip:
        _cached_gateway_ip = gw_ip
        logger.info("Gateway IP set from mode detector: %s", gw_ip)
    else:
        _cached_gateway_ip = None  # allow re-detection


def _get_gateway_ip() -> str:
    """Detect and cache the default gateway IP address.

    Prefers the value set by :func:`set_gateway_ip` (from mode detection).
    Falls back to ``netifaces.gateways()`` for cross-platform detection.
    Uses a TTL so a stale empty-string cache is retried after 30 seconds.
    """
    global _cached_gateway_ip, _gateway_cache_time
    import time as _time

    # Use explicit cache if available and non-empty
    if _cached_gateway_ip:
        return _cached_gateway_ip

    # If we cached an empty result recently, honour the TTL
    if (_cached_gateway_ip == ""
            and _gateway_cache_time
            and (_time.time() - _gateway_cache_time) < 30):
        return ""

    try:
        import netifaces
        gws = netifaces.gateways()
        default_gw = gws.get('default', {}).get(netifaces.AF_INET)
        if default_gw:
            gw_ip = default_gw[0]  # (gateway_ip, interface_name, is_default)
            if gw_ip and gw_ip[0].isdigit():
                _cached_gateway_ip = gw_ip
                _gateway_cache_time = _time.time()
                return gw_ip
    except Exception:
        pass

    _cached_gateway_ip = ""
    _gateway_cache_time = _time.time()
    return ""


def set_subnet_from_ip(ip: str):
    """
    Explicitly set the subnet cache from a known-good IP.

    Called at startup from the capture interface's IP to override
    the default socket-based detection which may use Docker/VPN IPs.

    Args:
        ip: IP address like "10.234.255.114"
    """
    global _cached_subnet, _cached_our_ip
    if ip:
        parts = ip.split('.')
        if len(parts) == 4:
            _cached_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
            _cached_our_ip = ip
            logger.info(
                "Subnet frozen to capture interface: %s -> %s",
                ip, _cached_subnet
            )


def set_current_mode(mode_name: str):
    """
    Set the current network mode name so device filtering can adapt.

    In port_mirror and hotspot modes, subnet filtering is relaxed
    because we can see traffic from multiple subnets.

    Args:
        mode_name: One of 'wifi_client', 'hotspot', 'ethernet',
                   'port_mirror', 'public_network'
    """
    global _current_mode_name
    _current_mode_name = mode_name
    logger.info("Device queries: mode set to '%s'", mode_name)


def deactivate_stale_devices(new_subnet_prefix: str) -> int:
    """Legacy wrapper — calls :func:`scope_devices_to_mode`."""
    return scope_devices_to_mode(_current_mode_name or "unknown", new_subnet_prefix)


_RESTRICTIVE_MODES = frozenset({"wifi_client", "public_network"})


def scope_devices_to_mode(
    new_mode_name: str,
    new_subnet_prefix: str,
    our_mac: Optional[str] = None,
    gateway_mac: Optional[str] = None,
) -> int:
    """
    Scope devices to the new mode: set ``active_mode`` for matching
    devices and clear it for everyone else.

    Called during mode changes so that only the new mode's devices
    appear in the dashboard.  Records are NOT deleted — switching
    back restores them as traffic resumes.

    For **wifi_client** and **public_network** modes only our own device
    (identified by *our_mac*) and optionally the gateway (*gateway_mac*)
    are tagged active.  All other devices are cleared.

    For **hotspot**, **ethernet**, **port_mirror**: tag all subnet devices
    (original behaviour).

    Args:
        new_mode_name:      e.g. ``'wifi_client'``, ``'hotspot'``.
        new_subnet_prefix:  Three-octet prefix, e.g. ``'192.168.1'``.
        our_mac:            MAC address of this machine (lower-case,
                            colon-separated).  Required for restrictive
                            modes; ignored otherwise.
        gateway_mac:        MAC address of the default gateway (optional).

    Returns:
        Number of devices whose ``active_mode`` was cleared.
    """
    if not new_subnet_prefix:
        return 0

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            if new_mode_name in _RESTRICTIVE_MODES and our_mac:
                # ── Restrictive path (wifi_client / public_network) ──
                # 1. Clear ALL devices first
                cursor.execute(
                    "UPDATE devices SET active_mode = NULL WHERE active_mode IS NOT NULL"
                )
                cleared = cursor.rowcount

                # 2. Tag only our MAC (+ gateway MAC if known)
                allowed_macs = [our_mac.lower()]
                if gateway_mac:
                    allowed_macs.append(gateway_mac.lower())
                placeholders = ",".join("?" for _ in allowed_macs)
                cursor.execute(
                    f"""
                    UPDATE devices
                    SET active_mode = ?
                    WHERE LOWER(mac_address) IN ({placeholders})
                    """,
                    (new_mode_name, *allowed_macs),
                )
                tagged = cursor.rowcount
            else:
                # ── Permissive path (hotspot / ethernet / port_mirror) ──
                # 1. Tag devices that belong to the new mode's subnet
                cursor.execute(
                    """
                    UPDATE devices
                    SET active_mode = ?
                    WHERE (ipv4_address LIKE ? OR ip_address LIKE ?)
                      AND mac_address IS NOT NULL
                      AND mac_address != ''
                    """,
                    (new_mode_name, f"{new_subnet_prefix}.%", f"{new_subnet_prefix}.%"),
                )
                tagged = cursor.rowcount

                # 2. Clear active_mode for devices NOT in the new subnet
                cursor.execute(
                    """
                    UPDATE devices
                    SET active_mode = NULL
                    WHERE (active_mode IS NOT NULL OR active_mode != '')
                      AND (ipv4_address NOT LIKE ? AND ip_address NOT LIKE ?)
                    """,
                    (f"{new_subnet_prefix}.%", f"{new_subnet_prefix}.%"),
                )
                cleared = cursor.rowcount

            conn.commit()
            if tagged or cleared:
                logger.info(
                    "scope_devices_to_mode('%s', '%s.*'): tagged=%d, cleared=%d",
                    new_mode_name, new_subnet_prefix, tagged, cleared,
                )
            return cleared
    except sqlite3.Error as e:
        logger.error("scope_devices_to_mode error: %s", e)
        return 0



# ---------------------------------------------------------------------------
# IP validation helpers
# ---------------------------------------------------------------------------

def is_private_ip(ip_address: str) -> bool:
    """
    Return *True* if *ip_address* belongs to a private (RFC 1918) range.

    Accepted ranges:
    - ``10.0.0.0/8``
    - ``172.16.0.0/12``   (172.16.x – 172.31.x)
    - ``192.168.0.0/16``

    Note: IPv6 addresses always return False (device tracking is IPv4-only).
    """
    if not ip_address or ":" in ip_address:
        return False
    return _shared_is_private_ip(ip_address)


def is_valid_device_ip(ip_address: str) -> bool:
    """
    Return *True* if *ip_address* looks like a real device
    (not broadcast / multicast / loopback / link-local / unknown).
    """
    return _shared_is_valid_device_ip(ip_address)


def is_valid_device(ip: str, mac: str, current_subnet: str) -> bool:
    """
    Determine if device should be tracked.

    Args:
        ip: Device IP address (e.g., "10.234.255.114")
        mac: Device MAC address (e.g., "28:d0:43:a5:22:70")
        current_subnet: Current network subnet (e.g., "10.234.255")

    Returns:
        True if device should be tracked, False otherwise

    CRITICAL FILTERING RULES:
    1. Must be in current subnet (e.g. 10.234.255.x)
    2. Must have valid MAC (not broadcast, not null)
    3. Must not be broadcast IP (x.x.x.255)
    4. Must not be multicast IP (224-239.x.x.x)
    """
    # Rule 1: Validate MAC address
    if not mac or len(mac) < 17:
        return False
    mac_lower = mac.lower()
    if mac_lower in ('ff:ff:ff:ff:ff:ff', 'ff-ff-ff-ff-ff-ff'):
        return False
    if mac_lower in ('00:00:00:00:00:00', '00-00-00-00-00-00'):
        return False
    if mac_lower.startswith('01:00:5e:'):  # IPv4 multicast MAC
        return False
    if mac_lower.startswith('33:33:'):     # IPv6 multicast MAC
        return False

    # Rule 2: Validate IP format
    if not ip or '.' not in ip:
        return False

    # Rule 3: Must be in current subnet
    if current_subnet and not ip.startswith(current_subnet + '.'):
        return False

    # Rule 4: Reject broadcast IP
    if ip.endswith('.255'):
        return False

    # Rule 5: Reject network address
    if ip.endswith('.0'):
        return False

    # Rule 6: Reject multicast IP (224-239.x.x.x)
    try:
        first_octet = int(ip.split('.')[0])
        if 224 <= first_octet <= 239:
            return False
        if first_octet == 127:  # loopback
            return False
        if first_octet == 0:
            return False
    except (ValueError, IndexError):
        return False

    # Rule 7: Reject link-local
    if ip.startswith('169.254.'):
        return False

    return True


def get_current_subnet() -> Optional[str]:
    """
    Get current network subnet prefix (first 3 octets).

    Returns:
        Subnet prefix like "10.234.255", or ``None`` if the local IP
        could not be determined.  Callers MUST handle ``None`` gracefully
        (e.g. skip subnet-specific filtering).
    """
    subnet = _detect_subnet()
    return subnet or None


def _is_valid_mac(mac: Optional[str]) -> bool:
    """Quick check that *mac* is a real unicast MAC."""
    return _shared_is_valid_mac(mac)


# ---------------------------------------------------------------------------
# SQL fragments shared across queries
# ---------------------------------------------------------------------------

_PRIVATE_IP_FILTER_SOURCE = """
    source_ip LIKE '10.%'
    OR source_ip LIKE '192.168.%'
    OR source_ip LIKE '172.16.%' OR source_ip LIKE '172.17.%'
    OR source_ip LIKE '172.18.%' OR source_ip LIKE '172.19.%'
    OR source_ip LIKE '172.20.%' OR source_ip LIKE '172.21.%'
    OR source_ip LIKE '172.22.%' OR source_ip LIKE '172.23.%'
    OR source_ip LIKE '172.24.%' OR source_ip LIKE '172.25.%'
    OR source_ip LIKE '172.26.%' OR source_ip LIKE '172.27.%'
    OR source_ip LIKE '172.28.%' OR source_ip LIKE '172.29.%'
    OR source_ip LIKE '172.30.%' OR source_ip LIKE '172.31.%'
"""

_PRIVATE_IP_FILTER_DEST = """
    dest_ip LIKE '10.%'
    OR dest_ip LIKE '192.168.%'
    OR dest_ip LIKE '172.16.%' OR dest_ip LIKE '172.17.%'
    OR dest_ip LIKE '172.18.%' OR dest_ip LIKE '172.19.%'
    OR dest_ip LIKE '172.20.%' OR dest_ip LIKE '172.21.%'
    OR dest_ip LIKE '172.22.%' OR dest_ip LIKE '172.23.%'
    OR dest_ip LIKE '172.24.%' OR dest_ip LIKE '172.25.%'
    OR dest_ip LIKE '172.26.%' OR dest_ip LIKE '172.27.%'
    OR dest_ip LIKE '172.28.%' OR dest_ip LIKE '172.29.%'
    OR dest_ip LIKE '172.30.%' OR dest_ip LIKE '172.31.%'
"""

_VALID_MAC_FILTER_SOURCE = """
    source_mac IS NOT NULL
    AND source_mac != ''
    AND source_mac != 'ff:ff:ff:ff:ff:ff'
    AND source_mac != '00:00:00:00:00:00'
    AND source_mac NOT LIKE '01:00:5e:%'
    AND source_mac NOT LIKE '33:33:%'
"""

_VALID_MAC_FILTER_DEST = """
    dest_mac IS NOT NULL
    AND dest_mac != ''
    AND dest_mac != 'ff:ff:ff:ff:ff:ff'
    AND dest_mac != '00:00:00:00:00:00'
    AND dest_mac NOT LIKE '01:00:5e:%'
    AND dest_mac NOT LIKE '33:33:%'
"""

# For filtering the devices table — requires the IP to be a **private**
# (RFC 1918 / ULA) unicast address.  Public IPs, multicast, broadcast,
# loopback, link-local and special addresses are all excluded.
VALID_DEVICE_IP_FILTER = """
    (
        ip_address LIKE '10.%'
        OR ip_address LIKE '192.168.%'
        OR ip_address LIKE '172.16.%' OR ip_address LIKE '172.17.%'
        OR ip_address LIKE '172.18.%' OR ip_address LIKE '172.19.%'
        OR ip_address LIKE '172.20.%' OR ip_address LIKE '172.21.%'
        OR ip_address LIKE '172.22.%' OR ip_address LIKE '172.23.%'
        OR ip_address LIKE '172.24.%' OR ip_address LIKE '172.25.%'
        OR ip_address LIKE '172.26.%' OR ip_address LIKE '172.27.%'
        OR ip_address LIKE '172.28.%' OR ip_address LIKE '172.29.%'
        OR ip_address LIKE '172.30.%' OR ip_address LIKE '172.31.%'
        OR ip_address LIKE 'fd%'
        OR ip_address LIKE 'fc%'
    )
    AND ip_address NOT LIKE '%.255'
    AND ip_address NOT LIKE '%.0'
    AND ip_address != 'unknown'
"""

# Same filter expressed on ``COALESCE(ipv4_address, ip_address)`` for the
# devices-table leg of multi-source UNION queries.
_PRIVATE_IP_FILTER_DEVICE = """
    COALESCE(ipv4_address, ip_address) LIKE '10.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '192.168.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.16.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.17.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.18.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.19.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.20.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.21.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.22.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.23.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.24.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.25.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.26.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.27.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.28.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.29.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.30.%'
    OR COALESCE(ipv4_address, ip_address) LIKE '172.31.%'
    OR COALESCE(ipv4_address, ip_address) LIKE 'fd%'
    OR COALESCE(ipv4_address, ip_address) LIKE 'fc%'
"""

# ---------------------------------------------------------------------------
# THE SINGLE SOURCE OF TRUTH  —  device count
# ---------------------------------------------------------------------------

@time_query
def get_active_device_count(minutes: int = 5, conn=None) -> int:
    """
    **SINGLE SOURCE OF TRUTH** for the active-device count.

    Returns the number of unique **IP addresses** seen in the last *minutes*
    minutes whose associated IP is a **private** address AND in the
    current subnet.  Uses IP (not MAC) as the dedup key so that devices
    with randomised MACs are not double-counted.

    Used by:
    - Dashboard device-count display
    - Alert threshold checking
    - Health-score calculation
    - ``/api/v1/stats/realtime`` endpoint

    Parameters
    ----------
    minutes : int
        Look-back window (default 5).
    conn : sqlite3.Connection, optional
        An existing database connection to reuse.  When provided the
        function will **not** acquire a new connection from the pool,
        avoiding pool exhaustion when called from ``get_dashboard_data()``
        which already holds a connection.
    """
    cache_key = f"active_count_{minutes}"
    cached = _device_cache.get(cache_key)
    if cached is not None:
        return cached
    def _do_count(cursor):
        since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

        # Build optional subnet filter
        # Only port_mirror skips subnet filtering (sees ALL traffic).
        # Hotspot, ethernet, wifi_client and public_network all enforce
        # the subnet that was set by main.py for the current mode.
        current_subnet = _detect_subnet()
        skip_subnet = _current_mode_name == "port_mirror"
        subnet_filter_src = ""
        subnet_filter_dst = ""
        subnet_filter_dev = ""
        params_src = [since]
        params_dst = [since]
        params_dev = [since]
        if current_subnet and not skip_subnet:
            subnet_filter_src = "AND source_ip LIKE ?"
            subnet_filter_dst = "AND dest_ip LIKE ?"
            subnet_filter_dev = "AND ip_address LIKE ?"
            params_src.append(f"{current_subnet}.%")
            params_dst.append(f"{current_subnet}.%")
            params_dev.append(f"{current_subnet}.%")

        # Build exclusion list for gateway/own device
        try:
            from config import SHOW_OWN_DEVICE, SHOW_GATEWAY
        except ImportError:
            SHOW_OWN_DEVICE = True
            SHOW_GATEWAY = True

        excluded_ips: list = []
        if not SHOW_GATEWAY:
            gw = _get_gateway_ip()
            if gw:
                excluded_ips.append(gw)
            # Only exclude .1 as a common gateway fallback when
            # actual detection failed — do NOT exclude .2 which
            # could be a legitimate device.
            if not gw and current_subnet:
                excluded_ips.append(f"{current_subnet}.1")
        if not SHOW_OWN_DEVICE:
            our_ip = _detect_our_ip()
            if our_ip:
                excluded_ips.append(our_ip)

        exclude_clause = ""
        exclude_params: list = []
        if excluded_ips:
            placeholders = ",".join("?" for _ in excluded_ips)
            exclude_clause = f"WHERE ip_address NOT IN ({placeholders})"
            exclude_params = excluded_ips

        # Build active_mode filter for the devices table leg
        mode_filter_dev = ""
        if _current_mode_name:
            mode_filter_dev = "AND active_mode = ?"
            params_dev.append(_current_mode_name)

        cursor.execute(f"""
            SELECT COUNT(DISTINCT ip_address) AS count
            FROM (
                SELECT source_ip AS ip_address
                FROM traffic_summary
                WHERE timestamp >= ?
                    AND {_VALID_MAC_FILTER_SOURCE}
                    AND ({_PRIVATE_IP_FILTER_SOURCE})
                    {subnet_filter_src}
                UNION
                SELECT dest_ip AS ip_address
                FROM traffic_summary
                WHERE timestamp >= ?
                    AND {_VALID_MAC_FILTER_DEST}
                    AND ({_PRIVATE_IP_FILTER_DEST})
                    {subnet_filter_dst}
                UNION
                SELECT COALESCE(ipv4_address, ip_address) AS ip_address
                FROM devices
                WHERE last_seen >= ?
                    AND mac_address IS NOT NULL AND mac_address != ''
                    AND mac_address != 'ff:ff:ff:ff:ff:ff'
                    AND mac_address != '00:00:00:00:00:00'
                    AND {VALID_DEVICE_IP_FILTER}
                    AND ({_PRIVATE_IP_FILTER_DEVICE})
                    {subnet_filter_dev}
                    {mode_filter_dev}
            )
            {exclude_clause}
        """, (*params_src, *params_dst, *params_dev, *exclude_params))

        row = cursor.fetchone()
        return row["count"] if row else 0

    try:
        if conn is not None:
            result = _do_count(conn.cursor())
        else:
            with get_connection() as new_conn:
                result = _do_count(new_conn.cursor())
        _device_cache.set(cache_key, result)
        return result
    except sqlite3.Error as e:
        logger.error("get_active_device_count error: %s", e)
        return 0


# Alias kept for backward compatibility with callers that use get_device_count()
def get_device_count(minutes: int = 5) -> int:
    """Alias for :func:`get_active_device_count`."""
    return get_active_device_count(minutes)


# ---------------------------------------------------------------------------
# Packet / device save
# ---------------------------------------------------------------------------

def save_packet(packet_data: dict) -> Optional[int]:
    """
    Save a single packet and upsert its source/dest device.

    *Only private IPs* are inserted into the ``devices`` table so that
    public destinations (google.com, cloudflare.com …) never pollute the
    device list.
    """
    if not packet_data:
        return None

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            timestamp = packet_data.get("timestamp", datetime.now())
            if isinstance(timestamp, datetime):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            source_ip = packet_data.get("source_ip") or packet_data.get("src", "unknown")
            dest_ip = packet_data.get("dest_ip") or packet_data.get("dst", "unknown")
            source_mac = packet_data.get("source_mac")
            dest_mac = packet_data.get("dest_mac")
            source_port = packet_data.get("source_port")
            dest_port = packet_data.get("dest_port")
            protocol = packet_data.get("protocol", "UNKNOWN")
            raw_protocol = packet_data.get("raw_protocol", protocol)
            bytes_transferred = packet_data.get("bytes", 0)
            device_name = packet_data.get("device_name")
            vendor = packet_data.get("vendor")
            dest_vendor = packet_data.get("dest_vendor")
            direction = packet_data.get("direction", "unknown")

            # 1. Insert traffic record (always)
            cursor.execute("""
                INSERT INTO traffic_summary
                (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                 source_port, dest_port, protocol, raw_protocol,
                 bytes_transferred, device_name, vendor, direction)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                  source_port, dest_port, protocol, raw_protocol,
                  bytes_transferred, device_name, vendor, direction))

            record_id = cursor.lastrowid

            # 2. Upsert source device — ONLY if valid local device
            if _is_valid_device_for_insert(source_ip, source_mac):
                _is_ipv6_src = source_ip and ":" in source_ip
                cursor.execute("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         device_name, vendor,
                         first_seen, last_seen,
                         total_bytes_sent, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor       = COALESCE(excluded.vendor, vendor),
                        last_seen    = excluded.last_seen,
                        total_bytes_sent = total_bytes_sent + excluded.total_bytes_sent,
                        total_packets    = total_packets + 1,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, (source_mac, source_ip,
                      None if _is_ipv6_src else source_ip,
                      source_ip if _is_ipv6_src else None,
                      device_name, vendor,
                      timestamp, timestamp, bytes_transferred,
                      _current_mode_name, _current_mode_name))

            # 3. Upsert dest device — ONLY if valid local device
            if _is_valid_device_for_insert(dest_ip, dest_mac):
                _is_ipv6_dst = dest_ip and ":" in dest_ip
                cursor.execute("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         vendor,
                         first_seen, last_seen,
                         total_bytes_received, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        vendor      = COALESCE(excluded.vendor, vendor),
                        last_seen   = excluded.last_seen,
                        total_bytes_received = total_bytes_received + excluded.total_bytes_received,
                        total_packets        = total_packets + 1,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, (dest_mac, dest_ip,
                      None if _is_ipv6_dst else dest_ip,
                      dest_ip if _is_ipv6_dst else None,
                      dest_vendor,
                      timestamp, timestamp, bytes_transferred,
                      _current_mode_name, _current_mode_name))

            # 4. Update daily usage (inside the same transaction)
            if _is_valid_device_for_insert(source_ip, source_mac):
                _update_daily_usage_cursor(cursor, source_mac, source_ip, device_name, bytes_transferred, 0, 1)
            if _is_valid_device_for_insert(dest_ip, dest_mac):
                _update_daily_usage_cursor(cursor, dest_mac, dest_ip, None, 0, bytes_transferred, 0)

            # 5. IPv6 traffic attribution (same logic as save_packets_batch)
            src_is_ipv6 = source_ip and ":" in source_ip
            dst_is_ipv6 = dest_ip and ":" in dest_ip

            if src_is_ipv6 and source_mac:
                mac_to_ipv4 = _build_mac_to_ipv4(cursor)
                mapped_ip = mac_to_ipv4.get(source_mac.lower())
                if mapped_ip and _is_valid_device_for_insert(mapped_ip, source_mac):
                    cursor.execute("""
                        UPDATE devices SET
                            total_bytes_sent = total_bytes_sent + ?,
                            total_packets = total_packets + 1,
                            last_seen = ?,
                            ipv6_address = COALESCE(ipv6_address, ?)
                        WHERE mac_address = ?
                    """, (bytes_transferred, timestamp, source_ip, source_mac))
                    _update_daily_usage_cursor(
                        cursor, source_mac, mapped_ip,
                        device_name, bytes_transferred, 0, 1)

            if dst_is_ipv6 and dest_mac:
                if not src_is_ipv6:
                    mac_to_ipv4 = _build_mac_to_ipv4(cursor)
                mapped_ip = mac_to_ipv4.get(dest_mac.lower())
                if mapped_ip and _is_valid_device_for_insert(mapped_ip, dest_mac):
                    cursor.execute("""
                        UPDATE devices SET
                            total_bytes_received = total_bytes_received + ?,
                            total_packets = total_packets + 1,
                            last_seen = ?,
                            ipv6_address = COALESCE(ipv6_address, ?)
                        WHERE mac_address = ?
                    """, (bytes_transferred, timestamp, dest_ip, dest_mac))
                    _update_daily_usage_cursor(
                        cursor, dest_mac, mapped_ip,
                        None, 0, bytes_transferred, 0)

            conn.commit()

            return record_id

    except sqlite3.Error as e:
        logger.error("save_packet error: %s", e)
        return None
    except Exception as e:
        logger.error("Unexpected save_packet error: %s", e)
        return None


def _is_valid_device_for_insert(ip: str, mac: Optional[str]) -> bool:
    """
    Check if a device should be inserted into the devices table.

    Filters out:
    - Invalid / null MAC addresses (00:00:00:00:00:00)
    - Devices not in the current subnet (ALWAYS enforced)
    - Our own device (if SHOW_OWN_DEVICE is False)
    - Gateway IP (if SHOW_GATEWAY is False) — uses real gateway detection
    - Broadcast / multicast / loopback / link-local
    """
    try:
        from config import SHOW_OWN_DEVICE, SHOW_GATEWAY
    except ImportError:
        SHOW_OWN_DEVICE = True
        SHOW_GATEWAY = True

    if not is_private_ip(ip):
        return False
    if not _is_valid_mac(mac):
        return False

    # Subnet filtering — always enforced except in port_mirror mode
    # (port_mirror sees ALL traffic across subnets).
    # Hotspot mode now enforces its own subnet set by main.py.
    if _current_mode_name != "port_mirror":
        subnet = _detect_subnet()
        if subnet and not ip.startswith(subnet + "."):
            return False

    # Reject broadcast / network addresses
    if ip.endswith('.255') or ip.endswith('.0'):
        return False

    # Reject multicast (224-239.x.x.x)
    try:
        first_octet = int(ip.split('.')[0])
        if 224 <= first_octet <= 239:
            return False
    except (ValueError, IndexError):
        pass

    # Own device filter
    if not SHOW_OWN_DEVICE:
        our_ip = _detect_our_ip()
        if our_ip and ip == our_ip:
            return False

    # Gateway filter — detect real gateway IP, not just .1/.2
    if not SHOW_GATEWAY:
        gw = _get_gateway_ip()
        if gw and ip == gw:
            return False
        # Fallback: exclude .1 only when actual gateway was not detected
        if not gw:
            try:
                last_octet = int(ip.split('.')[-1])
                if last_octet == 1:
                    return False
            except (ValueError, IndexError):
                pass

    return True


def _is_multicast_or_broadcast(ip: str) -> bool:
    """Return True if *ip* is a multicast, broadcast, or IPv6 multicast address."""
    if not ip or ip == "unknown":
        return False
    if ":" in ip:
        # IPv6 multicast starts with ff
        return ip.lower().startswith("ff")
    try:
        parts = ip.split(".")
        first = int(parts[0])
        if 224 <= first <= 239:
            return True
        if ip == "255.255.255.255":
            return True
        if parts[3] == "255":
            return True
    except (ValueError, IndexError):
        pass
    return False


def save_packets_batch(packets: list) -> int:
    """
    Save multiple packets in a **single transaction** for performance.

    Only devices passing ``_is_valid_device_for_insert`` (private IP,
    valid MAC, correct subnet, not our own device) are inserted into
    the devices table.  Traffic records are always saved.

    Phase 3 optimization: traffic_summary rows are inserted via a single
    ``executemany()`` call (~10× faster than per-packet INSERT loops for
    typical batch sizes of 100–1000 packets).

    Phase 4 optimization: device UPSERTs, daily usage, and IPv6 attribution
    are pre-aggregated by MAC address and also use ``executemany()`` —
    reducing N per-packet UPSERTs down to (unique MACs) batch calls.

    Packets where **both** source and dest are multicast / broadcast are
    skipped entirely (they carry no useful device information).

    Returns the count of successfully saved packets.
    """
    if not packets:
        return 0

    saved = 0
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Pre-build MAC → IPv4 lookup for IPv6 traffic attribution
            mac_to_ipv4 = _build_mac_to_ipv4(cursor)

            # ---------------------------------------------------------------
            # Phase 3: Bulk INSERT traffic_summary via executemany()
            # ---------------------------------------------------------------
            traffic_rows = []
            normalized_packets = []  # parallel list of normalised dicts

            for pkt in packets:
                try:
                    timestamp = pkt.get("timestamp", datetime.now())
                    if isinstance(timestamp, datetime):
                        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                    source_ip = pkt.get("source_ip") or pkt.get("src", "unknown")
                    dest_ip = pkt.get("dest_ip") or pkt.get("dst", "unknown")

                    # Skip packets where BOTH endpoints are multicast/broadcast
                    # — they carry no useful device information.
                    if (_is_multicast_or_broadcast(source_ip)
                            and _is_multicast_or_broadcast(dest_ip)):
                        continue

                    source_mac = pkt.get("source_mac")
                    dest_mac = pkt.get("dest_mac")
                    source_port = pkt.get("source_port")
                    dest_port = pkt.get("dest_port")
                    protocol = pkt.get("protocol", "UNKNOWN")
                    raw_protocol = pkt.get("raw_protocol", protocol)
                    bytes_transferred = pkt.get("bytes", 0)
                    device_name = pkt.get("device_name")
                    vendor = pkt.get("vendor")
                    dest_vendor = pkt.get("dest_vendor")
                    direction = pkt.get("direction", "unknown")

                    traffic_rows.append((
                        timestamp, source_ip, dest_ip, source_mac, dest_mac,
                        source_port, dest_port, protocol, raw_protocol,
                        bytes_transferred, device_name, vendor, direction,
                    ))
                    normalized_packets.append({
                        "timestamp": timestamp,
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "source_mac": source_mac,
                        "dest_mac": dest_mac,
                        "source_port": source_port,
                        "dest_port": dest_port,
                        "protocol": protocol,
                        "raw_protocol": raw_protocol,
                        "bytes": bytes_transferred,
                        "device_name": device_name,
                        "vendor": vendor,
                        "dest_vendor": dest_vendor,
                        "direction": direction,
                    })
                except Exception as e:
                    logger.warning("Error normalizing packet for batch: %s", e)

            # Bulk traffic_summary insert
            if traffic_rows:
                cursor.executemany("""
                    INSERT INTO traffic_summary
                    (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                     source_port, dest_port, protocol, raw_protocol,
                     bytes_transferred, device_name, vendor, direction)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, traffic_rows)
                saved = len(traffic_rows)

            # ---------------------------------------------------------------
            # Phase 4: Pre-aggregate device data by MAC, then batch UPSERT
            # ---------------------------------------------------------------
            # Collect per-MAC aggregations to reduce N individual UPSERTs
            # to at most 2 × (unique MACs) executemany calls.
            src_agg: dict = {}   # mac -> {bytes, packets, ip, ipv4, ipv6, name, vendor, ts}
            dst_agg: dict = {}   # mac -> {bytes, packets, ip, ipv4, ipv6, vendor, ts}
            daily_agg: dict = {} # (mac, ip, role) -> {sent, recv, pkts, name}
            ipv6_src_agg: dict = {}  # mac -> {bytes, ts, ipv6}
            ipv6_dst_agg: dict = {}  # mac -> {bytes, ts, ipv6}

            for npkt in normalized_packets:
                try:
                    timestamp = npkt["timestamp"]
                    source_ip = npkt["source_ip"]
                    dest_ip = npkt["dest_ip"]
                    source_mac = npkt["source_mac"]
                    dest_mac = npkt["dest_mac"]
                    bytes_transferred = npkt["bytes"]
                    device_name = npkt["device_name"]
                    vendor = npkt["vendor"]
                    dest_vendor = npkt["dest_vendor"]

                    # Source device — only valid local devices
                    if _is_valid_device_for_insert(source_ip, source_mac):
                        is_ipv6 = source_ip and ":" in source_ip
                        agg = src_agg.get(source_mac)
                        if agg is None:
                            agg = {"bytes": 0, "packets": 0, "ip": source_ip,
                                   "ipv4": None if is_ipv6 else source_ip,
                                   "ipv6": source_ip if is_ipv6 else None,
                                   "name": device_name, "vendor": vendor, "ts": timestamp}
                            src_agg[source_mac] = agg
                        agg["bytes"] += bytes_transferred
                        agg["packets"] += 1
                        agg["ts"] = timestamp  # keep latest
                        if not is_ipv6:
                            agg["ipv4"] = source_ip
                            agg["ip"] = source_ip
                        elif is_ipv6:
                            agg["ipv6"] = source_ip
                        if device_name and not agg["name"]:
                            agg["name"] = device_name
                        if vendor and not agg["vendor"]:
                            agg["vendor"] = vendor

                        # Daily usage aggregation (source)
                        dk = (source_mac, source_ip, "src")
                        du = daily_agg.get(dk)
                        if du is None:
                            du = {"sent": 0, "recv": 0, "pkts": 0, "name": device_name}
                            daily_agg[dk] = du
                        du["sent"] += bytes_transferred
                        du["pkts"] += 1

                    # Dest device — only valid local devices
                    if _is_valid_device_for_insert(dest_ip, dest_mac):
                        is_ipv6 = dest_ip and ":" in dest_ip
                        agg = dst_agg.get(dest_mac)
                        if agg is None:
                            agg = {"bytes": 0, "packets": 0, "ip": dest_ip,
                                   "ipv4": None if is_ipv6 else dest_ip,
                                   "ipv6": dest_ip if is_ipv6 else None,
                                   "vendor": dest_vendor, "ts": timestamp}
                            dst_agg[dest_mac] = agg
                        agg["bytes"] += bytes_transferred
                        agg["packets"] += 1
                        agg["ts"] = timestamp
                        if not is_ipv6:
                            agg["ipv4"] = dest_ip
                            agg["ip"] = dest_ip
                        elif is_ipv6:
                            agg["ipv6"] = dest_ip
                        if dest_vendor and not agg["vendor"]:
                            agg["vendor"] = dest_vendor

                        # Daily usage aggregation (dest)
                        dk = (dest_mac, dest_ip, "dst")
                        du = daily_agg.get(dk)
                        if du is None:
                            du = {"sent": 0, "recv": 0, "pkts": 0, "name": None}
                            daily_agg[dk] = du
                        du["recv"] += bytes_transferred

                    # IPv6 traffic attribution aggregation
                    src_is_ipv6 = source_ip and ":" in source_ip
                    dst_is_ipv6 = dest_ip and ":" in dest_ip

                    if src_is_ipv6 and source_mac:
                        mapped_ip = mac_to_ipv4.get(source_mac.lower())
                        if mapped_ip and _is_valid_device_for_insert(mapped_ip, source_mac):
                            agg = ipv6_src_agg.get(source_mac)
                            if agg is None:
                                agg = {"bytes": 0, "ts": timestamp, "ipv6": source_ip, "mapped_ip": mapped_ip, "name": device_name}
                                ipv6_src_agg[source_mac] = agg
                            agg["bytes"] += bytes_transferred
                            agg["ts"] = timestamp

                            dk = (source_mac, mapped_ip, "src")
                            du = daily_agg.get(dk)
                            if du is None:
                                du = {"sent": 0, "recv": 0, "pkts": 0, "name": device_name}
                                daily_agg[dk] = du
                            du["sent"] += bytes_transferred
                            du["pkts"] += 1

                    if dst_is_ipv6 and dest_mac:
                        mapped_ip = mac_to_ipv4.get(dest_mac.lower())
                        if mapped_ip and _is_valid_device_for_insert(mapped_ip, dest_mac):
                            agg = ipv6_dst_agg.get(dest_mac)
                            if agg is None:
                                agg = {"bytes": 0, "ts": timestamp, "ipv6": dest_ip, "mapped_ip": mapped_ip}
                                ipv6_dst_agg[dest_mac] = agg
                            agg["bytes"] += bytes_transferred
                            agg["ts"] = timestamp

                            dk = (dest_mac, mapped_ip, "dst")
                            du = daily_agg.get(dk)
                            if du is None:
                                du = {"sent": 0, "recv": 0, "pkts": 0, "name": None}
                                daily_agg[dk] = du
                            du["recv"] += bytes_transferred

                except Exception as e:
                    logger.warning("Error aggregating packet in batch: %s", e)
                    continue

            # Batch source device UPSERTs
            if src_agg:
                src_rows = []
                for mac, a in src_agg.items():
                    src_rows.append((mac, a["ip"], a["ipv4"], a["ipv6"],
                                     a["name"], a["vendor"],
                                     a["ts"], a["ts"], a["bytes"],
                                     a["packets"],
                                     _current_mode_name, _current_mode_name))
                cursor.executemany("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         device_name, vendor,
                         first_seen, last_seen,
                         total_bytes_sent, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor       = COALESCE(excluded.vendor, vendor),
                        last_seen    = excluded.last_seen,
                        total_bytes_sent = total_bytes_sent + excluded.total_bytes_sent,
                        total_packets    = total_packets + excluded.total_packets,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, src_rows)

            # Batch dest device UPSERTs
            if dst_agg:
                dst_rows = []
                for mac, a in dst_agg.items():
                    dst_rows.append((mac, a["ip"], a["ipv4"], a["ipv6"],
                                     a["vendor"],
                                     a["ts"], a["ts"], a["bytes"],
                                     a["packets"],
                                     _current_mode_name, _current_mode_name))
                cursor.executemany("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         vendor,
                         first_seen, last_seen,
                         total_bytes_received, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        vendor      = COALESCE(excluded.vendor, vendor),
                        last_seen   = excluded.last_seen,
                        total_bytes_received = total_bytes_received + excluded.total_bytes_received,
                        total_packets        = total_packets + excluded.total_packets,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, dst_rows)

            # Batch IPv6 source attribution
            if ipv6_src_agg:
                ipv6_src_rows = [(a["bytes"], a["ts"], a["ipv6"], mac)
                                 for mac, a in ipv6_src_agg.items()]
                cursor.executemany("""
                    UPDATE devices SET
                        total_bytes_sent = total_bytes_sent + ?,
                        total_packets = total_packets + 1,
                        last_seen = ?,
                        ipv6_address = COALESCE(ipv6_address, ?)
                    WHERE mac_address = ?
                """, ipv6_src_rows)

            # Batch IPv6 dest attribution
            if ipv6_dst_agg:
                ipv6_dst_rows = [(a["bytes"], a["ts"], a["ipv6"], mac)
                                 for mac, a in ipv6_dst_agg.items()]
                cursor.executemany("""
                    UPDATE devices SET
                        total_bytes_received = total_bytes_received + ?,
                        total_packets = total_packets + 1,
                        last_seen = ?,
                        ipv6_address = COALESCE(ipv6_address, ?)
                    WHERE mac_address = ?
                """, ipv6_dst_rows)

            # Batch daily usage UPSERTs
            if daily_agg:
                today = datetime.now().strftime("%Y-%m-%d")
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                daily_rows = []
                for (mac, ip, _role), du in daily_agg.items():
                    total = du["sent"] + du["recv"]
                    daily_rows.append((
                        today, mac, ip, du["name"],
                        du["sent"], du["recv"], total, du["pkts"],
                        now_str, now_str,
                    ))
                cursor.executemany("""
                    INSERT INTO daily_usage
                    (date, mac_address, ip_address, device_name,
                     bytes_sent, bytes_received, total_bytes, packet_count,
                     first_seen_today, last_seen_today)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(date, mac_address) DO UPDATE SET
                        ip_address   = COALESCE(excluded.ip_address, ip_address),
                        device_name  = COALESCE(excluded.device_name, device_name),
                        bytes_sent     = bytes_sent     + excluded.bytes_sent,
                        bytes_received = bytes_received + excluded.bytes_received,
                        total_bytes    = total_bytes    + excluded.total_bytes,
                        packet_count   = packet_count   + excluded.packet_count,
                        last_seen_today = excluded.last_seen_today
                """, daily_rows)

            conn.commit()

        # Periodic WAL checkpoint after large batches to prevent the
        # write-ahead log from growing unboundedly, which would degrade
        # read latency on subsequent dashboard queries.
        if saved >= 20:
            try:
                from database.connection import wal_checkpoint
                wal_checkpoint("PASSIVE")
            except Exception:
                pass  # non-critical

    except sqlite3.Error as e:
        logger.error("Batch save error: %s", e)

    return saved


# ---------------------------------------------------------------------------
# Device queries
# ---------------------------------------------------------------------------

def _resolve_and_persist_hostname(d: dict, conn=None) -> dict:
    """
    Resolve hostname for a device dict and persist it to the devices table
    so subsequent queries don't need to re-resolve.

    IMPORTANT: Always checks the ``devices`` table first for a user-set
    hostname (set via the UI edit button). User-set names take priority
    over DNS resolution and are never overwritten.

    Args:
        d: Device dict to enrich with hostname.
        conn: Optional existing SQLite connection to reuse.  When provided
              the function will NOT open its own connection — this prevents
              pool exhaustion from nested ``get_connection()`` calls.
    """
    if not d:
        return d

    ip = d.get("ip_address", "")
    mac = d.get("mac_address", "")

    # 1. Check the devices table for a user-set hostname / device_name
    try:
        def _check_db(c):
            cursor = c.cursor()
            cursor.execute("""
                SELECT hostname, device_name FROM devices
                WHERE ip_address = ? OR ipv4_address = ? OR mac_address = ?
                LIMIT 1
            """, (ip, ip, mac))
            return cursor.fetchone()

        if conn is not None:
            row = _check_db(conn)
        else:
            with get_connection() as _conn:
                row = _check_db(_conn)

        if row:
            db_hostname = (row["hostname"] if isinstance(row, dict)
                           else row[0]) or ""
            db_device_name = (row["device_name"] if isinstance(row, dict)
                              else row[1]) or ""
            user_name = db_hostname or db_device_name
            if user_name and user_name != ip and user_name != "unknown":
                d["hostname"] = user_name
                return d
    except Exception:
        pass  # Fall through to existing logic

    # 2. Already have a meaningful hostname from the query result
    existing_name = d.get("device_name") or d.get("hostname")
    if existing_name and existing_name != ip and existing_name != "unknown":
        d["hostname"] = existing_name
        return d

    # 3. Try hostname resolution via DNS / MAC vendor
    try:
        from packet_capture.hostname_resolver import resolve_hostname
        resolved = resolve_hostname(ip, mac)
    except Exception:
        resolved = ip

    d["hostname"] = resolved

    # Persist to devices table if we got a real hostname (not just the IP)
    if resolved and resolved != ip:
        try:
            def _persist(c):
                cursor = c.cursor()
                cursor.execute("""
                    UPDATE devices
                    SET hostname = CASE
                            WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                            THEN ? ELSE hostname END
                    WHERE ip_address = ? OR ipv4_address = ? OR mac_address = ?
                """, (resolved, ip, ip, mac))
                c.commit()

            if conn is not None:
                _persist(conn)
            else:
                with get_connection() as _conn:
                    _persist(_conn)
        except Exception:
            pass  # Don't fail the query just because persist failed

    return d

@time_query
def get_active_devices(minutes: int = 5, limit: int = 100) -> list:
    """
    Return active devices using the **same filter** as
    ``get_active_device_count`` so that counts always match.
    Includes subnet filtering to only show devices on current network.
    Also merges in devices from the ``devices`` table (populated by ARP
    scans) that were seen recently, so that ARP-discovered devices show
    up even when their traffic doesn't carry MAC addresses (common on
    Windows WiFi captures).
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

            # Build subnet filter — only port_mirror skips subnet filtering.
            # (same logic as get_active_device_count)
            current_subnet = _detect_subnet()
            skip_subnet = _current_mode_name == "port_mirror"
            subnet_filter_dev = ""
            params_src = [since]
            params_dst = [since]
            params_dev = [since]
            if current_subnet and not skip_subnet:
                ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) AND source_ip LIKE ? OR source_ip LIKE '%:%')"
                ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) AND dest_ip LIKE ? OR dest_ip LIKE '%:%')"
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_src.append(f"{current_subnet}.%")
                params_dst.append(f"{current_subnet}.%")
                params_dev.append(f"{current_subnet}.%")
            else:
                ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')"
                ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')"

            # Build active_mode filter for the devices union leg
            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            cursor.execute(f"""
                WITH all_devices AS (
                    SELECT source_mac AS mac_address, source_ip AS ip_address,
                           device_name, vendor,
                           bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        {ip_filter_src}
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL,
                           0, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_DEST}
                        {ip_filter_dst}
                    UNION ALL
                    SELECT mac_address,
                           COALESCE(ipv4_address, ip_address) AS ip_address,
                           COALESCE(hostname, device_name) AS device_name, vendor,
                           0, 0, last_seen AS timestamp
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        AND ({_PRIVATE_IP_FILTER_DEVICE})
                        {subnet_filter_dev}
                        {mode_filter_dev}
                )
                SELECT
                    mac_address,
                    COALESCE(
                        MAX(CASE WHEN ip_address NOT LIKE '%:%' THEN ip_address END),
                        MAX(ip_address)
                    ) AS ip_address,
                    MAX(device_name) AS device_name,
                    MAX(vendor) AS vendor,
                    COUNT(*)        AS packet_count,
                    SUM(bytes_sent)      AS bytes_sent,
                    SUM(bytes_received)  AS bytes_received,
                    SUM(bytes_sent) + SUM(bytes_received) AS total_bytes,
                    MAX(timestamp) AS last_seen,
                    MIN(timestamp) AS first_seen
                FROM all_devices
                GROUP BY mac_address
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (*params_src, *params_dst, *params_dev, limit))

            devices = []
            for row in cursor.fetchall():
                d = dict_from_row(row)
                if d:
                    # Read hostname from DB only — no active resolution
                    # (background resolver handles hostname IS NULL devices)
                    existing_name = d.get("device_name") or d.get("hostname")
                    ip_d = d.get("ip_address", "")
                    if existing_name and existing_name != ip_d and existing_name != "unknown":
                        d["hostname"] = existing_name
                    else:
                        d["hostname"] = ip_d
                    d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))
                    devices.append(d)

            # MAC-primary keying means no IP-based dedup needed
            return devices

    except sqlite3.Error as e:
        logger.error("get_active_devices error: %s", e)
        return []


@time_query
def get_all_devices(limit: int = 100, offset: int = 0, hours: int = 24) -> list:
    """
    Same logic as ``get_active_devices`` but with a wider time window
    (default 24 h) and pagination support.
    Includes subnet filtering to only show devices on current network.
    In port_mirror mode, subnet filtering is skipped.
    Also merges in devices from the ``devices`` table (populated by ARP
    scans) so ARP-discovered devices appear even when traffic_summary
    lacks their MAC addresses.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Build subnet filter — only port_mirror skips subnet filtering.
            current_subnet = _detect_subnet()
            skip_subnet = _current_mode_name == "port_mirror"
            subnet_filter_dev = ""
            params_src = [since]
            params_dst = [since]
            params_dev = [since]
            if current_subnet and not skip_subnet:
                ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) AND source_ip LIKE ? OR source_ip LIKE '%:%')"
                ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) AND dest_ip LIKE ? OR dest_ip LIKE '%:%')"
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_src.append(f"{current_subnet}.%")
                params_dst.append(f"{current_subnet}.%")
                params_dev.append(f"{current_subnet}.%")
            else:
                ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')"
                ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')"

            # Build active_mode filter for the devices union leg
            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            cursor.execute(f"""
                WITH all_devices AS (
                    SELECT source_mac AS mac_address, source_ip AS ip_address,
                           device_name, vendor,
                           bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        {ip_filter_src}
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL,
                           0, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_DEST}
                        {ip_filter_dst}
                    UNION ALL
                    SELECT mac_address,
                           COALESCE(ipv4_address, ip_address) AS ip_address,
                           COALESCE(hostname, device_name) AS device_name, vendor,
                           0, 0, last_seen AS timestamp
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        AND ({_PRIVATE_IP_FILTER_DEVICE})
                        {subnet_filter_dev}
                        {mode_filter_dev}
                )
                SELECT
                    mac_address,
                    COALESCE(
                        MAX(CASE WHEN ip_address NOT LIKE '%:%' THEN ip_address END),
                        MAX(ip_address)
                    ) AS ip_address,
                    MAX(device_name) AS device_name,
                    MAX(vendor) AS vendor,
                    COUNT(*)        AS packet_count,
                    SUM(bytes_sent)      AS bytes_sent,
                    SUM(bytes_received)  AS bytes_received,
                    SUM(bytes_sent) + SUM(bytes_received) AS total_bytes,
                    MAX(timestamp) AS last_seen,
                    MIN(timestamp) AS first_seen
                FROM all_devices
                GROUP BY mac_address
                ORDER BY total_bytes DESC
                LIMIT ? OFFSET ?
            """, (*params_src, *params_dst, *params_dev, limit, offset))

            devices = []
            for row in cursor.fetchall():
                d = dict_from_row(row)
                if d:
                    # Read hostname from DB only — no active resolution
                    # (background resolver handles hostname IS NULL devices)
                    existing_name = d.get("device_name") or d.get("hostname")
                    ip_d = d.get("ip_address", "")
                    if existing_name and existing_name != ip_d and existing_name != "unknown":
                        d["hostname"] = existing_name
                    else:
                        d["hostname"] = ip_d
                    d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))
                    devices.append(d)

            # MAC-primary keying means no IP-based dedup needed
            return devices[:limit]

    except sqlite3.Error as e:
        logger.error("get_all_devices error: %s", e)
        return []


@time_query
def get_top_devices(limit: int = 10, hours: int = 1) -> list:
    """Top devices by traffic volume — same filter as ``get_all_devices``.
    Includes subnet filtering to only show devices on current network.
    In port_mirror mode, subnet filtering is skipped.
    Also merges in devices from the ``devices`` table.

    Optimised to batch hostname + today_usage lookups instead of
    issuing N+1 queries per device row."""
    cache_key = f"top_devices_{limit}_{hours}"
    cached = _device_cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Build subnet filter — only port_mirror skips subnet filtering.
            current_subnet = _detect_subnet()
            skip_subnet = _current_mode_name == "port_mirror"
            subnet_filter_dev = ""
            params_src = [since]
            params_dst = [since]
            params_dev = [since]
            if current_subnet and not skip_subnet:
                # Include IPv6 rows (they bypass the private-IP + subnet check)
                ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) AND source_ip LIKE ? OR source_ip LIKE '%:%')"
                ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) AND dest_ip LIKE ? OR dest_ip LIKE '%:%')"
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_src.append(f"{current_subnet}.%")
                params_dst.append(f"{current_subnet}.%")
                params_dev.append(f"{current_subnet}.%")
            else:
                ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')"
                ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')"

            # Build active_mode filter for the devices union leg
            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            cursor.execute(f"""
                WITH all_devices AS (
                    SELECT source_mac AS mac_address, source_ip AS ip_address,
                           device_name, vendor,
                           bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        {ip_filter_src}
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL,
                           0, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_DEST}
                        {ip_filter_dst}
                    UNION ALL
                    SELECT mac_address,
                           COALESCE(ipv4_address, ip_address) AS ip_address,
                           COALESCE(hostname, device_name) AS device_name, vendor,
                           0, 0, last_seen AS timestamp
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        AND ({_PRIVATE_IP_FILTER_DEVICE})
                        {subnet_filter_dev}
                        {mode_filter_dev}
                )
                SELECT
                    mac_address,
                    COALESCE(
                        MAX(CASE WHEN ip_address NOT LIKE '%:%' THEN ip_address END),
                        MAX(ip_address)
                    ) AS ip_address,
                    MAX(device_name)    AS device_name,
                    MAX(vendor)         AS vendor,
                    COUNT(*)            AS packet_count,
                    SUM(bytes_sent)     AS bytes_sent,
                    SUM(bytes_received) AS bytes_received,
                    SUM(bytes_sent) + SUM(bytes_received) AS total_bytes,
                    MAX(timestamp)      AS last_seen,
                    MIN(timestamp)      AS first_seen
                FROM all_devices
                GROUP BY mac_address
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (*params_src, *params_dst, *params_dev, limit))

            results = []
            for row in cursor.fetchall():
                d = dict_from_row(row)
                if d:
                    results.append(d)

            if not results:
                return []

            # --- Batch hostname resolution (1 query instead of N) ---
            mac_list = [d.get("mac_address", "") for d in results if d.get("mac_address")]
            ip_list = [d.get("ip_address", "") for d in results if d.get("ip_address")]
            db_hostnames: dict = {}  # key: (ip, mac) -> hostname
            if mac_list or ip_list:
                try:
                    placeholders_mac = ",".join("?" for _ in mac_list)
                    placeholders_ip = ",".join("?" for _ in ip_list)
                    where_parts = []
                    params_hn: list = []
                    if mac_list:
                        where_parts.append(f"mac_address IN ({placeholders_mac})")
                        params_hn.extend(mac_list)
                    if ip_list:
                        where_parts.append(f"ip_address IN ({placeholders_ip})")
                        params_hn.extend(ip_list)
                    cursor.execute(f"""
                        SELECT ip_address, mac_address, hostname, device_name
                        FROM devices WHERE {" OR ".join(where_parts)}
                    """, params_hn)
                    for r in cursor.fetchall():
                        ip_r = r["ip_address"] or ""
                        mac_r = r["mac_address"] or ""
                        name = r["hostname"] or r["device_name"] or ""
                        if name and name != ip_r and name != "unknown":
                            db_hostnames[mac_r] = name
                            db_hostnames[ip_r] = name
                except Exception:
                    pass  # fall through — hostname will be IP

            for d in results:
                # Apply batched hostname
                existing_name = d.get("device_name") or d.get("hostname")
                ip_d = d.get("ip_address", "")
                mac_d = d.get("mac_address", "")
                resolved = (
                    db_hostnames.get(mac_d)
                    or db_hostnames.get(ip_d)
                    or existing_name
                    or ip_d
                )
                d["hostname"] = resolved

            # --- Batch today usage (1 query instead of N) ---
            today_str = datetime.now().strftime("%Y-%m-%d")
            today_map: dict = {}  # mac -> {today_bytes, ...}
            if mac_list:
                try:
                    ph = ",".join("?" for _ in mac_list)
                    cursor.execute(f"""
                        SELECT mac_address, total_bytes, bytes_sent, bytes_received, packet_count
                        FROM daily_usage
                        WHERE date = ? AND mac_address IN ({ph})
                    """, (today_str, *mac_list))
                    for r in cursor.fetchall():
                        today_map[r["mac_address"]] = {
                            "today_bytes": r["total_bytes"] or 0,
                            "today_sent": r["bytes_sent"] or 0,
                            "today_received": r["bytes_received"] or 0,
                        }
                except Exception:
                    pass

            for d in results:
                mac = d.get("mac_address", "")
                tu = today_map.get(mac, {})
                d["today_bytes"] = tu.get("today_bytes", 0)
                d["today_sent"] = tu.get("today_sent", 0)
                d["today_received"] = tu.get("today_received", 0)

            # MAC-primary keying means no IP-based dedup needed
            _device_cache.set(cache_key, results)
            return results

    except sqlite3.Error as e:
        logger.error("get_top_devices error: %s", e)
        return []


def get_device_by_ip(ip_address: str) -> Optional[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM devices WHERE ip_address = ? OR ipv4_address = ? OR ipv6_address = ?",
                (ip_address, ip_address, ip_address),
            )
            return dict_from_row(cursor.fetchone())
    except sqlite3.Error as e:
        logger.error("get_device_by_ip error: %s", e)
        return None


def get_device_by_mac(mac_address: str) -> Optional[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
            return dict_from_row(cursor.fetchone())
    except sqlite3.Error as e:
        logger.error("get_device_by_mac error: %s", e)
        return None


def update_device_name(ip_address: str, new_name: str) -> bool:
    """Update hostname for a device. Accepts IP or MAC."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # Try IP first — search ip_address and ipv4_address
            cursor.execute(
                "UPDATE devices SET hostname = ?, device_name = ? WHERE ip_address = ? OR ipv4_address = ?",
                (new_name, new_name, ip_address, ip_address),
            )
            if cursor.rowcount == 0:
                # Try MAC address
                cursor.execute(
                    "UPDATE devices SET hostname = ?, device_name = ? WHERE mac_address = ?",
                    (new_name, new_name, ip_address),
                )
            if cursor.rowcount == 0:
                # Device not in devices table — try inserting from traffic_summary data
                cursor.execute("""
                    SELECT source_mac FROM traffic_summary
                    WHERE source_ip = ? AND source_mac IS NOT NULL AND source_mac != ''
                          AND source_mac != 'ff:ff:ff:ff:ff:ff'
                    ORDER BY timestamp DESC LIMIT 1
                """, (ip_address,))
                row = cursor.fetchone()
                if row:
                    mac = row["source_mac"] if isinstance(row, dict) else row[0]
                    _is_ipv6 = ip_address and ":" in ip_address
                    cursor.execute("""
                        INSERT INTO devices (mac_address, ip_address, ipv4_address, ipv6_address,
                                             hostname, device_name, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                        ON CONFLICT(mac_address) DO UPDATE SET
                            hostname = excluded.hostname,
                            device_name = excluded.device_name
                    """, (mac, ip_address,
                          None if _is_ipv6 else ip_address,
                          ip_address if _is_ipv6 else None,
                          new_name, new_name))
                else:
                    logger.warning("update_device_name: no device found for %s", ip_address)
                    return False
            conn.commit()
            logger.info("Device name updated: %s -> %s", ip_address, new_name)
            return True
    except sqlite3.Error as e:
        logger.error("update_device_name error: %s", e)
        return False


@time_query
def get_device_details(ip_address: str) -> Optional[dict]:
    """Detailed view of a single device including 24 h traffic and recent alerts.
    
    Falls back to building device info from traffic_summary if the device
    isn't in the devices table (e.g. own device when SHOW_OWN_DEVICE=False).

    Optimised: All queries use time-bounded windows and LIMIT clauses to
    ensure response times <200 ms even with 100k+ traffic records.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM devices WHERE ip_address = ? OR ipv4_address = ? OR ipv6_address = ?",
                (ip_address, ip_address, ip_address),
            )
            row = cursor.fetchone()

            if row:
                device = dict_from_row(row)
            else:
                # Fallback: build device info from traffic_summary (limited to 24h)
                since_fb = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(f"""
                    WITH dev AS (
                        SELECT source_mac AS mac_address, source_ip AS ip_address,
                               device_name, vendor,
                               bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                        FROM traffic_summary
                        WHERE source_ip = ? AND timestamp >= ?
                            AND {_VALID_MAC_FILTER_SOURCE}
                        UNION ALL
                        SELECT dest_mac, dest_ip, NULL, NULL,
                               0, bytes_transferred, timestamp
                        FROM traffic_summary
                        WHERE dest_ip = ? AND timestamp >= ?
                            AND {_VALID_MAC_FILTER_DEST}
                    )
                    SELECT
                        MAX(mac_address) AS mac_address,
                        ? AS ip_address,
                        MAX(device_name) AS device_name,
                        MAX(vendor) AS vendor,
                        MIN(timestamp) AS first_seen,
                        MAX(timestamp) AS last_seen,
                        SUM(bytes_sent) AS total_bytes_sent,
                        SUM(bytes_received) AS total_bytes_received,
                        COUNT(*) AS total_packets
                    FROM dev
                """, (ip_address, since_fb, ip_address, since_fb, ip_address))
                fallback_row = cursor.fetchone()
                if not fallback_row or not (dict_from_row(fallback_row) or {}).get('mac_address'):
                    return None
                device = dict_from_row(fallback_row)
                device['hostname'] = device.get('device_name') or ip_address
                device['total_bytes'] = (device.get('total_bytes_sent') or 0) + (device.get('total_bytes_received') or 0)

            # Resolve hostname if missing and persist it
            _resolve_and_persist_hostname(device, conn=conn)

            since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

            # 24h traffic aggregation — use UNION ALL for index usage
            cursor.execute("""
                SELECT
                    SUM(bytes_transferred) AS total_bytes_24h,
                    COUNT(*) AS packet_count_24h
                FROM (
                    SELECT bytes_transferred FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                    UNION ALL
                    SELECT bytes_transferred FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                )
            """, (ip_address, since, ip_address, since))
            traffic = cursor.fetchone()
            device["total_bytes_24h"] = (traffic["total_bytes_24h"] or 0) if traffic else 0
            device["packet_count_24h"] = (traffic["packet_count_24h"] or 0) if traffic else 0

            # Protocol breakdown (last 24h, top 20 only)
            cursor.execute("""
                SELECT protocol, COUNT(*) AS count, SUM(bytes_transferred) AS bytes
                FROM (
                    SELECT protocol, bytes_transferred FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                    UNION ALL
                    SELECT protocol, bytes_transferred FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                )
                GROUP BY protocol ORDER BY bytes DESC
                LIMIT 20
            """, (ip_address, since, ip_address, since))
            device["protocols"] = [dict_from_row(r) for r in cursor.fetchall()]

            # Recent alerts (last 5)
            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, message
                FROM alerts WHERE source_ip = ?
                ORDER BY timestamp DESC LIMIT 5
            """, (ip_address,))
            device["recent_alerts"] = [dict_from_row(r) for r in cursor.fetchall()]

            # Compute total_bytes if not present
            if 'total_bytes' not in device:
                device['total_bytes'] = (device.get('total_bytes_sent') or 0) + (device.get('total_bytes_received') or 0)

            return device

    except sqlite3.Error as e:
        logger.error("get_device_details error: %s", e)
        return None


# ---------------------------------------------------------------------------
# Daily usage helpers
# ---------------------------------------------------------------------------

def update_daily_usage(mac_address: str, ip_address: str, device_name: Optional[str],
                       bytes_sent: int, bytes_received: int, packet_count: int = 1) -> bool:
    if not mac_address:
        return False
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            _update_daily_usage_cursor(cursor, mac_address, ip_address,
                                       device_name, bytes_sent, bytes_received, packet_count)
            conn.commit()
            return True
    except sqlite3.Error as e:
        logger.error("update_daily_usage error: %s", e)
        return False


def _update_daily_usage_cursor(cursor, mac_address, ip_address, device_name,
                                bytes_sent, bytes_received, packet_count):
    """Inner helper that works on an existing cursor (no commit)."""
    today = datetime.now().strftime("%Y-%m-%d")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_bytes = bytes_sent + bytes_received
    cursor.execute("""
        INSERT INTO daily_usage
        (date, mac_address, ip_address, device_name, bytes_sent, bytes_received,
         total_bytes, packet_count, first_seen_today, last_seen_today)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(date, mac_address) DO UPDATE SET
            ip_address   = COALESCE(excluded.ip_address, ip_address),
            device_name  = COALESCE(excluded.device_name, device_name),
            bytes_sent     = bytes_sent     + excluded.bytes_sent,
            bytes_received = bytes_received + excluded.bytes_received,
            total_bytes    = total_bytes    + excluded.total_bytes,
            packet_count   = packet_count   + excluded.packet_count,
            last_seen_today = excluded.last_seen_today
    """, (today, mac_address, ip_address, device_name, bytes_sent, bytes_received,
          total_bytes, packet_count, now, now))


def get_daily_usage(date: str = None, mac_address: str = None) -> list:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if date is None:
                date = datetime.now().strftime("%Y-%m-%d")
            if mac_address:
                cursor.execute("SELECT * FROM daily_usage WHERE date = ? AND mac_address = ?",
                               (date, mac_address))
            else:
                cursor.execute("SELECT * FROM daily_usage WHERE date = ? ORDER BY total_bytes DESC",
                               (date,))
            return [dict_from_row(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_daily_usage error: %s", e)
        return []


def get_device_today_usage(mac_address: str, conn=None) -> dict:
    empty = {"today_bytes": 0, "today_sent": 0, "today_received": 0, "today_packets": 0}
    try:
        def _query(c):
            cursor = c.cursor()
            today = datetime.now().strftime("%Y-%m-%d")
            cursor.execute("""
                SELECT total_bytes, bytes_sent, bytes_received, packet_count,
                       first_seen_today, last_seen_today
                FROM daily_usage WHERE date = ? AND mac_address = ?
            """, (today, mac_address))
            return cursor.fetchone()

        if conn is not None:
            row = _query(conn)
        else:
            with get_connection() as _conn:
                row = _query(_conn)

        if row:
            return {
                "today_bytes": row["total_bytes"] or 0,
                "today_sent": row["bytes_sent"] or 0,
                "today_received": row["bytes_received"] or 0,
                "today_packets": row["packet_count"] or 0,
                "first_seen_today": row["first_seen_today"],
                "last_seen_today": row["last_seen_today"],
            }
        return empty
    except sqlite3.Error as e:
        logger.error("get_device_today_usage error: %s", e)
        return empty


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    else:
        return f"{b / 1024 ** 3:.2f} GB"
