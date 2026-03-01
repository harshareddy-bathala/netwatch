"""
network_filters.py - Network Detection, Validation & SQL Fragments
====================================================================

Subnet detection, IP/MAC validation, mode-aware device filtering,
and reusable SQL WHERE clauses.  Extracted from device_queries.py
to separate network-detection concerns from database CRUD logic.
"""

import sqlite3
import logging
from typing import Optional

from database.connection import get_connection
from utils.network_utils import is_private_ip as _shared_is_private_ip
from utils.network_utils import is_valid_device_ip as _shared_is_valid_device_ip
from utils.network_utils import is_valid_mac as _shared_is_valid_mac

logger = logging.getLogger(__name__)

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
_cached_all_local_ips: Optional[set] = None
_cached_all_local_macs: Optional[set] = None


def _detect_all_local_ips() -> set:
    """Collect ALL IPv4 addresses from all local network adapters.

    Used to prevent cross-adapter IPs (e.g. WiFi IP appearing as a
    hotspot client) from being inserted as separate devices.
    """
    global _cached_all_local_ips
    if _cached_all_local_ips is not None:
        return _cached_all_local_ips
    ips: set = set()
    try:
        import psutil
        for _name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == 'AF_INET':
                    ip = addr.address
                    if ip and ip not in ('0.0.0.0', '127.0.0.1'):
                        ips.add(ip)
    except ImportError:
        pass
    except Exception:
        pass
    # Always include the capture-interface IP
    our_ip = _detect_our_ip()
    if our_ip:
        ips.add(our_ip)
    _cached_all_local_ips = ips
    return ips


def _detect_all_local_macs() -> set:
    """Collect ALL MAC addresses from all local network adapters (upper-case, colon-separated).

    Used to prevent the host's own adapter MACs (hotspot virtual adapter, physical
    WiFi, etc.) from being written to the devices table or returned in API queries.
    """
    global _cached_all_local_macs
    if _cached_all_local_macs is not None:
        return _cached_all_local_macs
    macs: set = set()
    try:
        import psutil
        for _name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name in ('AF_LINK', 'AF_PACKET'):
                    mac = addr.address
                    if mac and mac not in ('', '00:00:00:00:00:00'):
                        macs.add(mac.upper().replace('-', ':'))
    except ImportError:
        pass
    except Exception:
        pass
    _cached_all_local_macs = macs
    return macs


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
    global _cached_subnet, _cached_our_ip, _cached_our_mac, _cached_gateway_ip, _cached_gateway_mac, _gateway_cache_time, _cached_all_local_ips, _cached_all_local_macs
    _cached_subnet = None
    _cached_our_ip = None
    _cached_our_mac = None
    _cached_gateway_ip = None
    _cached_gateway_mac = None
    _gateway_cache_time = None
    _cached_all_local_ips = None
    _cached_all_local_macs = None


# Current network mode name — set by main.py on startup and mode changes
_current_mode_name: Optional[str] = None
_cached_gateway_ip: Optional[str] = None
_cached_gateway_mac: Optional[str] = None
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


def set_gateway_mac(gw_mac: str):
    """Set the gateway MAC address from mode detection / ARP resolution.

    Used by :func:`_active_mode_for_mac` in restrictive modes to decide
    whether a device should be tagged with ``active_mode``.
    """
    global _cached_gateway_mac
    if gw_mac:
        _cached_gateway_mac = gw_mac.lower()
        logger.info("Gateway MAC set: %s", _cached_gateway_mac)
    else:
        _cached_gateway_mac = None


_RESTRICTIVE_MODES = frozenset({"public_network"})


def _active_mode_for_mac(mac: Optional[str]) -> Optional[str]:
    """Return the ``active_mode`` value to use when upserting a device.

    In **restrictive modes** (public_network) only our own
    MAC is tagged with the current mode name so it appears in the
    dashboard.  The gateway and all other devices get ``NULL`` — they
    are still stored for traffic records but won't appear in
    mode-filtered queries.

    In **permissive modes** (hotspot, ethernet, port_mirror) every device
    is tagged as before.
    """
    if _current_mode_name not in _RESTRICTIVE_MODES:
        return _current_mode_name

    if not mac:
        return None

    mac_lower = mac.lower()

    # Our own device — the only one shown in restrictive mode
    our_mac = _detect_our_mac()
    if our_mac and mac_lower == our_mac:
        return _current_mode_name

    # Everything else in restrictive mode → not shown in dashboard
    return None


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
        mode_name: One of 'hotspot', 'ethernet',
                   'port_mirror', 'public_network'
    """
    global _current_mode_name
    _current_mode_name = mode_name
    logger.info("Device queries: mode set to '%s'", mode_name)


def deactivate_stale_devices(new_subnet_prefix: str) -> int:
    """Legacy wrapper — calls :func:`scope_devices_to_mode`."""
    return scope_devices_to_mode(_current_mode_name or "unknown", new_subnet_prefix)


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

    For **public_network** mode only our own device (identified by
    *our_mac*) is tagged active.  The gateway and all other devices
    are cleared so only the host appears in the device list.

    For **hotspot**, **ethernet**, **port_mirror**: tag
    all subnet devices so ARP-discovered and traffic-producing devices
    both appear in the dashboard.

    Args:
        new_mode_name:      e.g. ``'public_network'``, ``'hotspot'``.
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
                # ── Restrictive path (public_network) ──
                # 1. Clear ALL devices first
                cursor.execute(
                    "UPDATE devices SET active_mode = NULL WHERE active_mode IS NOT NULL"
                )
                cleared = cursor.rowcount

                # 2. Tag only our MAC — gateway is excluded from the
                #    device list so the router never appears as a device.
                allowed_macs = [our_mac.lower()]
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

                # 3. Set hostname to machine name so the device list shows
                #    a meaningful name instead of a random vendor string.
                import socket as _sock
                machine_name = _sock.gethostname()
                if machine_name:
                    cursor.execute(
                        f"""
                        UPDATE devices
                        SET hostname = COALESCE(hostname, ?),
                            device_name = COALESCE(device_name, ?)
                        WHERE LOWER(mac_address) IN ({placeholders})
                        """,
                        (machine_name, machine_name, *allowed_macs),
                    )
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
                    WHERE (active_mode IS NOT NULL AND active_mode != '')
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

    # Own device filter — check ALL local adapter IPs so cross-adapter
    # IPs (e.g. WiFi IP appearing as hotspot client) are excluded too.
    if not SHOW_OWN_DEVICE:
        all_local = _detect_all_local_ips()
        if ip in all_local:
            return False
    else:
        # Even with SHOW_OWN_DEVICE=True, only allow the capture
        # interface's IP through.  Other local adapter IPs (e.g.
        # WiFi IP while in hotspot mode) are cross-adapter leaks.
        our_ip = _detect_our_ip()
        if ip != our_ip:
            all_local = _detect_all_local_ips()
            if ip in all_local:
                return False

    # Own adapter MAC filter — the host's own adapter MACs (physical WiFi,
    # hotspot virtual adapter, etc.) must never appear as client devices
    # regardless of IP.  This catches the laptop showing up with its own
    # MAC even when the IP check above passes.
    # Exception: in public_network, ethernet, and port_mirror modes the
    # capture interface MAC IS a device we want to track, so allow it
    # through while still blocking other local adapter MACs.
    all_local_macs = _detect_all_local_macs()
    if mac and mac.upper().replace('-', ':') in all_local_macs:
        if _current_mode_name not in ("public_network", "ethernet", "port_mirror"):
            return False
        # In these modes, only allow the capture interface MAC
        # through — other local adapter MACs are still excluded.
        our_mac = _detect_our_mac()
        if our_mac and mac.upper().replace('-', ':') != our_mac.upper().replace('-', ':'):
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

    # In restrictive modes (public_network), ALWAYS exclude the gateway
    # regardless of SHOW_GATEWAY setting.  On campus/public WiFi, the
    # gateway is NOT our device and must not appear in the device list
    # or inflate the device count.
    if _current_mode_name in _RESTRICTIVE_MODES:
        gw = _get_gateway_ip()
        if gw and ip == gw:
            return False
        gw_mac = _cached_gateway_mac
        if gw_mac and mac and mac.lower() == gw_mac:
            return False
        # Hard restriction: only allow our own capture interface MAC.
        # Belt-and-suspenders defense — even if gateway detection fails,
        # no other device can be inserted in public_network mode.
        our_mac = _detect_our_mac()
        if our_mac and mac:
            if mac.lower().replace('-', ':') != our_mac.lower().replace('-', ':'):
                return False

    # In hotspot mode, the host IS the gateway — always exclude it
    # regardless of SHOW_GATEWAY / SHOW_OWN_DEVICE settings, because
    # the user wants to see only connected CLIENT devices.
    if _current_mode_name == "hotspot":
        our_ip = _detect_our_ip()
        if our_ip and ip == our_ip:
            return False
        gw = _get_gateway_ip()
        if gw and ip == gw:
            return False
        gw_mac = _cached_gateway_mac
        if gw_mac and mac and mac.lower() == gw_mac:
            return False

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
