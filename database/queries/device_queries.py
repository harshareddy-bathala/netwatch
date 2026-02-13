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
from utils.query_cache import time_query
from utils.network_utils import is_private_ip as _shared_is_private_ip
from utils.network_utils import is_valid_device_ip as _shared_is_valid_device_ip
from utils.network_utils import is_valid_mac as _shared_is_valid_mac

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subnet detection helpers
# ---------------------------------------------------------------------------

_cached_subnet: Optional[str] = None
_cached_our_ip: Optional[str] = None


def _detect_our_ip() -> str:
    """Detect this machine's local IP address."""
    global _cached_our_ip
    if _cached_our_ip:
        return _cached_our_ip
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
    global _cached_subnet, _cached_our_ip, _cached_gateway_ip, _gateway_cache_time
    _cached_subnet = None
    _cached_our_ip = None
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
    Falls back to parsing OS commands only when no explicit value has been set.
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
        import subprocess, sys, re
        if sys.platform == "win32":
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            current_subnet = _detect_subnet()
            best_gw = ""
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        gw = parts[1].strip()
                        if gw and gw[0].isdigit():
                            # Prefer a gateway in our current subnet
                            if current_subnet and gw.startswith(current_subnet + "."):
                                _cached_gateway_ip = gw
                                _gateway_cache_time = _time.time()
                                return gw
                            if not best_gw:
                                best_gw = gw
            if best_gw:
                _cached_gateway_ip = best_gw
                _gateway_cache_time = _time.time()
                return best_gw
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                _cached_gateway_ip = match.group(1)
                _gateway_cache_time = _time.time()
                return _cached_gateway_ip
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

# ---------------------------------------------------------------------------
# IP-based device deduplication
# ---------------------------------------------------------------------------

def _deduplicate_devices_by_ip(devices: list) -> list:
    """
    Merge device entries that share the same IP address.

    Modern devices use MAC address randomisation, which causes the same
    physical device to appear with multiple MACs in ``traffic_summary``.
    Since the device list queries ``GROUP BY mac_address``, the same IP
    can appear twice with different MACs.

    This post-processing step merges those duplicates:
    - Traffic totals (bytes, packets) are summed.
    - The most-recently-seen MAC address is kept.
    - Hostname / device_name are preserved from whichever entry has one.

    Additionally, gateway and own-device entries are filtered out here
    based on the SHOW_GATEWAY / SHOW_OWN_DEVICE config flags.  This
    ensures consistent counts across all device-listing APIs.
    """
    if not devices:
        return devices

    # Determine which IPs to exclude
    try:
        from config import SHOW_OWN_DEVICE, SHOW_GATEWAY
    except ImportError:
        SHOW_OWN_DEVICE = True
        SHOW_GATEWAY = True

    excluded_ips: set = set()
    if not SHOW_GATEWAY:
        gw = _get_gateway_ip()
        if gw:
            excluded_ips.add(gw)
        # Fallback: only exclude .1 when actual gateway was not detected
        if not gw:
            subnet = _detect_subnet()
            if subnet:
                excluded_ips.add(f"{subnet}.1")
    if not SHOW_OWN_DEVICE:
        our_ip = _detect_our_ip()
        if our_ip:
            excluded_ips.add(our_ip)

    ip_map: Dict[str, dict] = {}
    for d in devices:
        ip = d.get("ip_address")
        if not ip:
            continue
        # Skip excluded IPs
        if ip in excluded_ips:
            continue
        if ip in ip_map:
            existing = ip_map[ip]
            # Merge traffic totals
            for key in ("total_bytes", "bytes_sent", "bytes_received",
                        "packet_count", "today_bytes", "today_sent",
                        "today_received"):
                existing[key] = (existing.get(key) or 0) + (d.get(key) or 0)
            # Keep the most recently seen MAC / timestamp
            if (d.get("last_seen") or "") > (existing.get("last_seen") or ""):
                existing["mac_address"] = d.get("mac_address") or existing.get("mac_address")
                existing["last_seen"] = d.get("last_seen")
            # Prefer a meaningful hostname / device_name
            for name_key in ("hostname", "device_name"):
                new_val = d.get(name_key) or ""
                old_val = existing.get(name_key) or ""
                if new_val and new_val != ip and (not old_val or old_val == ip):
                    existing[name_key] = new_val
            # Recalculate formatted total
            existing["total_bytes_formatted"] = _format_bytes(existing.get("total_bytes") or 0)
        else:
            ip_map[ip] = d

    result = list(ip_map.values())
    result.sort(key=lambda x: x.get("total_bytes") or 0, reverse=True)
    return result


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


def get_current_subnet() -> str:
    """
    Get current network subnet prefix (first 3 octets).

    Returns:
        Subnet prefix like "10.234.255" or "192.168.1"
    """
    subnet = _detect_subnet()
    if subnet:
        return subnet
    return "192.168.1"  # Fallback


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

# For filtering old devices table (kept for backward compat)
VALID_DEVICE_IP_FILTER = """
    ip_address NOT LIKE '255.255.255.%'
    AND ip_address NOT LIKE '224.%' AND ip_address NOT LIKE '225.%'
    AND ip_address NOT LIKE '226.%' AND ip_address NOT LIKE '227.%'
    AND ip_address NOT LIKE '228.%' AND ip_address NOT LIKE '229.%'
    AND ip_address NOT LIKE '230.%' AND ip_address NOT LIKE '231.%'
    AND ip_address NOT LIKE '232.%' AND ip_address NOT LIKE '233.%'
    AND ip_address NOT LIKE '234.%' AND ip_address NOT LIKE '235.%'
    AND ip_address NOT LIKE '236.%' AND ip_address NOT LIKE '237.%'
    AND ip_address NOT LIKE '238.%' AND ip_address NOT LIKE '239.%'
    AND ip_address NOT LIKE '127.%'
    AND ip_address NOT LIKE '169.254.%'
    AND ip_address NOT LIKE '0.%'
    AND ip_address NOT LIKE 'ff%'
    AND ip_address NOT LIKE 'fe80:%'
    AND ip_address != '::1'
    AND ip_address != 'unknown'
    AND ip_address NOT LIKE '%.255'
    AND ip_address NOT LIKE '%.0'
"""

# ---------------------------------------------------------------------------
# THE SINGLE SOURCE OF TRUTH  —  device count
# ---------------------------------------------------------------------------

@time_query
def get_active_device_count(minutes: int = 5) -> int:
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
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

            # Build optional subnet filter
            # In port_mirror / hotspot modes, skip subnet filtering because
            # we intentionally see traffic from multiple subnets.
            current_subnet = _detect_subnet()
            skip_subnet = _current_mode_name in ("port_mirror", "hotspot")
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
                    SELECT ip_address
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        {subnet_filter_dev}
                )
                {exclude_clause}
            """, (*params_src, *params_dst, *params_dev, *exclude_params))

            row = cursor.fetchone()
            return row["count"] if row else 0

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
                cursor.execute("""
                    INSERT INTO devices
                        (ip_address, mac_address, device_name, vendor,
                         first_seen, last_seen, total_bytes_sent, total_packets)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        mac_address  = CASE
                            WHEN excluded.mac_address IS NOT NULL
                                 AND excluded.mac_address != ''
                                 AND excluded.mac_address != '00:00:00:00:00:00'
                                 AND excluded.mac_address != 'ff:ff:ff:ff:ff:ff'
                                 AND excluded.mac_address NOT LIKE '01:00:5e:%'
                                 AND excluded.mac_address NOT LIKE '33:33:%'
                            THEN excluded.mac_address
                            ELSE mac_address END,
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor       = COALESCE(excluded.vendor,       vendor),
                        last_seen    = excluded.last_seen,
                        total_bytes_sent = total_bytes_sent + excluded.total_bytes_sent,
                        total_packets    = total_packets + 1
                """, (source_ip, source_mac, device_name, vendor,
                      timestamp, timestamp, bytes_transferred))

            # 3. Upsert dest device — ONLY if valid local device
            if _is_valid_device_for_insert(dest_ip, dest_mac):
                cursor.execute("""
                    INSERT INTO devices
                        (ip_address, mac_address, vendor,
                         first_seen, last_seen, total_bytes_received, total_packets)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        mac_address = CASE
                            WHEN excluded.mac_address IS NOT NULL
                                 AND excluded.mac_address != ''
                                 AND excluded.mac_address != '00:00:00:00:00:00'
                                 AND excluded.mac_address != 'ff:ff:ff:ff:ff:ff'
                                 AND excluded.mac_address NOT LIKE '01:00:5e:%'
                                 AND excluded.mac_address NOT LIKE '33:33:%'
                            THEN excluded.mac_address
                            ELSE mac_address END,
                        vendor      = COALESCE(excluded.vendor,      vendor),
                        last_seen   = excluded.last_seen,
                        total_bytes_received = total_bytes_received + excluded.total_bytes_received,
                        total_packets        = total_packets + 1
                """, (dest_ip, dest_mac, dest_vendor,
                      timestamp, timestamp, bytes_transferred))

            conn.commit()

            # 4. Update daily usage
            if _is_valid_device_for_insert(source_ip, source_mac):
                update_daily_usage(source_mac, source_ip, device_name, bytes_transferred, 0, 1)
            if _is_valid_device_for_insert(dest_ip, dest_mac):
                update_daily_usage(dest_mac, dest_ip, None, 0, bytes_transferred, 0)

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

    # Subnet filtering — mode-aware
    # In port_mirror mode we see ALL traffic, so skip subnet filtering.
    # In hotspot mode we see connected clients on a different subnet.
    # In other modes enforce subnet to prevent wrong-subnet devices.
    if _current_mode_name not in ("port_mirror", "hotspot"):
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


def save_packets_batch(packets: list) -> int:
    """
    Save multiple packets in a **single transaction** for performance.

    Only devices passing ``_is_valid_device_for_insert`` (private IP,
    valid MAC, correct subnet, not our own device) are inserted into
    the devices table.  Traffic records are always saved.

    Returns the count of successfully saved packets.
    """
    if not packets:
        return 0

    saved = 0
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            for pkt in packets:
                try:
                    timestamp = pkt.get("timestamp", datetime.now())
                    if isinstance(timestamp, datetime):
                        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                    source_ip = pkt.get("source_ip") or pkt.get("src", "unknown")
                    dest_ip = pkt.get("dest_ip") or pkt.get("dst", "unknown")
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

                    # Traffic record (always saved for bandwidth stats)
                    cursor.execute("""
                        INSERT INTO traffic_summary
                        (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                         source_port, dest_port, protocol, raw_protocol,
                         bytes_transferred, device_name, vendor, direction)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                          source_port, dest_port, protocol, raw_protocol,
                          bytes_transferred, device_name, vendor, direction))

                    # Source device — only valid local devices
                    if _is_valid_device_for_insert(source_ip, source_mac):
                        cursor.execute("""
                            INSERT INTO devices
                                (ip_address, mac_address, device_name, vendor,
                                 first_seen, last_seen, total_bytes_sent, total_packets)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                            ON CONFLICT(ip_address) DO UPDATE SET
                                mac_address  = CASE
                                    WHEN excluded.mac_address IS NOT NULL
                                         AND excluded.mac_address != ''
                                         AND excluded.mac_address != '00:00:00:00:00:00'
                                         AND excluded.mac_address != 'ff:ff:ff:ff:ff:ff'
                                         AND excluded.mac_address NOT LIKE '01:00:5e:%'
                                         AND excluded.mac_address NOT LIKE '33:33:%'
                                    THEN excluded.mac_address
                                    ELSE mac_address END,
                                device_name  = CASE
                                    WHEN device_name IS NULL OR device_name = ''
                                    THEN COALESCE(excluded.device_name, device_name)
                                    ELSE device_name END,
                                vendor       = COALESCE(excluded.vendor,       vendor),
                                last_seen    = excluded.last_seen,
                                total_bytes_sent = total_bytes_sent + excluded.total_bytes_sent,
                                total_packets    = total_packets + 1
                        """, (source_ip, source_mac, device_name, vendor,
                              timestamp, timestamp, bytes_transferred))

                    # Dest device — only valid local devices
                    if _is_valid_device_for_insert(dest_ip, dest_mac):
                        cursor.execute("""
                            INSERT INTO devices
                                (ip_address, mac_address, vendor,
                                 first_seen, last_seen, total_bytes_received, total_packets)
                            VALUES (?, ?, ?, ?, ?, ?, 1)
                            ON CONFLICT(ip_address) DO UPDATE SET
                                mac_address = CASE
                                    WHEN excluded.mac_address IS NOT NULL
                                         AND excluded.mac_address != ''
                                         AND excluded.mac_address != '00:00:00:00:00:00'
                                         AND excluded.mac_address != 'ff:ff:ff:ff:ff:ff'
                                         AND excluded.mac_address NOT LIKE '01:00:5e:%'
                                         AND excluded.mac_address NOT LIKE '33:33:%'
                                    THEN excluded.mac_address
                                    ELSE mac_address END,
                                vendor      = COALESCE(excluded.vendor,      vendor),
                                last_seen   = excluded.last_seen,
                                total_bytes_received = total_bytes_received + excluded.total_bytes_received,
                                total_packets        = total_packets + 1
                        """, (dest_ip, dest_mac, dest_vendor,
                              timestamp, timestamp, bytes_transferred))

                    # Daily usage (valid local devices only)
                    if _is_valid_device_for_insert(source_ip, source_mac):
                        _update_daily_usage_cursor(cursor, source_mac, source_ip,
                                                   device_name, bytes_transferred, 0, 1)
                    if _is_valid_device_for_insert(dest_ip, dest_mac):
                        _update_daily_usage_cursor(cursor, dest_mac, dest_ip,
                                                   None, 0, bytes_transferred, 0)

                    saved += 1

                except Exception as e:
                    logger.warning("Error saving individual packet in batch: %s", e)
                    continue

            conn.commit()

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
                WHERE ip_address = ? OR mac_address = ?
                LIMIT 1
            """, (ip, mac))
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
                    WHERE ip_address = ? OR mac_address = ?
                """, (resolved, ip, mac))
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

            # Build subnet filter
            current_subnet = _detect_subnet()
            subnet_filter_src = ""
            subnet_filter_dst = ""
            subnet_filter_dev = ""
            params_src = [since]
            params_dst = [since]
            params_dev = [since]
            if current_subnet:
                subnet_filter_src = "AND source_ip LIKE ?"
                subnet_filter_dst = "AND dest_ip LIKE ?"
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_src.append(f"{current_subnet}.%")
                params_dst.append(f"{current_subnet}.%")
                params_dev.append(f"{current_subnet}.%")

            cursor.execute(f"""
                WITH all_devices AS (
                    SELECT source_mac AS mac_address, source_ip AS ip_address,
                           device_name, vendor,
                           bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        AND ({_PRIVATE_IP_FILTER_SOURCE})
                        {subnet_filter_src}
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL,
                           0, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_DEST}
                        AND ({_PRIVATE_IP_FILTER_DEST})
                        {subnet_filter_dst}
                    UNION ALL
                    SELECT mac_address, ip_address,
                           COALESCE(hostname, device_name) AS device_name, vendor,
                           0, 0, last_seen AS timestamp
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        {subnet_filter_dev}
                )
                SELECT
                    mac_address,
                    MAX(ip_address) AS ip_address,
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
                    _resolve_and_persist_hostname(d, conn=conn)
                    d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))
                    devices.append(d)

            # Deduplicate by IP so MAC-randomised devices don't appear twice
            return _deduplicate_devices_by_ip(devices)

    except sqlite3.Error as e:
        logger.error("get_active_devices error: %s", e)
        return []


@time_query
def get_all_devices(limit: int = 100, offset: int = 0, hours: int = 24) -> list:
    """
    Same logic as ``get_active_devices`` but with a wider time window
    (default 24 h) and pagination support.
    Includes subnet filtering to only show devices on current network.
    Also merges in devices from the ``devices`` table (populated by ARP
    scans) so ARP-discovered devices appear even when traffic_summary
    lacks their MAC addresses.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Build subnet filter
            current_subnet = _detect_subnet()
            subnet_filter_src = ""
            subnet_filter_dst = ""
            subnet_filter_dev = ""
            params_src = [since]
            params_dst = [since]
            params_dev = [since]
            if current_subnet:
                subnet_filter_src = "AND source_ip LIKE ?"
                subnet_filter_dst = "AND dest_ip LIKE ?"
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_src.append(f"{current_subnet}.%")
                params_dst.append(f"{current_subnet}.%")
                params_dev.append(f"{current_subnet}.%")

            cursor.execute(f"""
                WITH all_devices AS (
                    SELECT source_mac AS mac_address, source_ip AS ip_address,
                           device_name, vendor,
                           bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        AND ({_PRIVATE_IP_FILTER_SOURCE})
                        {subnet_filter_src}
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL,
                           0, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_DEST}
                        AND ({_PRIVATE_IP_FILTER_DEST})
                        {subnet_filter_dst}
                    UNION ALL
                    SELECT mac_address, ip_address,
                           COALESCE(hostname, device_name) AS device_name, vendor,
                           0, 0, last_seen AS timestamp
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        {subnet_filter_dev}
                )
                SELECT
                    mac_address,
                    MAX(ip_address) AS ip_address,
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
                    _resolve_and_persist_hostname(d, conn=conn)
                    d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))
                    devices.append(d)

            # Deduplicate by IP so MAC-randomised devices don't appear twice
            return _deduplicate_devices_by_ip(devices)

    except sqlite3.Error as e:
        logger.error("get_all_devices error: %s", e)
        return []


@time_query
def get_top_devices(limit: int = 10, hours: int = 1) -> list:
    """Top devices by traffic volume — same filter as ``get_all_devices``.
    Includes subnet filtering to only show devices on current network.
    Also merges in devices from the ``devices`` table.

    Optimised to batch hostname + today_usage lookups instead of
    issuing N+1 queries per device row."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Build subnet filter
            current_subnet = _detect_subnet()
            subnet_filter_src = ""
            subnet_filter_dst = ""
            subnet_filter_dev = ""
            params_src = [since]
            params_dst = [since]
            params_dev = [since]
            if current_subnet:
                subnet_filter_src = "AND source_ip LIKE ?"
                subnet_filter_dst = "AND dest_ip LIKE ?"
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_src.append(f"{current_subnet}.%")
                params_dst.append(f"{current_subnet}.%")
                params_dev.append(f"{current_subnet}.%")

            cursor.execute(f"""
                WITH all_devices AS (
                    SELECT source_mac AS mac_address, source_ip AS ip_address,
                           device_name, vendor,
                           bytes_transferred AS bytes_sent, 0 AS bytes_received, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        AND ({_PRIVATE_IP_FILTER_SOURCE})
                        {subnet_filter_src}
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL,
                           0, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp > ?
                        AND {_VALID_MAC_FILTER_DEST}
                        AND ({_PRIVATE_IP_FILTER_DEST})
                        {subnet_filter_dst}
                    UNION ALL
                    SELECT mac_address, ip_address,
                           COALESCE(hostname, device_name) AS device_name, vendor,
                           0, 0, last_seen AS timestamp
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        {subnet_filter_dev}
                )
                SELECT
                    mac_address,
                    MAX(ip_address)     AS ip_address,
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

            # Deduplicate by IP so MAC-randomised devices don't appear twice
            return _deduplicate_devices_by_ip(results)

    except sqlite3.Error as e:
        logger.error("get_top_devices error: %s", e)
        return []


def get_device_by_ip(ip_address: str) -> Optional[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
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
            # Try IP first — update both hostname and device_name
            cursor.execute(
                "UPDATE devices SET hostname = ?, device_name = ? WHERE ip_address = ?",
                (new_name, new_name, ip_address),
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
                    cursor.execute("""
                        INSERT INTO devices (ip_address, mac_address, hostname, device_name, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
                        ON CONFLICT(ip_address) DO UPDATE SET
                            hostname = excluded.hostname,
                            device_name = excluded.device_name
                    """, (ip_address, mac, new_name, new_name))
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
            cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
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
