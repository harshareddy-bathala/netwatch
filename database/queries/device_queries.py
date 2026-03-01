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

Network detection, validation, and SQL filter fragments live in
``network_filters.py``.  Packet/traffic writes live in
``packet_store.py``.  This module re-exports their public symbols
for full backward compatibility.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from database.connection import get_connection, dict_from_row
from utils.query_cache import time_query, TTLCache

# ---------------------------------------------------------------------------
# Import from network_filters (extracted module)
# ---------------------------------------------------------------------------
from database.queries.network_filters import (
    # Detection functions
    _detect_our_ip,
    _detect_all_local_ips,
    _detect_all_local_macs,
    _detect_our_mac,
    _detect_subnet,
    _build_mac_to_ipv4,
    _get_gateway_ip,
    _active_mode_for_mac,
    # Setters
    set_capture_interface,
    set_gateway_ip,
    set_gateway_mac,
    set_subnet_from_ip,
    set_current_mode,
    reset_subnet_cache,
    # Validation
    is_private_ip,
    is_valid_device_ip,
    is_valid_device,
    get_current_subnet,
    _is_valid_mac,
    _is_valid_device_for_insert,
    _is_multicast_or_broadcast,
    # Mode scoping
    scope_devices_to_mode,
    deactivate_stale_devices,
    # SQL fragments
    _PRIVATE_IP_FILTER_SOURCE,
    _PRIVATE_IP_FILTER_DEST,
    _VALID_MAC_FILTER_SOURCE,
    _VALID_MAC_FILTER_DEST,
    VALID_DEVICE_IP_FILTER,
    _PRIVATE_IP_FILTER_DEVICE,
    # Constants
    _RESTRICTIVE_MODES,
)
# Re-export module-level mutable state accessors
from database.queries import network_filters as _nf

# ---------------------------------------------------------------------------
# Import from packet_store (extracted module)
# ---------------------------------------------------------------------------
from database.queries.packet_store import (
    save_packet,
    save_packets_batch,
    update_daily_usage,
    _update_daily_usage_cursor,
)

logger = logging.getLogger(__name__)

# Cache for expensive device queries (15s TTL)
_device_cache = TTLCache(ttl_seconds=15)


# ---------------------------------------------------------------------------
# Backward-compat: allow external code to read/write _current_mode_name etc.
# via device_queries module (they now live in network_filters)
# ---------------------------------------------------------------------------

def __getattr__(name):
    """Module-level __getattr__ for backward compatibility.

    Allows ``from database.queries.device_queries import _current_mode_name``
    and similar accesses to network_filters module-level variables.
    """
    _NF_ATTRS = {
        '_cached_subnet', '_cached_our_ip', '_capture_interface_name',
        '_cached_our_mac', '_cached_all_local_ips', '_cached_all_local_macs',
        '_current_mode_name', '_cached_gateway_ip', '_cached_gateway_mac',
        '_gateway_cache_time',
    }
    if name in _NF_ATTRS:
        return getattr(_nf, name)
    raise AttributeError(f"module 'database.queries.device_queries' has no attribute {name}")


# ---------------------------------------------------------------------------
# THE SINGLE SOURCE OF TRUTH  --  device count
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
        current_subnet = _detect_subnet()
        _current_mode_name = _nf._current_mode_name
        skip_subnet = _current_mode_name == "port_mirror"
        is_restrictive = _current_mode_name in _RESTRICTIVE_MODES

        subnet_filter_dev = ""
        params_dev = [since]
        if current_subnet and not skip_subnet:
            subnet_filter_dev = "AND ip_address LIKE ?"
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
            if not gw and current_subnet:
                excluded_ips.append(f"{current_subnet}.1")
        if not SHOW_OWN_DEVICE:
            our_ip = _detect_our_ip()
            if our_ip:
                excluded_ips.append(our_ip)

        if is_restrictive:
            gw = _get_gateway_ip()
            if gw and gw not in excluded_ips:
                excluded_ips.append(gw)

        exclude_clause = ""
        exclude_params: list = []
        if excluded_ips:
            placeholders = ",".join("?" for _ in excluded_ips)
            exclude_clause = f"WHERE ip_address NOT IN ({placeholders})"
            exclude_params = excluded_ips

        mode_filter_dev = ""
        if _current_mode_name:
            mode_filter_dev = "AND active_mode = ?"
            params_dev.append(_current_mode_name)

        if is_restrictive:
            cursor.execute(f"""
                SELECT COUNT(DISTINCT ip_address) AS count
                FROM (
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
            """, (*params_dev, *exclude_params))
        else:
            cursor.execute(f"""
                SELECT COUNT(DISTINCT ip_address) AS count
                FROM (
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
            """, (*params_dev, *exclude_params))

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


# Alias kept for backward compatibility
def get_device_count(minutes: int = 5) -> int:
    """Alias for :func:`get_active_device_count`."""
    return get_active_device_count(minutes)


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
        conn: Optional existing SQLite connection to reuse.
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
            # Detect local hostname for hotspot DNS leak cleanup
            import socket as _socket
            _local_hn = ""
            try:
                _local_hn = _socket.gethostname()
            except Exception:
                pass

            def _persist(c):
                cursor = c.cursor()
                if _local_hn:
                    cursor.execute("""
                        UPDATE devices
                        SET hostname = CASE
                                WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address
                                      OR hostname = ?)
                                THEN ? ELSE hostname END
                        WHERE ip_address = ? OR ipv4_address = ? OR mac_address = ?
                    """, (_local_hn, resolved, ip, ip, mac))
                else:
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
    scans) that were seen recently.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

            current_subnet = _detect_subnet()
            _current_mode_name = _nf._current_mode_name
            skip_subnet = _current_mode_name == "port_mirror"
            is_restrictive = _current_mode_name in _RESTRICTIVE_MODES
            subnet_filter_dev = ""
            params_dev = [since]
            if current_subnet and not skip_subnet:
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_dev.append(f"{current_subnet}.%")

            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            if is_restrictive:
                cursor.execute(f"""
                    SELECT
                        mac_address,
                        COALESCE(ipv4_address, ip_address) AS ip_address,
                        COALESCE(hostname, device_name) AS hostname,
                        COALESCE(hostname, device_name) AS device_name,
                        vendor,
                        total_packets AS packet_count,
                        total_bytes_sent AS bytes_sent,
                        total_bytes_received AS bytes_received,
                        COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0) AS total_bytes,
                        last_seen,
                        first_seen
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        AND ({_PRIVATE_IP_FILTER_DEVICE})
                        {subnet_filter_dev}
                        {mode_filter_dev}
                    ORDER BY (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) DESC
                    LIMIT ?
                """, (*params_dev, limit))
            else:
                params_src = [since]
                params_dst = [since]
                if current_subnet and not skip_subnet:
                    ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) AND source_ip LIKE ? OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) AND dest_ip LIKE ? OR dest_ip LIKE '%:%')"
                    params_src.append(f"{current_subnet}.%")
                    params_dst.append(f"{current_subnet}.%")
                else:
                    ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')"

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
                               0, 0, first_seen AS timestamp
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
                    existing_name = d.get("device_name") or d.get("hostname")
                    ip_d = d.get("ip_address", "")
                    if existing_name and existing_name != ip_d and existing_name != "unknown":
                        d["hostname"] = existing_name
                    else:
                        d["hostname"] = ip_d
                    d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))
                    devices.append(d)

            return devices

    except sqlite3.Error as e:
        logger.error("get_active_devices error: %s", e)
        return []


@time_query
def get_all_devices(limit: int = 100, offset: int = 0, hours: int = 24) -> list:
    """
    Same logic as ``get_active_devices`` but with a wider time window
    (default 24 h) and pagination support.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            current_subnet = _detect_subnet()
            _current_mode_name = _nf._current_mode_name
            skip_subnet = _current_mode_name == "port_mirror"
            is_restrictive = _current_mode_name in _RESTRICTIVE_MODES
            subnet_filter_dev = ""
            params_dev = [since]
            if current_subnet and not skip_subnet:
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_dev.append(f"{current_subnet}.%")

            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            if is_restrictive:
                cursor.execute(f"""
                    SELECT
                        mac_address,
                        COALESCE(ipv4_address, ip_address) AS ip_address,
                        COALESCE(hostname, device_name) AS device_name,
                        vendor,
                        total_packets AS packet_count,
                        total_bytes_sent AS bytes_sent,
                        total_bytes_received AS bytes_received,
                        COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0) AS total_bytes,
                        last_seen,
                        first_seen
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        AND ({_PRIVATE_IP_FILTER_DEVICE})
                        {subnet_filter_dev}
                        {mode_filter_dev}
                    ORDER BY (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) DESC
                    LIMIT ? OFFSET ?
                """, (*params_dev, limit, offset))
            else:
                params_src = [since]
                params_dst = [since]
                if current_subnet and not skip_subnet:
                    ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) AND source_ip LIKE ? OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) AND dest_ip LIKE ? OR dest_ip LIKE '%:%')"
                    params_src.append(f"{current_subnet}.%")
                    params_dst.append(f"{current_subnet}.%")
                else:
                    ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')"

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
                               0, 0, first_seen AS timestamp
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
                    existing_name = d.get("device_name") or d.get("hostname")
                    ip_d = d.get("ip_address", "")
                    if existing_name and existing_name != ip_d and existing_name != "unknown":
                        d["hostname"] = existing_name
                    else:
                        d["hostname"] = ip_d
                    d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))
                    devices.append(d)

            # Strip out any entry whose MAC matches a local adapter.
            # Skip this in restrictive modes (public_network) where our own
            # device IS the only one we want to show, and in ethernet mode
            # where the host is a legitimate device on the LAN.
            is_ethernet = _current_mode_name == "ethernet"
            if not is_restrictive and not is_ethernet:
                local_macs = _detect_all_local_macs()
                if local_macs:
                    devices = [
                        d for d in devices
                        if not (d.get("mac_address") or "").upper().replace("-", ":") in local_macs
                    ]
            return devices[:limit]

    except sqlite3.Error as e:
        logger.error("get_all_devices error: %s", e)
        return []


@time_query
def get_top_devices(limit: int = 10, hours: int = 1) -> list:
    """Top devices by traffic volume -- same filter as ``get_all_devices``.
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

            current_subnet = _detect_subnet()
            _current_mode_name = _nf._current_mode_name
            skip_subnet = _current_mode_name == "port_mirror"
            is_restrictive = _current_mode_name in _RESTRICTIVE_MODES
            subnet_filter_dev = ""
            params_dev = [since]
            if current_subnet and not skip_subnet:
                subnet_filter_dev = "AND ip_address LIKE ?"
                params_dev.append(f"{current_subnet}.%")

            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            if is_restrictive:
                cursor.execute(f"""
                    SELECT
                        mac_address,
                        COALESCE(ipv4_address, ip_address) AS ip_address,
                        COALESCE(hostname, device_name) AS device_name,
                        vendor,
                        total_packets AS packet_count,
                        total_bytes_sent AS bytes_sent,
                        total_bytes_received AS bytes_received,
                        COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0) AS total_bytes,
                        last_seen,
                        first_seen
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        AND ({_PRIVATE_IP_FILTER_DEVICE})
                        {subnet_filter_dev}
                        {mode_filter_dev}
                        AND (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) > 512
                    ORDER BY (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) DESC
                    LIMIT ?
                """, (*params_dev, limit))
            else:
                params_src = [since]
                params_dst = [since]
                if current_subnet and not skip_subnet:
                    ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) AND source_ip LIKE ? OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) AND dest_ip LIKE ? OR dest_ip LIKE '%:%')"
                    params_src.append(f"{current_subnet}.%")
                    params_dst.append(f"{current_subnet}.%")
                else:
                    ip_filter_src = f"AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')"

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
                               0, 0, first_seen AS timestamp
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
                    HAVING total_bytes > 512
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
            db_hostnames: dict = {}
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
                    pass

            for d in results:
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
            today_map: dict = {}
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

            # Strip out any entry whose MAC matches a local adapter.
            # Same logic as get_all_devices() — skip for restrictive modes
            # (public_network) and ethernet mode where the host is a device.
            is_ethernet = _current_mode_name == "ethernet"
            if not is_restrictive and not is_ethernet:
                local_macs = _detect_all_local_macs()
                if local_macs:
                    results = [
                        d for d in results
                        if not (d.get("mac_address") or "").upper().replace("-", ":") in local_macs
                    ]

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
            cursor.execute(
                "UPDATE devices SET hostname = ?, device_name = ? WHERE ip_address = ? OR ipv4_address = ?",
                (new_name, new_name, ip_address, ip_address),
            )
            if cursor.rowcount == 0:
                cursor.execute(
                    "UPDATE devices SET hostname = ?, device_name = ? WHERE mac_address = ?",
                    (new_name, new_name, ip_address),
                )
            if cursor.rowcount == 0:
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
    """
    cache_key = f"device_detail_{ip_address}"
    cached = _device_cache.get(cache_key)
    if cached is not None:
        return cached
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

                mac_for_fs = device.get('mac_address', '')
                if mac_for_fs:
                    cursor.execute(
                        "SELECT first_seen FROM devices WHERE mac_address = ? OR ip_address = ? LIMIT 1",
                        (mac_for_fs, ip_address),
                    )
                    fs_row = cursor.fetchone()
                    if fs_row and fs_row["first_seen"]:
                        device['first_seen'] = fs_row["first_seen"]

            _resolve_and_persist_hostname(device, conn=conn)

            since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

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

            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, message
                FROM alerts WHERE source_ip = ?
                ORDER BY timestamp DESC LIMIT 5
            """, (ip_address,))
            device["recent_alerts"] = [dict_from_row(r) for r in cursor.fetchall()]

            if 'total_bytes' not in device:
                device['total_bytes'] = (device.get('total_bytes_sent') or 0) + (device.get('total_bytes_received') or 0)

            _device_cache.set(cache_key, device)
            return device

    except sqlite3.Error as e:
        logger.error("get_device_details error: %s", e)
        return None


# ---------------------------------------------------------------------------
# Daily usage queries (read-only; write helpers in packet_store.py)
# ---------------------------------------------------------------------------

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
