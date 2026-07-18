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
import ipaddress
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
    _detect_subnet_cidr,
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
from database.queries import packet_store as _packet_store

_MIRRORED_PACKET_STORE_VALIDATOR = _packet_store._is_valid_device_for_insert


def _bind_packet_store_validation_hook() -> None:
    """Keep packet_store validation hook in sync with this module.

    Backward compatibility: tests and legacy callers often monkeypatch
    ``database.queries.device_queries._is_valid_device_for_insert``.
    Since write paths now live in ``packet_store``, mirror this symbol
    before each call so those patches still apply.
    """
    global _MIRRORED_PACKET_STORE_VALIDATOR

    # Respect explicit monkeypatches applied directly to packet_store.
    # We only synchronize when packet_store still points at the validator
    # last mirrored by this module.
    if _packet_store._is_valid_device_for_insert is _MIRRORED_PACKET_STORE_VALIDATOR:
        _packet_store._is_valid_device_for_insert = _is_valid_device_for_insert
        _MIRRORED_PACKET_STORE_VALIDATOR = _is_valid_device_for_insert


def save_packet(packet_data: dict):
    _bind_packet_store_validation_hook()
    return _packet_store.save_packet(packet_data)


def save_packets_batch(packets: list) -> int:
    _bind_packet_store_validation_hook()
    return _packet_store.save_packets_batch(packets)


def update_daily_usage(
    mac_address: str,
    ip_address: str,
    device_name: Optional[str],
    bytes_sent: int,
    bytes_received: int,
    packet_count: int = 1,
) -> bool:
    return _packet_store.update_daily_usage(
        mac_address,
        ip_address,
        device_name,
        bytes_sent,
        bytes_received,
        packet_count,
    )


def _update_daily_usage_cursor(
    cursor,
    mac_address,
    ip_address,
    device_name,
    bytes_sent,
    bytes_received,
    packet_count,
):
    return _packet_store._update_daily_usage_cursor(
        cursor,
        mac_address,
        ip_address,
        device_name,
        bytes_sent,
        bytes_received,
        packet_count,
    )

logger = logging.getLogger(__name__)

# Cache for expensive device queries (15s TTL)
_device_cache = TTLCache(ttl_seconds=15)


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    return mac.lower().replace("-", ":")


def _to_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _fetch_control_bytes_by_mac(cursor, mac_addresses: list, since: Optional[str] = None) -> dict:
    """Return control-byte totals by MAC from traffic_summary.

    Result shape:
        {"aa:bb:...": {"sent": 123, "received": 456}, ...}
    """
    normalized = sorted({_normalize_mac(m) for m in (mac_addresses or []) if m})
    if not normalized:
        return {}

    placeholders = ",".join("?" for _ in normalized)
    result = {m: {"sent": 0, "received": 0} for m in normalized}

    src_params = []
    dst_params = []
    time_clause = ""
    if since:
        time_clause = "AND timestamp >= ?"
        src_params.append(since)
        dst_params.append(since)
    src_params.extend(normalized)
    dst_params.extend(normalized)

    cursor.execute(f"""
        SELECT LOWER(REPLACE(source_mac, '-', ':')) AS mac_address,
               SUM(bytes_transferred) AS bytes_sent
        FROM traffic_summary
        WHERE COALESCE(is_control, 0) = 1
          {time_clause}
          AND source_mac IS NOT NULL
          AND LOWER(REPLACE(source_mac, '-', ':')) IN ({placeholders})
        GROUP BY LOWER(REPLACE(source_mac, '-', ':'))
    """, src_params)
    for row in cursor.fetchall():
        mac = _normalize_mac(row["mac_address"])
        if mac in result:
            result[mac]["sent"] = _to_int(row["bytes_sent"])

    cursor.execute(f"""
        SELECT LOWER(REPLACE(dest_mac, '-', ':')) AS mac_address,
               SUM(bytes_transferred) AS bytes_received
        FROM traffic_summary
        WHERE COALESCE(is_control, 0) = 1
          {time_clause}
          AND dest_mac IS NOT NULL
          AND LOWER(REPLACE(dest_mac, '-', ':')) IN ({placeholders})
        GROUP BY LOWER(REPLACE(dest_mac, '-', ':'))
    """, dst_params)
    for row in cursor.fetchall():
        mac = _normalize_mac(row["mac_address"])
        if mac in result:
            result[mac]["received"] = _to_int(row["bytes_received"])

    return result


def _apply_device_metric_view(devices: list, include_control: bool, control_bytes_by_mac: Optional[dict] = None) -> list:
    """Attach Phase 2 app/control/total byte fields to device rows."""
    control_bytes_by_mac = control_bytes_by_mac or {}

    for d in devices:
        mac = _normalize_mac(d.get("mac_address", ""))
        app_sent = _to_int(d.get("bytes_sent"))
        app_received = _to_int(d.get("bytes_received"))
        app_total = app_sent + app_received

        control_sent = _to_int(d.get("bytes_sent_control") or d.get("control_bytes_sent"))
        control_received = _to_int(d.get("bytes_received_control") or d.get("control_bytes_received"))
        if (control_sent == 0 and control_received == 0) and mac:
            control_lookup = control_bytes_by_mac.get(mac, {})
            control_sent = _to_int(control_lookup.get("sent"))
            control_received = _to_int(control_lookup.get("received"))

        control_total = control_sent + control_received
        total_sent = app_sent + control_sent
        total_received = app_received + control_received
        total_all = app_total + control_total

        d["bytes_sent_app"] = app_sent
        d["bytes_received_app"] = app_received
        d["total_bytes_app"] = app_total

        d["bytes_sent_control"] = control_sent
        d["bytes_received_control"] = control_received
        d["total_bytes_control"] = control_total

        d["bytes_sent_total"] = total_sent
        d["bytes_received_total"] = total_received
        d["total_bytes_total"] = total_all

        d["control_overhead_ratio"] = round((control_total / total_all), 4) if total_all else 0.0

        if include_control:
            d["bytes_sent"] = total_sent
            d["bytes_received"] = total_received
            d["total_bytes"] = total_all
        else:
            d["bytes_sent"] = app_sent
            d["bytes_received"] = app_received
            d["total_bytes"] = app_total

        # Legacy aliases used by parts of the frontend.
        d["total_bytes_sent"] = d["bytes_sent"]
        d["total_bytes_received"] = d["bytes_received"]
        d["total_bytes_formatted"] = _format_bytes(d.get("total_bytes", 0))

    return devices


def _strip_host_devices(devices: list) -> list:
    """Remove the host machine's own entries from a device list.

    Filters by both MAC **and** IP so that even if one detection method
    fails (e.g. psutil can't read the hotspot virtual adapter MAC on
    Windows), the other catches it.

    In hotspot mode this is critical: the host IS the gateway
    (192.168.137.1) and must never appear as a client device.
    """
    _current_mode_name = _nf._current_mode_name

    # In restrictive modes (public_network) and ethernet the host is a
    # device we want to track — don't strip.
    is_restrictive = _current_mode_name in _RESTRICTIVE_MODES
    is_ethernet = _current_mode_name == "ethernet"
    if is_restrictive or is_ethernet:
        return devices

    # Collect all host MACs and IPs
    local_macs = _detect_all_local_macs()
    local_ips = _detect_all_local_ips()

    def _is_host_device(d: dict) -> bool:
        mac = (d.get("mac_address") or "").upper().replace("-", ":")
        if mac and local_macs and mac in local_macs:
            return True
        ip = d.get("ip_address") or ""
        if ip and local_ips and ip in local_ips:
            return True
        return False

    return [d for d in devices if not _is_host_device(d)]


def _use_devices_table_only_mode(mode_name: Optional[str]) -> bool:
    """Return True when device queries should read from ``devices`` only.

    Hotspot mode needs real-time connected-client visibility and should not
    aggregate long traffic history from ``traffic_summary`` for list views.
    """
    return mode_name in _RESTRICTIVE_MODES or mode_name == "hotspot"


def _host_exclusion_sql() -> str:
    """SQL that removes the monitoring host / gateway from a device list.

    In hotspot the host IS the gateway (192.168.137.1) and NAT-forwards every
    client's traffic, so without this it appears as a bogus device whose usage
    mirrors a client's. The device LIST previously lacked this exclusion while
    the COUNT had it — hence "count 2, list 3". Uses the same identity the
    dashboard uses; addresses are our own (psutil), inlined as validated
    literals (no user input). Matches on BOTH the COALESCEd IP and the MAC.
    """
    try:
        from utils.realtime_state import dashboard_state
        ident = dashboard_state.get_host_identity()
        ips = {i for i in (ident.get("ips") or set()) if _looks_like_addr(i)}
        macs = {m.lower() for m in (ident.get("macs") or set()) if _looks_like_mac(m)}
    except Exception:
        return ""
    parts = []
    if ips:
        vals = ",".join(f"'{i}'" for i in ips)
        parts.append(f"COALESCE(ipv4_address, ip_address) NOT IN ({vals})")
    if macs:
        vals = ",".join(f"'{m}'" for m in macs)
        parts.append(f"LOWER(mac_address) NOT IN ({vals})")
    return (" AND " + " AND ".join(f"({p})" for p in parts)) if parts else ""


def _looks_like_addr(s: str) -> bool:
    return bool(s) and all(c in "0123456789abcdefABCDEF.:%" for c in s)


def _looks_like_mac(s: str) -> bool:
    return bool(s) and all(c in "0123456789abcdefABCDEF:-" for c in s) and (":" in s or "-" in s)


def _devices_table_ip_filter_clause(mode_name: Optional[str]) -> str:
    """Return SQL predicate for devices-table IP visibility by mode.

    In hotspot mode, connected clients can be discovered by MAC before IP
    assignment/ARP resolution is complete. Keep those rows visible instead
    of dropping them behind strict private-IP-only checks — but always
    exclude the host/gateway itself.
    """
    if mode_name == "hotspot":
        return f"""
            (
                ({_PRIVATE_IP_FILTER_DEVICE})
                OR COALESCE(ipv4_address, ip_address) IS NULL
                OR TRIM(COALESCE(ipv4_address, ip_address)) = ''
                OR LOWER(TRIM(COALESCE(ipv4_address, ip_address))) = 'unknown'
            )
            {_host_exclusion_sql()}
        """

    return f"({_PRIVATE_IP_FILTER_DEVICE})"


def _hotspot_presence_window_seconds() -> int:
    """Return hotspot recency window used by list-style device queries.

    This is a fallback guard for lock-contention periods where DB updates
    that clear ``active_mode`` can be delayed. In hotspot mode we only want
    currently connected/recently-seen clients on the devices page.
    """
    try:
        from config import HOTSPOT_STALE_DEVICE_SECONDS

        return max(30, int(HOTSPOT_STALE_DEVICE_SECONDS))
    except Exception:
        return 60


def _hotspot_since_timestamp() -> str:
    """Return UTC cutoff timestamp for hotspot recency filtering."""
    return (datetime.utcnow() - timedelta(seconds=_hotspot_presence_window_seconds())).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


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
        # SQLite datetime('now') is UTC, so use UTC here to avoid
        # timezone skew that can hide recently-seen devices.
        since = (datetime.utcnow() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

        # Build optional subnet filter
        current_subnet_cidr = _detect_subnet_cidr()
        _current_mode_name = _nf._current_mode_name
        skip_subnet = _current_mode_name == "port_mirror"
        is_restrictive = _current_mode_name in _RESTRICTIVE_MODES

        subnet_filter_dev = ""
        params_dev = [since]
        if current_subnet_cidr and not skip_subnet:
            subnet_filter_dev = "AND ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1"
            params_dev.append(current_subnet_cidr)

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
            if not gw and current_subnet_cidr:
                try:
                    subnet = ipaddress.IPv4Network(current_subnet_cidr, strict=False)
                    if subnet.num_addresses > 2:
                        excluded_ips.append(str(subnet.network_address + 1))
                except Exception:
                    pass
        if not SHOW_OWN_DEVICE:
            our_ip = _detect_our_ip()
            if our_ip:
                excluded_ips.append(our_ip)

        # In hotspot mode the host IS the gateway — always exclude it
        # regardless of SHOW_GATEWAY / SHOW_OWN_DEVICE settings.
        if _current_mode_name == "hotspot":
            for lip in _detect_all_local_ips():
                if lip not in excluded_ips:
                    excluded_ips.append(lip)

        if is_restrictive:
            gw = _get_gateway_ip()
            if gw and gw not in excluded_ips:
                excluded_ips.append(gw)

        # Exclude the monitoring host by BOTH its IP(s) and MAC(s), using the
        # SAME identity source the device *list* uses
        # (dashboard_state.get_host_identity()). _detect_all_local_ips() misses
        # the hotspot ICS virtual adapter, so the host slipped through here and
        # the count read N+1 (1 with nothing connected, 2 with one phone) even
        # though the list correctly dropped it. This keeps count == list.
        host_mac_exclude = ""
        host_macs_lc: list = []
        try:
            from utils.realtime_state import dashboard_state
            _ident = dashboard_state.get_host_identity()
            for _hip in (_ident.get("ips") or set()):
                if _hip and _hip not in excluded_ips:
                    excluded_ips.append(_hip)
            host_macs_lc = sorted(
                {m.lower() for m in (_ident.get("macs") or set()) if m})
            if host_macs_lc:
                ph = ",".join("?" for _ in host_macs_lc)
                host_mac_exclude = f"AND LOWER(mac_address) NOT IN ({ph})"
        except Exception:
            host_macs_lc = []

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

        # Host-MAC exclusion params come last in the subquery WHERE, so append
        # them after the mode param to keep positional binding aligned.
        params_dev.extend(host_macs_lc)

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
                        {host_mac_exclude}
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
                        {host_mac_exclude}
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
def get_active_devices(minutes: int = 5, limit: int = 100, include_control: bool = False) -> list:
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
            _current_mode_name = _nf._current_mode_name
            if _current_mode_name == "hotspot":
                since = _hotspot_since_timestamp()
            else:
                since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

            current_subnet_cidr = _detect_subnet_cidr()
            skip_subnet = _current_mode_name == "port_mirror"
            use_devices_table_only = _use_devices_table_only_mode(_current_mode_name)
            devices_ip_filter = _devices_table_ip_filter_clause(_current_mode_name)
            subnet_filter_dev = ""
            params_dev = [since]
            if current_subnet_cidr and not skip_subnet:
                if _current_mode_name == "hotspot":
                    subnet_filter_dev = """
                        AND (
                            ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1
                            OR COALESCE(ipv4_address, ip_address) IS NULL
                            OR TRIM(COALESCE(ipv4_address, ip_address)) = ''
                            OR LOWER(TRIM(COALESCE(ipv4_address, ip_address))) = 'unknown'
                        )
                    """
                else:
                    subnet_filter_dev = "AND ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1"
                params_dev.append(current_subnet_cidr)

            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            if use_devices_table_only:
                cursor.execute(f"""
                    SELECT
                        mac_address,
                        COALESCE(ipv4_address, ip_address) AS ip_address,
                        COALESCE(hostname, device_name) AS hostname,
                        COALESCE(hostname, device_name) AS device_name,
                        vendor,
                        COALESCE(device_type, 'unknown') AS device_type,
                        total_packets AS packet_count,
                        total_bytes_sent AS bytes_sent,
                        total_bytes_received AS bytes_received,
                        COALESCE(control_bytes_sent, 0) AS bytes_sent_control,
                        COALESCE(control_bytes_received, 0) AS bytes_received_control,
                        COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0) AS total_bytes,
                        last_seen,
                        first_seen
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {devices_ip_filter}
                        {subnet_filter_dev}
                        {mode_filter_dev}
                    ORDER BY (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) DESC
                    LIMIT ?
                """, (*params_dev, limit))
            else:
                params_src = [since]
                params_dst = [since]
                if current_subnet_cidr and not skip_subnet:
                    ip_filter_src = f"AND ((({_PRIVATE_IP_FILTER_SOURCE}) AND ip_in_subnet(source_ip, ?) = 1) OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND ((({_PRIVATE_IP_FILTER_DEST}) AND ip_in_subnet(dest_ip, ?) = 1) OR dest_ip LIKE '%:%')"
                    params_src.append(current_subnet_cidr)
                    params_dst.append(current_subnet_cidr)
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
                            AND COALESCE(is_control, 0) = 0
                            AND {_VALID_MAC_FILTER_SOURCE}
                            {ip_filter_src}
                        UNION ALL
                        SELECT dest_mac, dest_ip, NULL, NULL,
                               0, bytes_transferred, timestamp
                        FROM traffic_summary
                        WHERE timestamp >= ?
                            AND COALESCE(is_control, 0) = 0
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
                            AND {devices_ip_filter}
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
                    devices.append(d)

            if devices:
                macs = [d.get("mac_address", "") for d in devices]
                control_map = {}
                if not use_devices_table_only:
                    control_map = _fetch_control_bytes_by_mac(cursor, macs, since=since)
                devices = _apply_device_metric_view(
                    devices,
                    include_control=include_control,
                    control_bytes_by_mac=control_map,
                )

            return _strip_host_devices(devices)

    except sqlite3.Error as e:
        logger.error("get_active_devices error: %s", e)
        return []


@time_query
def get_all_devices(
    limit: int = 100,
    offset: int = 0,
    hours: int = 24,
    include_control: bool = False,
) -> list:
    """
    Same logic as ``get_active_devices`` but with a wider time window
    (default 24 h) and pagination support.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            _current_mode_name = _nf._current_mode_name
            if _current_mode_name == "hotspot":
                since = _hotspot_since_timestamp()
            else:
                since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            current_subnet_cidr = _detect_subnet_cidr()
            skip_subnet = _current_mode_name == "port_mirror"
            use_devices_table_only = _use_devices_table_only_mode(_current_mode_name)
            devices_ip_filter = _devices_table_ip_filter_clause(_current_mode_name)
            subnet_filter_dev = ""
            params_dev = [since]
            if current_subnet_cidr and not skip_subnet:
                if _current_mode_name == "hotspot":
                    subnet_filter_dev = """
                        AND (
                            ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1
                            OR COALESCE(ipv4_address, ip_address) IS NULL
                            OR TRIM(COALESCE(ipv4_address, ip_address)) = ''
                            OR LOWER(TRIM(COALESCE(ipv4_address, ip_address))) = 'unknown'
                        )
                    """
                else:
                    subnet_filter_dev = "AND ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1"
                params_dev.append(current_subnet_cidr)

            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            if use_devices_table_only:
                cursor.execute(f"""
                    SELECT
                        mac_address,
                        COALESCE(ipv4_address, ip_address) AS ip_address,
                        COALESCE(hostname, device_name) AS device_name,
                        vendor,
                        total_packets AS packet_count,
                        total_bytes_sent AS bytes_sent,
                        total_bytes_received AS bytes_received,
                        COALESCE(control_bytes_sent, 0) AS bytes_sent_control,
                        COALESCE(control_bytes_received, 0) AS bytes_received_control,
                        COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0) AS total_bytes,
                        last_seen,
                        first_seen
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {devices_ip_filter}
                        {subnet_filter_dev}
                        {mode_filter_dev}
                    ORDER BY (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) DESC
                    LIMIT ? OFFSET ?
                """, (*params_dev, limit, offset))
            else:
                params_src = [since]
                params_dst = [since]
                if current_subnet_cidr and not skip_subnet:
                    ip_filter_src = f"AND ((({_PRIVATE_IP_FILTER_SOURCE}) AND ip_in_subnet(source_ip, ?) = 1) OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND ((({_PRIVATE_IP_FILTER_DEST}) AND ip_in_subnet(dest_ip, ?) = 1) OR dest_ip LIKE '%:%')"
                    params_src.append(current_subnet_cidr)
                    params_dst.append(current_subnet_cidr)
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
                            AND COALESCE(is_control, 0) = 0
                            AND {_VALID_MAC_FILTER_SOURCE}
                            {ip_filter_src}
                        UNION ALL
                        SELECT dest_mac, dest_ip, NULL, NULL,
                               0, bytes_transferred, timestamp
                        FROM traffic_summary
                        WHERE timestamp > ?
                            AND COALESCE(is_control, 0) = 0
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
                            AND {devices_ip_filter}
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
                    devices.append(d)

            if devices:
                macs = [d.get("mac_address", "") for d in devices]
                control_map = {}
                if not use_devices_table_only:
                    control_map = _fetch_control_bytes_by_mac(cursor, macs, since=since)
                devices = _apply_device_metric_view(
                    devices,
                    include_control=include_control,
                    control_bytes_by_mac=control_map,
                )

            # Strip out the host machine's own entries (by MAC + IP).
            devices = _strip_host_devices(devices)
            return devices[:limit]

    except sqlite3.Error as e:
        logger.error("get_all_devices error: %s", e)
        return []


@time_query
def get_top_devices(limit: int = 10, hours: int = 1, include_control: bool = False) -> list:
    """Top devices by traffic volume -- same filter as ``get_all_devices``.
    Optimised to batch hostname + today_usage lookups instead of
    issuing N+1 queries per device row."""
    mode_for_cache = _nf._current_mode_name or "unknown"
    use_hotspot_realtime = mode_for_cache == "hotspot"
    cache_key = f"top_devices_{mode_for_cache}_{limit}_{hours}_{int(include_control)}"
    if not use_hotspot_realtime:
        cached = _device_cache.get(cache_key)
        if cached is not None:
            return cached
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            _current_mode_name = mode_for_cache
            if _current_mode_name == "hotspot":
                since = _hotspot_since_timestamp()
            else:
                since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            current_subnet_cidr = _detect_subnet_cidr()
            skip_subnet = _current_mode_name == "port_mirror"
            use_devices_table_only = _use_devices_table_only_mode(_current_mode_name)
            devices_ip_filter = _devices_table_ip_filter_clause(_current_mode_name)
            subnet_filter_dev = ""
            params_dev = [since]
            if current_subnet_cidr and not skip_subnet:
                if _current_mode_name == "hotspot":
                    subnet_filter_dev = """
                        AND (
                            ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1
                            OR COALESCE(ipv4_address, ip_address) IS NULL
                            OR TRIM(COALESCE(ipv4_address, ip_address)) = ''
                            OR LOWER(TRIM(COALESCE(ipv4_address, ip_address))) = 'unknown'
                        )
                    """
                else:
                    subnet_filter_dev = "AND ip_in_subnet(COALESCE(ipv4_address, ip_address), ?) = 1"
                params_dev.append(current_subnet_cidr)

            mode_filter_dev = ""
            if _current_mode_name:
                mode_filter_dev = "AND active_mode = ?"
                params_dev.append(_current_mode_name)

            if use_devices_table_only:
                cursor.execute(f"""
                    SELECT
                        mac_address,
                        COALESCE(ipv4_address, ip_address) AS ip_address,
                        COALESCE(hostname, device_name) AS device_name,
                        vendor,
                        total_packets AS packet_count,
                        total_bytes_sent AS bytes_sent,
                        total_bytes_received AS bytes_received,
                        COALESCE(control_bytes_sent, 0) AS bytes_sent_control,
                        COALESCE(control_bytes_received, 0) AS bytes_received_control,
                        COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0) AS total_bytes,
                        last_seen,
                        first_seen
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {devices_ip_filter}
                        {subnet_filter_dev}
                        {mode_filter_dev}
                        AND (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) > 512
                    ORDER BY (COALESCE(total_bytes_sent, 0) + COALESCE(total_bytes_received, 0)) DESC
                    LIMIT ?
                """, (*params_dev, limit))
            else:
                params_src = [since]
                params_dst = [since]
                if current_subnet_cidr and not skip_subnet:
                    ip_filter_src = f"AND ((({_PRIVATE_IP_FILTER_SOURCE}) AND ip_in_subnet(source_ip, ?) = 1) OR source_ip LIKE '%:%')"
                    ip_filter_dst = f"AND ((({_PRIVATE_IP_FILTER_DEST}) AND ip_in_subnet(dest_ip, ?) = 1) OR dest_ip LIKE '%:%')"
                    params_src.append(current_subnet_cidr)
                    params_dst.append(current_subnet_cidr)
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
                            AND COALESCE(is_control, 0) = 0
                            AND {_VALID_MAC_FILTER_SOURCE}
                            {ip_filter_src}
                        UNION ALL
                        SELECT dest_mac, dest_ip, NULL, NULL,
                               0, bytes_transferred, timestamp
                        FROM traffic_summary
                        WHERE timestamp > ?
                            AND COALESCE(is_control, 0) = 0
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
                            AND {devices_ip_filter}
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

            # Attach Phase 2 app/control/total metrics.
            macs = [d.get("mac_address", "") for d in results]
            control_map = {}
            if not use_devices_table_only:
                control_map = _fetch_control_bytes_by_mac(cursor, macs, since=since)
            results = _apply_device_metric_view(
                results,
                include_control=include_control,
                control_bytes_by_mac=control_map,
            )

            # Strip out the host machine's own entries (by MAC + IP).
            results = _strip_host_devices(results)

            if not use_hotspot_realtime:
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


def classify_and_update_devices(limit: int = 500) -> int:
    """Auto-identify devices from their passive signals (W4).

    Reads each device's vendor + hostname, runs the deterministic
    ``device_fingerprint.classify_device`` classifier, and fills
    ``device_type`` (when still 'unknown'/NULL) and ``device_name`` (when
    empty) with a friendly guess. Only *raises* certainty — a name a device
    advertised for itself, or an operator set, is never overwritten.

    Returns the number of rows updated. Cheap and idempotent; called from
    the background hostname-resolution loop.
    """
    try:
        from intelligence.device_fingerprint import classify_device
    except Exception:
        return 0
    updated = 0
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT mac_address, vendor, hostname, device_name, device_type
                FROM devices
                WHERE (device_type IS NULL OR device_type = '' OR device_type = 'unknown'
                       OR device_name IS NULL OR device_name = '')
                  AND (vendor IS NOT NULL AND vendor != ''
                       OR hostname IS NOT NULL AND hostname != '')
                LIMIT ?
                """,
                (int(limit),),
            )
            rows = [dict(zip([c[0] for c in cursor.description], r))
                    for r in cursor.fetchall()]
            for d in rows:
                result = classify_device(
                    vendor=d.get("vendor"), hostname=d.get("hostname"),
                    mac=d.get("mac_address"))
                new_type = result["device_type"]
                cur_type = (d.get("device_type") or "unknown")
                set_type = (new_type != "unknown"
                            and cur_type in ("", "unknown", None)
                            and result["confidence"] >= 0.4)
                # Only fill device_name from the label when we have nothing
                # better already stored (hostname wins if present).
                set_name = (not (d.get("device_name") or "").strip()
                            and bool(result["label"]))
                if not set_type and not set_name:
                    continue
                sets, params = [], []
                if set_type:
                    sets.append("device_type = ?"); params.append(new_type)
                if set_name:
                    sets.append("device_name = ?"); params.append(result["label"])
                params.append(d["mac_address"])
                cursor.execute(
                    f"UPDATE devices SET {', '.join(sets)} WHERE mac_address = ?",
                    params,
                )
                updated += cursor.rowcount
            conn.commit()
    except sqlite3.Error as e:
        logger.debug("classify_and_update_devices error: %s", e)
    return updated


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
def get_device_details(ip_address: str, include_control: bool = False) -> Optional[dict]:
    """Detailed view of a single device including 24 h traffic and recent alerts.

    Falls back to building device info from traffic_summary if the device
    isn't in the devices table (e.g. own device when SHOW_OWN_DEVICE=False).
    """
    cache_key = f"device_detail_{ip_address}_{int(include_control)}"
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
                               CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END AS bytes_sent,
                               0 AS bytes_received,
                               CASE WHEN COALESCE(is_control, 0) = 1 THEN bytes_transferred ELSE 0 END AS control_bytes_sent,
                               0 AS control_bytes_received,
                               CASE WHEN COALESCE(is_control, 0) = 0 THEN 1 ELSE 0 END AS packet_count,
                               CASE WHEN COALESCE(is_control, 0) = 1 THEN 1 ELSE 0 END AS control_packet_count,
                               timestamp
                        FROM traffic_summary
                        WHERE source_ip = ? AND timestamp >= ?
                            AND {_VALID_MAC_FILTER_SOURCE}
                        UNION ALL
                        SELECT dest_mac, dest_ip, NULL, NULL,
                               0,
                               CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END,
                               0,
                               CASE WHEN COALESCE(is_control, 0) = 1 THEN bytes_transferred ELSE 0 END,
                               CASE WHEN COALESCE(is_control, 0) = 0 THEN 1 ELSE 0 END,
                               CASE WHEN COALESCE(is_control, 0) = 1 THEN 1 ELSE 0 END,
                               timestamp
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
                        SUM(control_bytes_sent) AS control_bytes_sent,
                        SUM(control_bytes_received) AS control_bytes_received,
                        SUM(packet_count) AS total_packets,
                        SUM(control_packet_count) AS control_packets
                    FROM dev
                """, (ip_address, since_fb, ip_address, since_fb, ip_address))
                fallback_row = cursor.fetchone()
                if not fallback_row or not (dict_from_row(fallback_row) or {}).get('mac_address'):
                    return None
                device = dict_from_row(fallback_row)
                device['hostname'] = device.get('device_name') or ip_address

                mac_for_fs = device.get('mac_address', '')
                if mac_for_fs:
                    cursor.execute(
                        "SELECT first_seen FROM devices WHERE mac_address = ? OR ip_address = ? LIMIT 1",
                        (mac_for_fs, ip_address),
                    )
                    fs_row = cursor.fetchone()
                    if fs_row and fs_row["first_seen"]:
                        device['first_seen'] = fs_row["first_seen"]

            # Phase 2 metric split (app/control/total) with backward-compatible
            # legacy fields defaulting to app-only unless include_control=true.
            app_sent = _to_int(device.get("total_bytes_sent"))
            app_received = _to_int(device.get("total_bytes_received"))
            app_total = app_sent + app_received

            control_sent = _to_int(device.get("control_bytes_sent"))
            control_received = _to_int(device.get("control_bytes_received"))
            control_total = control_sent + control_received

            total_sent = app_sent + control_sent
            total_received = app_received + control_received
            total_all = app_total + control_total

            device["total_bytes_sent_app"] = app_sent
            device["total_bytes_received_app"] = app_received
            device["total_bytes_app"] = app_total

            device["total_bytes_sent_control"] = control_sent
            device["total_bytes_received_control"] = control_received
            device["total_bytes_control"] = control_total

            device["total_bytes_sent_total"] = total_sent
            device["total_bytes_received_total"] = total_received
            device["total_bytes_total"] = total_all

            device["bytes_sent_app"] = app_sent
            device["bytes_received_app"] = app_received
            device["bytes_sent_control"] = control_sent
            device["bytes_received_control"] = control_received
            device["bytes_sent_total"] = total_sent
            device["bytes_received_total"] = total_received
            device["control_overhead_ratio"] = round((control_total / total_all), 4) if total_all else 0.0

            if include_control:
                device["total_bytes_sent"] = total_sent
                device["total_bytes_received"] = total_received
                device["total_bytes"] = total_all
                device["total_packets"] = _to_int(device.get("total_packets")) + _to_int(device.get("control_packets"))
            else:
                device["total_bytes_sent"] = app_sent
                device["total_bytes_received"] = app_received
                device["total_bytes"] = app_total
                device["total_packets"] = _to_int(device.get("total_packets"))

            _resolve_and_persist_hostname(device, conn=conn)

            since = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                SELECT
                    SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END) AS total_bytes_24h_app,
                    SUM(CASE WHEN COALESCE(is_control, 0) = 1 THEN bytes_transferred ELSE 0 END) AS total_bytes_24h_control,
                    SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN 1 ELSE 0 END) AS packet_count_24h_app,
                    SUM(CASE WHEN COALESCE(is_control, 0) = 1 THEN 1 ELSE 0 END) AS packet_count_24h_control
                FROM (
                    SELECT bytes_transferred, is_control FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                    UNION ALL
                    SELECT bytes_transferred, is_control FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                )
            """, (ip_address, since, ip_address, since))
            traffic = cursor.fetchone()

            bytes_24h_app = (traffic["total_bytes_24h_app"] or 0) if traffic else 0
            bytes_24h_control = (traffic["total_bytes_24h_control"] or 0) if traffic else 0
            packets_24h_app = (traffic["packet_count_24h_app"] or 0) if traffic else 0
            packets_24h_control = (traffic["packet_count_24h_control"] or 0) if traffic else 0

            device["total_bytes_24h_app"] = bytes_24h_app
            device["total_bytes_24h_control"] = bytes_24h_control
            device["total_bytes_24h_total"] = bytes_24h_app + bytes_24h_control

            device["packet_count_24h_app"] = packets_24h_app
            device["packet_count_24h_control"] = packets_24h_control
            device["packet_count_24h_total"] = packets_24h_app + packets_24h_control

            if include_control:
                device["total_bytes_24h"] = bytes_24h_app + bytes_24h_control
                device["packet_count_24h"] = packets_24h_app + packets_24h_control
            else:
                device["total_bytes_24h"] = bytes_24h_app
                device["packet_count_24h"] = packets_24h_app

            protocol_filter = "" if include_control else "AND COALESCE(is_control, 0) = 0"

            cursor.execute(f"""
                SELECT protocol, COUNT(*) AS count, SUM(bytes_transferred) AS bytes
                FROM (
                    SELECT protocol, bytes_transferred FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                        {protocol_filter}
                    UNION ALL
                    SELECT protocol, bytes_transferred FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                        {protocol_filter}
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

            _device_cache.set(cache_key, device)
            return device

    except sqlite3.Error as e:
        logger.error("get_device_details error: %s", e)
        return None


@time_query
def get_device_control_overhead(hours: int = 1, limit: int = 50) -> list:
    """Return per-device app/control byte split for the recent window."""
    hours = min(max(hours, 1), 168)
    limit = min(max(limit, 1), 500)
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                WITH device_bytes AS (
                    SELECT
                        source_mac AS mac_address,
                        source_ip AS ip_address,
                        SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END) AS app_bytes,
                        SUM(CASE WHEN COALESCE(is_control, 0) = 1 THEN bytes_transferred ELSE 0 END) AS control_bytes
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        AND (({_PRIVATE_IP_FILTER_SOURCE}) OR source_ip LIKE '%:%')
                    GROUP BY source_mac, source_ip

                    UNION ALL

                    SELECT
                        dest_mac AS mac_address,
                        dest_ip AS ip_address,
                        SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END) AS app_bytes,
                        SUM(CASE WHEN COALESCE(is_control, 0) = 1 THEN bytes_transferred ELSE 0 END) AS control_bytes
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_DEST}
                        AND (({_PRIVATE_IP_FILTER_DEST}) OR dest_ip LIKE '%:%')
                    GROUP BY dest_mac, dest_ip
                )
                SELECT
                    mac_address,
                    COALESCE(
                        MAX(CASE WHEN ip_address NOT LIKE '%:%' THEN ip_address END),
                        MAX(ip_address)
                    ) AS ip_address,
                    SUM(app_bytes) AS app_bytes,
                    SUM(control_bytes) AS control_bytes,
                    SUM(app_bytes) + SUM(control_bytes) AS total_bytes
                FROM device_bytes
                GROUP BY mac_address
                HAVING total_bytes > 0
                ORDER BY control_bytes DESC, total_bytes DESC
                LIMIT ?
            """, (since, since, limit))

            rows = [dict_from_row(r) for r in cursor.fetchall()]
            if not rows:
                return []

            macs = [r.get("mac_address", "") for r in rows if r.get("mac_address")]
            hostnames = {}
            if macs:
                ph = ",".join("?" for _ in macs)
                cursor.execute(
                    f"SELECT mac_address, hostname, device_name FROM devices WHERE mac_address IN ({ph})",
                    tuple(macs),
                )
                for r in cursor.fetchall():
                    hostnames[r["mac_address"]] = r["hostname"] or r["device_name"] or ""

            for d in rows:
                app_bytes = _to_int(d.get("app_bytes"))
                control_bytes = _to_int(d.get("control_bytes"))
                total_bytes = _to_int(d.get("total_bytes"))
                d["hostname"] = hostnames.get(d.get("mac_address", ""), d.get("ip_address", ""))
                d["control_overhead_ratio"] = round((control_bytes / total_bytes), 4) if total_bytes else 0.0
                d["app_bytes_formatted"] = _format_bytes(app_bytes)
                d["control_bytes_formatted"] = _format_bytes(control_bytes)
                d["total_bytes_formatted"] = _format_bytes(total_bytes)

            rows = _strip_host_devices(rows)
            return rows
    except sqlite3.Error as e:
        logger.error("get_device_control_overhead error: %s", e)
        return []


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
