"""
devices_bp.py - Device Endpoints Blueprint
============================================
"""

import re
import logging

from flask import Blueprint, jsonify, request

from database.db_handler import (
    get_top_devices, get_all_devices, get_device_details, update_device_name,
)
from database.queries import network_filters as _nf
from backend.helpers import handle_errors, clear_response_cache, is_valid_ip

logger = logging.getLogger(__name__)

devices_bp = Blueprint('devices', __name__)


def _parse_include_control(default: bool = False) -> bool:
    """Parse include_control query flag from request args."""
    raw = request.args.get('include_control')
    if raw is None:
        return default
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'on'}


def _device_identity(device: dict) -> str:
    """Stable identity for API-side device merging."""
    mac = str(device.get('mac_address') or '').strip().lower().replace('-', ':')
    if mac:
        return f"mac:{mac}"
    ip = str(device.get('ip_address') or '').strip()
    if ip:
        return f"ip:{ip}"
    return ''


def _to_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _drop_host_rows(devices: list) -> list:
    """Remove the monitoring host / gateway from the final device list.

    The DB query excludes it, but the hotspot realtime-merge
    (_merge_hotspot_realtime_devices) can re-add it from in-memory state, and
    the hotspot virtual-adapter MAC is sometimes invisible to psutil — so the
    host reappears with usage == the sum of every client's NAT-forwarded
    traffic. Filter by BOTH MAC and IP (our_ip catches it even when the MAC
    isn't detected), from the same identity the dashboard uses."""
    try:
        from utils.realtime_state import dashboard_state
        ident = dashboard_state.get_host_identity()
        macs = {m.lower() for m in (ident.get("macs") or set())}
        ips = set(ident.get("ips") or set())
    except Exception:
        return devices
    if not macs and not ips:
        return devices
    out = []
    for d in devices:
        mac = str(d.get("mac_address") or "").lower().replace("-", ":")
        ip = str(d.get("ip_address") or "").strip()
        if mac and mac in macs:
            continue
        if ip and ip in ips:
            continue
        out.append(d)
    return out


def _dedupe_by_hostname(devices: list) -> list:
    """Collapse rows that are the same physical device seen under two MACs.

    Phones use per-connection MAC randomization and can also raise a second
    row from an IPv6 link-local frame, so one device shows twice (both in the
    devices list and the parental dropdown). When two rows share a real
    hostname, keep the most-recently-seen one. Rows without a hostname pass
    through untouched (still keyed by their unique MAC)."""
    best: dict = {}
    passthrough: list = []
    order: list = []
    for d in devices:
        hn = str(d.get('hostname') or d.get('device_name') or '').strip().lower()
        ip = str(d.get('ip_address') or '').strip().lower()
        # Only dedupe on a meaningful hostname (not empty, not the bare IP).
        if not hn or hn == ip:
            passthrough.append(d)
            continue
        cur = best.get(hn)
        if cur is None:
            best[hn] = d
            order.append(hn)
        elif str(d.get('last_seen') or '') > str(cur.get('last_seen') or ''):
            best[hn] = d
    return [best[h] for h in order] + passthrough


def _merge_hotspot_realtime_devices(
    db_rows: list,
    include_control: bool,
    limit: int,
    offset: int,
) -> list:
    """Merge hotspot in-memory rows into DB rows for realtime parity."""
    if _nf._current_mode_name != 'hotspot':
        return db_rows

    try:
        from utils.realtime_state import dashboard_state

        mem_limit = max(limit + offset + 50, 100)
        mem_rows = dashboard_state.get_top_devices_memory(
            limit=mem_limit,
            include_control=include_control,
        )
    except Exception as exc:
        logger.debug("hotspot device merge skipped: %s", exc)
        return db_rows

    if not mem_rows:
        return db_rows

    merged = [dict(row) for row in (db_rows or [])]
    by_key = {}
    for row in merged:
        key = _device_identity(row)
        if key:
            by_key[key] = row

    metric_fields = (
        'bytes_sent', 'bytes_received', 'total_bytes',
        'bytes_sent_app', 'bytes_received_app', 'total_bytes_app',
        'bytes_sent_control', 'bytes_received_control', 'total_bytes_control',
        'bytes_sent_total', 'bytes_received_total', 'total_bytes_total',
        'packet_count', 'packet_count_app', 'packet_count_control', 'packet_count_total',
        'today_bytes', 'today_sent', 'today_received',
        'today_bytes_app', 'today_control_bytes', 'today_control_sent',
        'today_control_received', 'today_bytes_total',
        'control_overhead_ratio',
    )

    for mem in mem_rows:
        key = _device_identity(mem)
        if not key:
            continue

        existing = by_key.get(key)
        if existing is None:
            new_row = dict(mem)
            merged.append(new_row)
            by_key[key] = new_row
            continue

        mem_seen = str(mem.get('last_seen') or '')
        cur_seen = str(existing.get('last_seen') or '')
        if mem_seen and mem_seen > cur_seen:
            existing['last_seen'] = mem_seen

        if mem.get('ip_address') and not existing.get('ip_address'):
            existing['ip_address'] = mem.get('ip_address')
        if mem.get('hostname') and not existing.get('hostname'):
            existing['hostname'] = mem.get('hostname')
        if mem.get('device_name') and not existing.get('device_name'):
            existing['device_name'] = mem.get('device_name')
        if mem.get('vendor') and not existing.get('vendor'):
            existing['vendor'] = mem.get('vendor')

        for field in metric_fields:
            if field in mem and mem[field] is not None:
                existing[field] = mem[field]

    merged.sort(key=lambda d: _to_int(d.get('total_bytes')), reverse=True)
    return merged


@devices_bp.route('/api/devices/top')
@handle_errors
def get_top_devices_endpoint():
    """Get top devices by bandwidth usage."""
    limit = request.args.get('limit', 10, type=int)
    hours = request.args.get('hours', 1, type=int)
    include_control = _parse_include_control(default=False)
    limit = min(max(limit, 1), 100)
    hours = min(max(hours, 1), 168)
    devices = get_top_devices(limit=limit, hours=hours, include_control=include_control)
    return jsonify({
        'devices': devices,
        'data': devices,
        'meta': {
            'count': len(devices),
            'limit': limit,
            'hours': hours,
            'include_control': include_control,
        },
    })


def _apply_usage_today(devices: list) -> list:
    """Report each device's usage **today**, from the same source Controls uses.

    The Devices page and the Controls page disagreed wildly for the same phone
    — 4.4 MB against 53.5 MB. Both were "right": in hotspot mode the device
    list summed ``traffic_summary`` over the presence window, which is
    HOTSPOT_STALE_DEVICE_SECONDS (180s), so its "Usage" column was really
    "usage in the last three minutes". Nobody reads a column labelled Usage
    that way.

    The window is there to decide *which devices are still here*, which is a
    different question from *how much have they used*. Row selection keeps it;
    the number now comes from ``get_usage_today_by_mac`` — the one function
    Controls and quota enforcement already use, so the two pages cannot drift
    apart again.
    """
    if not devices:
        return devices
    try:
        from database.queries.policy_queries import get_usage_today_by_mac
        usage = get_usage_today_by_mac()
    except Exception as exc:
        logger.debug("usage-today enrichment unavailable: %s", exc)
        return devices

    for d in devices:
        mac = (d.get('mac_address') or '').lower().replace('-', ':')
        if not mac or mac not in usage:
            continue
        today = int(usage[mac])
        d['usage_today_bytes'] = today
        # The list's headline number. Keep the raw windowed figures under
        # their own keys so nothing that wants "recent activity" is lost.
        d['total_bytes_window'] = d.get('total_bytes')
        d['total_bytes'] = today
        d['total_bytes_app'] = today
    return devices


@devices_bp.route('/api/devices')
@handle_errors
def get_devices():
    """Get all devices."""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    include_control = _parse_include_control(default=False)
    limit = min(max(limit, 1), 500)
    offset = max(offset, 0)

    fetch_limit = min(max(limit + offset, limit), 500)
    devices = get_all_devices(limit=fetch_limit, offset=0, include_control=include_control)
    devices = _merge_hotspot_realtime_devices(
        devices,
        include_control=include_control,
        limit=limit,
        offset=offset,
    )
    devices = _drop_host_rows(devices)
    devices = _dedupe_by_hostname(devices)
    devices = _apply_usage_today(devices)
    devices = devices[offset:offset + limit]

    return jsonify({
        'devices': devices,
        'data': devices,
        'meta': {
            'count': len(devices),
            'limit': limit,
            'offset': offset,
            'include_control': include_control,
        },
    })


@devices_bp.route('/api/devices/<ip_address>')
@handle_errors
def get_device(ip_address):
    """Get details for a specific device."""
    if not is_valid_ip(ip_address):
        return jsonify({'error': 'Invalid IP address format', 'code': 'INVALID_IP'}), 400
    include_control = _parse_include_control(default=False)
    device = get_device_details(ip_address, include_control=include_control)
    if device:
        # Merge in-memory last_seen when it's more recent than the DB value.
        # The device list uses real-time in-memory state, but device detail
        # queries the DB — this closes the gap so both views agree.
        try:
            from utils.realtime_state import dashboard_state
            mem_dev = dashboard_state.get_device_by_ip(ip_address, include_control=include_control)
            if mem_dev and mem_dev.get("last_seen"):
                db_last_seen = device.get("last_seen", "")
                mem_last_seen = mem_dev["last_seen"]
                # Compare as strings (ISO format sorts correctly)
                if mem_last_seen > db_last_seen:
                    device["last_seen"] = mem_last_seen
        except Exception:
            pass
        return jsonify({'data': device})
    return jsonify({'error': 'Device not found', 'code': 'NOT_FOUND'}), 404


@devices_bp.route('/api/devices/update-name', methods=['POST'])
@handle_errors
def update_device_name_endpoint():
    """Update device hostname."""
    data = request.get_json()
    if not data:
        logger.warning("update-name: no JSON body")
        return jsonify({'error': 'No data provided', 'code': 'NO_DATA'}), 400

    ip_address = (data.get('ip_address') or data.get('ip') or data.get('mac', '')).strip()
    hostname = (data.get('hostname') or data.get('name', '')).strip()

    logger.info("update-name request: ip=%s hostname=%s", ip_address, hostname)

    if not ip_address or not hostname:
        return jsonify({'error': 'ip_address and hostname required', 'code': 'MISSING_FIELDS'}), 400

    if len(hostname) > 255:
        return jsonify({'error': 'hostname too long (max 255 chars)', 'code': 'VALIDATION'}), 400
    if not re.match(r'^[\w\s.\-()\'\'\u00C0-\u024F]+$', hostname):
        return jsonify({'error': 'hostname contains invalid characters', 'code': 'VALIDATION'}), 400

    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address)
    is_mac = re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', ip_address)
    if not is_ip and not is_mac:
        return jsonify({'error': 'invalid IP or MAC address format', 'code': 'VALIDATION'}), 400
    if is_mac:
        ip_address = ip_address.lower().replace('-', ':')

    success = update_device_name(ip_address, hostname)
    if success:
        clear_response_cache()
        return jsonify({'data': {'success': True, 'message': f'Device {ip_address} renamed to {hostname}'}})
    return jsonify({'error': 'Device not found or update failed', 'code': 'NOT_FOUND'}), 404
