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
from backend.helpers import handle_errors, cached_response, clear_response_cache, is_valid_ip

logger = logging.getLogger(__name__)

devices_bp = Blueprint('devices', __name__)


@devices_bp.route('/api/devices/top')
@handle_errors
def get_top_devices_endpoint():
    """Get top devices by bandwidth usage."""
    limit = request.args.get('limit', 10, type=int)
    hours = request.args.get('hours', 1, type=int)
    limit = min(max(limit, 1), 100)
    hours = min(max(hours, 1), 168)
    devices = get_top_devices(limit=limit, hours=hours)
    return jsonify({
        'data': devices,
        'meta': {'count': len(devices), 'limit': limit, 'hours': hours},
    })


@devices_bp.route('/api/devices')
@cached_response('devices')
@handle_errors
def get_devices():
    """Get all devices."""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    devices = get_all_devices(limit=limit, offset=offset)
    return jsonify({
        'data': devices,
        'meta': {'count': len(devices), 'limit': limit, 'offset': offset},
    })


@devices_bp.route('/api/devices/<ip_address>')
@handle_errors
def get_device(ip_address):
    """Get details for a specific device."""
    if not is_valid_ip(ip_address):
        return jsonify({'error': 'Invalid IP address format', 'code': 'INVALID_IP'}), 400
    device = get_device_details(ip_address)
    if device:
        # Merge in-memory last_seen when it's more recent than the DB value.
        # The device list uses real-time in-memory state, but device detail
        # queries the DB — this closes the gap so both views agree.
        try:
            from utils.realtime_state import dashboard_state
            mem_dev = dashboard_state.get_device_by_ip(ip_address)
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
