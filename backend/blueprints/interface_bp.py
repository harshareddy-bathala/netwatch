"""
interface_bp.py - Interface Status Endpoints Blueprint
=======================================================
"""

import logging

from flask import Blueprint, jsonify, request

from backend.helpers import handle_errors, cached_response, get_iface_manager, clear_response_cache

logger = logging.getLogger(__name__)

interface_bp = Blueprint('interface', __name__)


@interface_bp.route('/api/interface/status')
@cached_response('interface_status')
@handle_errors
def get_interface_status():
    """Get current network interface monitoring status."""
    try:
        mgr = get_iface_manager()
        if mgr:
            return jsonify({'data': mgr.get_status()})
        return jsonify({'data': {'mode': 'none', 'mode_display': 'Not Running', 'is_active': False}})
    except Exception as e:
        logger.error("Error getting interface status: %s", e)
        return jsonify({'error': 'Internal error during interface detection', 'code': 'INTERNAL_ERROR'}), 500


@interface_bp.route('/api/interface/refresh', methods=['POST'])
@handle_errors
def refresh_interface():
    """Refresh network interface detection."""
    try:
        mgr = get_iface_manager()
        if mgr:
            mgr.refresh_now()
            # Invalidate all response caches so next fetch gets fresh data
            clear_response_cache()
            try:
                from backend.blueprints.bandwidth_bp import invalidate_sse_cache
                invalidate_sse_cache()
            except ImportError:
                pass
            return jsonify({'data': {'success': True, 'message': 'Interface detection refreshed', 'status': mgr.get_status()}})
        return jsonify({'error': 'Interface manager not running', 'code': 'UNAVAILABLE'}), 503
    except Exception as e:
        logger.error("Error refreshing interface: %s", e)
        return jsonify({'error': 'Failed to refresh interface', 'code': 'FAILED'}), 500


@interface_bp.route('/api/interface/list')
@handle_errors
def list_interfaces():
    """List all available network interfaces."""
    try:
        from packet_capture.mode_detector import ModeDetector
        detector = ModeDetector()
        interfaces = detector._enumerate_interfaces()
        mgr = get_iface_manager()
        current_mode = mgr.get_current_mode() if mgr else None
        return jsonify({'data': {
            'interfaces': [
                {'name': i.name, 'friendly_name': i.friendly_name,
                 'ip_address': i.ip_address, 'is_active': i.is_active}
                for i in interfaces
            ],
            'count': len(interfaces),
            'current': current_mode.interface.name if current_mode else None,
            'mode': current_mode.get_mode_name().value if current_mode else 'none',
        }})
    except Exception as e:
        logger.error("Error listing interfaces: %s", e)
        return jsonify({'error': 'Failed to list interfaces', 'code': 'FAILED'}), 500


@interface_bp.route('/api/interface/select', methods=['POST'])
@handle_errors
def select_interface():
    """Manually select a network interface for monitoring."""
    data = request.get_json()
    if not data or 'interface' not in data:
        return jsonify({'error': 'interface parameter required', 'code': 'MISSING_FIELDS'}), 400

    interface_name = data['interface']

    mgr = get_iface_manager()
    if not mgr:
        return jsonify({'error': 'Interface manager not running', 'code': 'UNAVAILABLE'}), 503

    try:
        new_mode = mgr.select_interface(interface_name)
        return jsonify({'data': {
            'success': True,
            'message': f'Switched to interface {interface_name}',
            'mode': new_mode.get_mode_name().value,
            'status': mgr.get_status(),
        }})
    except ValueError as e:
        return jsonify({'error': str(e), 'code': 'NOT_FOUND'}), 404
    except Exception as e:
        logger.error("Error selecting interface '%s': %s", interface_name, e)
        return jsonify({'error': 'Failed to select interface', 'code': 'FAILED'}), 500
