"""
discovery_bp.py - Network Discovery Endpoints Blueprint
========================================================
"""

import logging

from flask import Blueprint, jsonify, request

from backend.helpers import (
    handle_errors, get_iface_manager, get_active_subnet, _discovery_lock,
)

logger = logging.getLogger(__name__)

discovery_bp = Blueprint('discovery', __name__)


@discovery_bp.route('/api/discovery/devices')
@handle_errors
def get_discovered_devices():
    """Get all devices discovered through network scanning."""
    try:
        from packet_capture.network_discovery import FullNetworkScanner

        mgr = get_iface_manager()
        if not mgr:
            return jsonify({'data': [], 'meta': {'count': 0}, 'error': 'Interface manager not running'}), 503

        status = mgr.get_status()
        iface = status.get('interface') or status.get('name')
        if not iface:
            mode = mgr.get_current_mode()
            iface = mode.interface.name if mode else None
        if not iface:
            return jsonify({'data': [], 'meta': {'count': 0}, 'error': 'No active network interface'}), 503

        scanner = FullNetworkScanner(interface=iface)
        devices = scanner.discovery.get_all_devices()

        ip = status.get('ip_address', '')
        network = 'unknown'
        if ip:
            network, _ = get_active_subnet(ip)

        return jsonify({
            'data': devices,
            'meta': {
                'count': len(devices), 'network': network, 'interface': iface,
                'discovery_methods': ['arp', 'ping', 'mdns', 'passive'],
            },
        })
    except ImportError as e:
        logger.warning("Network discovery module not available: %s", e)
        return jsonify({'data': [], 'meta': {'count': 0}, 'error': 'Network discovery module not available'}), 501
    except Exception as e:
        logger.error("Error getting discovered devices: %s", e)
        return jsonify({'data': [], 'meta': {'count': 0}, 'error': 'Failed to retrieve discovered devices'}), 500


@discovery_bp.route('/api/discovery/scan', methods=['POST'])
@handle_errors
def trigger_network_scan():
    """Trigger an immediate network scan to discover devices."""
    try:
        from flask import current_app
        from packet_capture.network_discovery import NetworkDiscovery

        mgr = get_iface_manager()
        if not mgr:
            return jsonify({'error': 'Interface manager not running', 'code': 'UNAVAILABLE', 'data': []}), 503

        mode = mgr.get_current_mode()
        iface = mode.interface.name if mode else None
        ip = mode.interface.ip_address if mode else None
        if not iface:
            return jsonify({'error': 'No active network interface', 'code': 'NO_IFACE', 'data': []}), 503

        network = None
        if ip:
            network, _ = get_active_subnet(ip)

        with _discovery_lock:
            discovery = current_app.config.get('_DISCOVERY_SINGLETON')
            if (discovery is None
                    or getattr(discovery, 'interface', None) != iface
                    or getattr(discovery, 'subnet', None) != network):
                discovery = NetworkDiscovery(interface=iface, subnet=network)
                current_app.config['_DISCOVERY_SINGLETON'] = discovery

        devices = discovery.arp_scan(timeout=3)
        return jsonify({
            'data': devices,
            'meta': {
                'count': len(devices), 'success': True,
                'network': network or 'auto-detected', 'interface': iface,
                'scan_type': 'arp', 'message': f'Discovered {len(devices)} devices',
            },
        })
    except ImportError as e:
        logger.warning("Network discovery module not available: %s", e)
        return jsonify({'error': 'Network discovery module not available', 'code': 'UNAVAILABLE', 'data': []}), 501
    except PermissionError:
        return jsonify({'error': 'Administrator/root privileges required', 'code': 'PERMISSION', 'data': []}), 403
    except Exception as e:
        logger.error("Error during network scan: %s", e)
        return jsonify({'error': 'Network scan failed', 'code': 'SCAN_FAILED', 'data': []}), 500


@discovery_bp.route('/api/discovery/capabilities')
@handle_errors
def get_discovery_capabilities():
    """Get current network discovery capabilities."""
    try:
        mgr = get_iface_manager()
        status = mgr.get_status() if mgr else {}
        capabilities = status.get('capabilities', {})
        return jsonify({'data': {
            'mode': status.get('mode', 'unknown'),
            'mode_display': status.get('mode_display', 'Unknown'),
            'interface': status.get('interface') or status.get('name'),
            'ip_address': status.get('ip_address'),
            'capabilities': capabilities,
            'features': {
                'arp_scanning': capabilities.get('can_arp_scan', False),
                'promiscuous_mode': capabilities.get('promiscuous_available', False),
                'full_traffic_capture': capabilities.get('can_see_all_traffic', False),
                'device_discovery': capabilities.get('can_discover_devices', True),
                'port_mirror_support': capabilities.get('port_mirror_support', False),
            },
            'description': status.get('description', ''),
        }})
    except Exception as e:
        logger.error("Error getting discovery capabilities: %s", e)
        return jsonify({'error': 'Failed to retrieve discovery capabilities', 'code': 'FAILED'}), 500


@discovery_bp.route('/api/discovery/port-mirror-status')
@handle_errors
def get_port_mirror_status():
    """Check if the current interface appears to be connected to a port mirror/SPAN."""
    try:
        from packet_capture.network_discovery import PortMirrorDetector

        mgr = get_iface_manager()
        mode = mgr.get_current_mode() if mgr else None
        iface = mode.interface.name if mode else None
        if not iface:
            return jsonify({'data': {'detected': False, 'description': 'No active interface', 'interface': None}})

        is_mirror, description = PortMirrorDetector.detect_port_mirror(interface=iface, duration=5)
        return jsonify({'data': {
            'detected': is_mirror, 'interface': iface, 'description': description,
            'recommendation': (
                'Full network monitoring available - all traffic visible' if is_mirror
                else 'Normal connection - use ARP scanning for device discovery'
            ),
        }})
    except ImportError as e:
        logger.warning("Port mirror detection module not available: %s", e)
        return jsonify({'data': {'detected': False, 'description': 'Port mirror detection module not available'}}), 501
    except Exception as e:
        logger.error("Error detecting port mirror: %s", e)
        return jsonify({'data': {'detected': False, 'description': 'Detection error occurred'}}), 500


@discovery_bp.route('/api/geoip/<ip_address>')
@handle_errors
def get_geoip(ip_address):
    """Return GeoIP info for an external IP."""
    from backend.helpers import is_valid_ip
    if not is_valid_ip(ip_address):
        return jsonify({'error': 'Invalid IP address format', 'code': 'INVALID_IP'}), 400
    from packet_capture.geoip import lookup_ip
    info = lookup_ip(ip_address)
    if info:
        return jsonify({'data': info})
    return jsonify({'error': 'No GeoIP data available', 'code': 'NOT_FOUND'}), 404


@discovery_bp.route('/api/geoip/batch', methods=['POST'])
@handle_errors
def get_geoip_batch():
    """Return GeoIP info for up to 100 IPs."""
    from backend.helpers import is_valid_ip
    data = request.get_json()
    if not data or 'ips' not in data:
        return jsonify({'error': 'ips array required', 'code': 'MISSING_FIELDS'}), 400
    if not isinstance(data['ips'], list):
        return jsonify({'error': 'ips must be an array', 'code': 'VALIDATION'}), 400
    raw_ips = data['ips'][:100]
    invalid_ips = [ip for ip in raw_ips if not is_valid_ip(str(ip))]
    if invalid_ips:
        return jsonify({'error': f'Invalid IP addresses: {invalid_ips[:5]}', 'code': 'VALIDATION'}), 400
    from packet_capture.geoip import lookup_batch
    results = lookup_batch(raw_ips)
    return jsonify({'data': results})
