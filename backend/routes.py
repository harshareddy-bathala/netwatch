"""
routes.py - REST API Endpoint Definitions
==========================================

Complete REST API routes for the NetWatch backend.
"""

import os
import sys
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request

# Add project root to path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import APP_VERSION, ENABLE_DATA_EXPORT
from database.db_handler import (
    get_realtime_stats, get_top_devices, get_protocol_distribution,
    get_bandwidth_history, get_alerts, get_health_score, update_device_name,
    get_dashboard_data, get_device_details, get_all_devices,
    get_alert_summary, acknowledge_alert, create_alert, get_traffic_summary,
    get_bandwidth_history_dual, get_device_count, get_recent_activity,
    resolve_alert, count_alerts,
)

# Setup logging
logger = logging.getLogger(__name__)

# Track API start time
API_START_TIME = datetime.now()

# =============================================================================
# RESPONSE CACHING - Reduces database load for frequently requested data
# =============================================================================

# In-memory cache with TTL and max-size cap
_response_cache = {}
CACHE_TTL = 2  # seconds - responses are cached for 2 seconds
CACHE_MAX_SIZE = 50  # Maximum number of cached responses

def cached_response(cache_key, ttl=CACHE_TTL):
    """
    Decorator for caching API responses.
    Prevents redundant database queries for frequently requested endpoints.
    
    Args:
        cache_key: Unique key for this endpoint's cache
        ttl: Time-to-live in seconds (default 2)
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            from time import time
            now = time()
            
            # Check cache
            if cache_key in _response_cache:
                cached_data, timestamp = _response_cache[cache_key]
                if now - timestamp < ttl:
                    # Return cached response
                    return jsonify(cached_data)
            
            # Call the actual function
            result = f(*args, **kwargs)
            
            # Cache the response data (extract JSON from response)
            try:
                if hasattr(result, 'get_json'):
                    # Evict oldest if at capacity
                    if len(_response_cache) >= CACHE_MAX_SIZE:
                        oldest_key = min(_response_cache, key=lambda k: _response_cache[k][1])
                        del _response_cache[oldest_key]
                    _response_cache[cache_key] = (result.get_json(), now)
                elif isinstance(result, tuple):
                    if len(_response_cache) >= CACHE_MAX_SIZE:
                        oldest_key = min(_response_cache, key=lambda k: _response_cache[k][1])
                        del _response_cache[oldest_key]
                    _response_cache[cache_key] = (result[0].get_json(), now)
            except Exception:
                pass  # Don't cache if there's an issue
            
            return result
        return wrapper
    return decorator


def clear_response_cache():
    """Clear all cached responses. Useful after data mutations."""
    global _response_cache
    _response_cache = {}


def handle_errors(f):
    """Decorator to handle errors in API endpoints. Never leaks exception details."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error("API error in %s: %s", f.__name__, e, exc_info=True)
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred. Check server logs for details.'
            }), 500
    return decorated


def register_routes(app: Flask) -> None:
    """Register all API routes with the Flask app."""

    # ── Helpers to get the live engine / interface manager from app.config ──
    def _get_engine():
        """Return the current CaptureEngine (or None)."""
        return app.config.get('CAPTURE_ENGINE')

    def _get_iface_manager():
        """Return the current InterfaceManager (or None)."""
        return app.config.get('INTERFACE_MANAGER')
    
    # =========================================================================
    # STATUS & SYSTEM ENDPOINTS
    # =========================================================================
    
    # =========================================================================
    # REAL-TIME STATS ENDPOINTS
    # =========================================================================
    
    @app.route('/api/stats/realtime')
    @cached_response('realtime_stats')
    @handle_errors
    def get_realtime():
        """Get real-time network statistics."""
        # Inject live bandwidth from CaptureEngine if available
        engine = _get_engine()
        live_bw = None
        if engine and engine.is_running:
            live_bw = engine.bandwidth.get_current_bps()
        stats = get_realtime_stats(live_bandwidth_bps=live_bw)
        return jsonify(stats)
    
    @app.route('/api/dashboard')
    @handle_errors
    def get_dashboard():
        """
        Get comprehensive dashboard data - ALL data in a single call.
        Reduces 8+ individual API calls to 1, cutting request volume by ~90%.
        """
        base = get_dashboard_data()  # stats, health, top_devices, protocols, etc.

        # Enrich with fields the SPA expects
        result = {
            'stats': base.get('stats'),
            'health': base.get('health'),
            'devices': base.get('top_devices'),
            'protocols': base.get('protocols'),
            'bandwidth': base.get('bandwidth_history'),
            'alerts': base.get('alerts'),
        }

        # Inject live bandwidth into stats from CaptureEngine
        engine = _get_engine()
        if engine and engine.is_running:
            bw_stats = engine.bandwidth.get_stats()
            if result.get('stats'):
                result['stats']['bandwidth_bps'] = round(bw_stats['total_bps'], 2)
                result['stats']['bandwidth_mbps'] = bw_stats['total_mbps']
                result['stats']['upload_bps'] = round(bw_stats['upload_bps'], 2)
                result['stats']['download_bps'] = round(bw_stats['download_bps'], 2)
                result['stats']['upload_mbps'] = bw_stats['upload_mbps']
                result['stats']['download_mbps'] = bw_stats['download_mbps']
                result['stats']['packets_per_second'] = bw_stats['packets_per_second']

        # Alert stats for badge counts — uses a SINGLE DB call instead of 5
        try:
            from database.connection import get_connection as _get_conn
            with _get_conn() as conn:
                cursor = conn.cursor()
                # All unresolved counts by severity in one query
                cursor.execute("""
                    SELECT severity, COUNT(*) AS cnt,
                           SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) AS unack
                    FROM alerts WHERE resolved = 0 GROUP BY severity
                """)
                total_unresolved = 0
                total_unack = 0
                by_severity = {'critical': 0, 'warning': 0, 'info': 0}
                for row in cursor.fetchall():
                    sev = row['severity'] if isinstance(row, dict) else row[0]
                    cnt = row['cnt'] if isinstance(row, dict) else row[1]
                    unack = row['unack'] if isinstance(row, dict) else row[2]
                    total_unresolved += cnt
                    total_unack += (unack or 0)
                    if sev in by_severity:
                        by_severity[sev] = cnt
                result['alert_stats'] = {
                    'total_unresolved': total_unresolved,
                    'unacknowledged': total_unack,
                    'by_severity': by_severity,
                }
        except Exception:
            result['alert_stats'] = None

        # Interface / mode info — use InterfaceManager (cached, never resets to NONE)
        try:
            mgr = _get_iface_manager()
            if mgr:
                result['mode'] = mgr.get_status()
            else:
                result['mode'] = {'mode': 'none', 'mode_display': 'Unknown'}
        except Exception:
            result['mode'] = {'mode': 'none', 'mode_display': 'Unknown'}

        # Dual bandwidth for download/upload chart (10s granularity for 1H view)
        try:
            result['bandwidth'] = {
                'history': get_bandwidth_history_dual(hours=1, interval='10s')
            }
        except Exception:
            pass  # keep original bandwidth_history

        return jsonify(result)
    
    # =========================================================================
    # DEVICE ENDPOINTS
    # =========================================================================
    
    @app.route('/api/devices/top')
    @handle_errors
    def get_top_devices_endpoint():
        """Get top devices by bandwidth usage."""
        limit = request.args.get('limit', 10, type=int)
        hours = request.args.get('hours', 1, type=int)
        
        # Clamp values
        limit = min(max(limit, 1), 100)
        hours = min(max(hours, 1), 168)
        
        devices = get_top_devices(limit=limit, hours=hours)
        return jsonify({
            'devices': devices,
            'count': len(devices),
            'limit': limit,
            'hours': hours
        })
    
    @app.route('/api/devices')
    @handle_errors
    def get_devices():
        """Get all devices."""
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        devices = get_all_devices(limit=limit, offset=offset)
        return jsonify({
            'devices': devices,
            'count': len(devices),
            'limit': limit,
            'offset': offset
        })
    
    @app.route('/api/devices/<ip_address>')
    @handle_errors
    def get_device(ip_address):
        """Get details for a specific device."""
        device = get_device_details(ip_address)
        if device:
            return jsonify(device)
        return jsonify({'error': 'Device not found'}), 404
    
    @app.route('/api/devices/update-name', methods=['POST'])
    @handle_errors
    def update_device_name_endpoint():
        """Update device hostname."""
        data = request.get_json()
        
        if not data:
            logger.warning("update-name: no JSON body")
            return jsonify({'error': 'No data provided'}), 400
        
        # Accept both 'ip_address' and 'ip' / 'mac' for flexibility
        ip_address = (data.get('ip_address') or data.get('ip') or data.get('mac', '')).strip()
        hostname = (data.get('hostname') or data.get('name', '')).strip()
        
        logger.info("update-name request: ip=%s hostname=%s", ip_address, hostname)
        
        if not ip_address or not hostname:
            return jsonify({'error': 'ip_address and hostname required'}), 400

        # Input validation
        import re as _re
        if len(hostname) > 255:
            return jsonify({'error': 'hostname too long (max 255 chars)'}), 400
        # Allow letters, numbers, spaces, hyphens, dots, parens, apostrophes, accented chars
        if not _re.match(r'^[\w\s.\-()\'\'\u00C0-\u024F]+$', hostname):
            return jsonify({'error': 'hostname contains invalid characters'}), 400
        # Accept IP address or MAC address format (colon or hyphen separated)
        is_ip = _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address)
        is_mac = _re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', ip_address)
        if not is_ip and not is_mac:
            return jsonify({'error': 'invalid IP or MAC address format'}), 400
        # Normalize MAC to lowercase with colons
        if is_mac:
            ip_address = ip_address.lower().replace('-', ':')
        
        success = update_device_name(ip_address, hostname)
        
        if success:
            clear_response_cache()  # bust cached dashboard/device data
            return jsonify({
                'success': True,
                'message': f'Device {ip_address} renamed to {hostname}'
            })
        return jsonify({
            'success': False,
            'message': 'Device not found or update failed'
        }), 404
    
    # =========================================================================
    # NETWORK DISCOVERY ENDPOINTS
    # =========================================================================
    
    @app.route('/api/discovery/devices')
    @handle_errors
    def get_discovered_devices():
        """
        Get all devices discovered through network scanning.
        """
        try:
            from packet_capture.network_discovery import FullNetworkScanner

            mgr = _get_iface_manager()
            if not mgr:
                return jsonify({'devices': [], 'count': 0, 'error': 'Interface manager not running'})

            status = mgr.get_status()
            iface = status.get('interface') or (status.get('name'))
            if not iface:
                mode = mgr.get_current_mode()
                iface = mode.interface.name if mode else None

            if not iface:
                return jsonify({'devices': [], 'count': 0, 'error': 'No active network interface'})

            scanner = FullNetworkScanner(interface=iface)
            devices = scanner.discovery.get_all_devices()

            ip = status.get('ip_address', '')
            network = 'unknown'
            if ip:
                parts = ip.split('.')
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            return jsonify({
                'devices': devices, 'count': len(devices),
                'network': network, 'interface': iface,
                'discovery_methods': ['arp', 'ping', 'mdns', 'passive']
            })
        except ImportError as e:
            logger.warning(f"Network discovery module not available: {e}")
            return jsonify({'devices': [], 'count': 0, 'message': 'Network discovery module not available'})
        except Exception as e:
            logger.error(f"Error getting discovered devices: {e}")
            return jsonify({'devices': [], 'count': 0, 'error': str(e)})

    @app.route('/api/discovery/scan', methods=['POST'])
    @handle_errors
    def trigger_network_scan():
        """Trigger an immediate network scan to discover devices."""
        try:
            from packet_capture.network_discovery import NetworkDiscovery

            mgr = _get_iface_manager()
            if not mgr:
                return jsonify({'success': False, 'error': 'Interface manager not running', 'devices': []})

            mode = mgr.get_current_mode()
            iface = mode.interface.name if mode else None
            ip = mode.interface.ip_address if mode else None

            if not iface:
                return jsonify({'success': False, 'error': 'No active network interface', 'devices': []})

            network = None
            if ip:
                parts = ip.split('.')
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

            discovery = NetworkDiscovery(interface=iface, subnet=network)
            devices = discovery.arp_scan(timeout=3)

            return jsonify({
                'success': True, 'devices': devices, 'count': len(devices),
                'network': network or 'auto-detected', 'interface': iface,
                'scan_type': 'arp', 'message': f'Discovered {len(devices)} devices'
            })
        except ImportError as e:
            logger.warning(f"Network discovery module not available: {e}")
            return jsonify({'success': False, 'error': 'Network discovery module not available', 'devices': []})
        except PermissionError:
            return jsonify({'success': False, 'error': 'Administrator/root privileges required', 'devices': []}), 403
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            return jsonify({'success': False, 'error': str(e), 'devices': []})

    @app.route('/api/discovery/capabilities')
    @handle_errors
    def get_discovery_capabilities():
        """Get current network discovery capabilities based on connection type."""
        try:
            mgr = _get_iface_manager()
            status = mgr.get_status() if mgr else {}

            capabilities = status.get('capabilities', {})

            return jsonify({
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
                    'port_mirror_support': capabilities.get('port_mirror_support', False)
                },
                'description': status.get('description', '')
            })
        except Exception as e:
            logger.error(f"Error getting discovery capabilities: {e}")
            return jsonify({'error': str(e), 'capabilities': {}})

    @app.route('/api/discovery/port-mirror-status')
    @handle_errors
    def get_port_mirror_status():
        """Check if the current interface appears to be connected to a port mirror/SPAN."""
        try:
            from packet_capture.network_discovery import PortMirrorDetector

            mgr = _get_iface_manager()
            mode = mgr.get_current_mode() if mgr else None
            iface = mode.interface.name if mode else None

            if not iface:
                return jsonify({'detected': False, 'description': 'No active interface', 'interface': None})

            is_mirror, description = PortMirrorDetector.detect_port_mirror(interface=iface, duration=5)

            return jsonify({
                'detected': is_mirror, 'interface': iface,
                'description': description,
                'recommendation': 'Full network monitoring available - all traffic visible' if is_mirror
                                  else 'Normal connection - use ARP scanning for device discovery'
            })
        except ImportError as e:
            logger.warning(f"Port mirror detection module not available: {e}")
            return jsonify({'detected': False, 'description': 'Port mirror detection module not available'})
        except Exception as e:
            logger.error(f"Error detecting port mirror: {e}")
            return jsonify({'detected': False, 'description': f'Detection error: {str(e)}'})
    
    # =========================================================================
    # PROTOCOL ENDPOINTS
    # =========================================================================
    
    @app.route('/api/protocols')
    @handle_errors
    def get_protocols():
        """Get protocol distribution statistics."""
        hours = request.args.get('hours', 1, type=int)
        hours = min(max(hours, 1), 168)
        
        protocols = get_protocol_distribution(hours=hours)
        return jsonify({
            'protocols': protocols,
            'count': len(protocols),
            'hours': hours
        })
    
    # =========================================================================
    # BANDWIDTH ENDPOINTS
    # =========================================================================
    
    @app.route('/api/bandwidth/history')
    @handle_errors
    def get_bandwidth_history_endpoint():
        """Get bandwidth history for charting."""
        hours = request.args.get('hours', 1, type=int)
        interval = request.args.get('interval', 'minute', type=str)
        
        hours = min(max(hours, 1), 168)
        if interval not in ['minute', 'hour', 'day']:
            interval = 'minute'
        
        history = get_bandwidth_history(hours=hours, interval=interval)
        return jsonify({
            'history': history,
            'count': len(history),
            'hours': hours,
            'interval': interval
        })
    
    @app.route('/api/stats/bandwidth/realtime')
    @handle_errors
    def get_realtime_bandwidth():
        """
        Get real-time bandwidth from in-memory sliding window (CaptureEngine).
        Returns sub-second accurate bandwidth readings instead of DB-derived values.
        """
        engine = _get_engine()
        if engine and engine.is_running:
            bw = engine.bandwidth.get_stats()
            bw['engine_running'] = True
            bw['engine_stats'] = engine.get_stats()
            return jsonify(bw)
        return jsonify({
            'total_bps': 0, 'total_mbps': 0,
            'upload_bps': 0, 'upload_mbps': 0,
            'download_bps': 0, 'download_mbps': 0,
            'packets_per_second': 0,
            'engine_running': False,
        })

    @app.route('/api/traffic')
    @handle_errors
    def get_traffic():
        """Get traffic summary."""
        hours = request.args.get('hours', 24, type=int)
        hours = min(max(hours, 1), 168)
        
        traffic = get_traffic_summary(hours=hours)
        return jsonify(traffic)
    
    @app.route('/api/bandwidth/dual')
    @handle_errors
    def get_bandwidth_dual_endpoint():
        """Get bandwidth history with separate download/upload for dual-line charts."""
        hours = request.args.get('hours', 1, type=int)
        interval = request.args.get('interval', 'minute', type=str)
        
        hours = min(max(hours, 1), 168)
        if interval not in ['10s', '30s', 'minute', 'hour', 'day']:
            interval = 'minute'
        
        history = get_bandwidth_history_dual(hours=hours, interval=interval)
        return jsonify({
            'history': history,
            'count': len(history),
            'hours': hours,
            'interval': interval
        })
    
    @app.route('/api/activity')
    @handle_errors
    def get_activity():
        """Get recent network activity for the activity timeline."""
        limit = request.args.get('limit', 20, type=int)
        limit = min(max(limit, 1), 100)
        
        activities = get_recent_activity(limit=limit)
        return jsonify({
            'activities': activities,
            'count': len(activities)
        })
    
    # =========================================================================
    # ALERTS ENDPOINTS
    # =========================================================================
    
    @app.route('/api/alerts')
    @handle_errors
    def get_alerts_endpoint():
        """Get alerts list."""
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None, type=str)
        acknowledged = request.args.get('acknowledged', None)
        
        limit = min(max(limit, 1), 500)
        
        # Parse acknowledged parameter
        if acknowledged is not None:
            acknowledged = acknowledged.lower() in ('true', '1', 'yes')
        
        alerts = get_alerts(limit=limit, severity=severity, acknowledged=acknowledged)
        return jsonify({
            'alerts': alerts,
            'count': len(alerts),
            'limit': limit
        })
    
    @app.route('/api/alerts/summary')
    @cached_response('alerts_summary')
    @handle_errors
    def get_alerts_summary():
        """Get alerts summary."""
        summary = get_alert_summary()
        return jsonify(summary)
    
    @app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
    @handle_errors
    def acknowledge_alert_endpoint(alert_id):
        """Acknowledge an alert (mark as read, decreases badge count)."""
        success = acknowledge_alert(alert_id)
        clear_response_cache()  # bust alerts cache

        if success:
            return jsonify({
                'success': True,
                'message': f'Alert {alert_id} acknowledged'
            })
        return jsonify({
            'success': False,
            'message': 'Failed to acknowledge alert'
        }), 400

    @app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
    @handle_errors
    def resolve_alert_endpoint(alert_id):
        """Resolve an alert (remove from active list, decreases badge count)."""
        success = resolve_alert(alert_id)
        clear_response_cache()  # bust alerts cache

        if success:
            return jsonify({
                'success': True,
                'message': f'Alert {alert_id} resolved'
            })
        return jsonify({
            'success': False,
            'message': 'Failed to resolve alert'
        }), 400

    @app.route('/api/alerts/stats', methods=['GET'])
    @handle_errors
    def get_alert_stats():
        """Get alert statistics for badge counts."""
        return jsonify({
            'total_unresolved': count_alerts(resolved=False),
            'unacknowledged': count_alerts(resolved=False, acknowledged=False),
            'by_severity': {
                'critical': count_alerts(resolved=False, severity='critical'),
                'warning': count_alerts(resolved=False, severity='warning'),
                'info': count_alerts(resolved=False, severity='info'),
            }
        })
    
    @app.route('/api/alerts', methods=['POST'])
    @handle_errors
    def create_alert_endpoint():
        """Create a new alert (for testing)."""
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        alert_type = data.get('type', 'custom')
        severity = data.get('severity', 'info')
        message = data.get('message', 'Test alert')
        source_ip = data.get('source_ip')
        details = data.get('details', {})
        
        alert_id = create_alert(
            alert_type=alert_type,
            severity=severity,
            message=message,
            source_ip=source_ip,
            details=details
        )
        
        if alert_id:
            return jsonify({
                'success': True,
                'alert_id': alert_id,
                'message': 'Alert created'
            }), 201
        return jsonify({
            'success': False,
            'message': 'Failed to create alert'
        }), 400
    
    # =========================================================================
    # HEALTH ENDPOINT
    # =========================================================================
    
    @app.route('/api/health')
    @cached_response('health')
    @handle_errors
    def get_health():
        """Get network health score and factors."""
        health = get_health_score()
        return jsonify(health)
    
    # =========================================================================
    # INTERFACE STATUS ENDPOINTS
    # =========================================================================
    
    @app.route('/api/interface/status')
    @cached_response('interface_status')
    @handle_errors
    def get_interface_status():
        """
        Get current network interface monitoring status.
        Uses InterfaceManager.get_status() which caches the mode and never
        resets it to NONE on transient detection failures.
        """
        try:
            mgr = _get_iface_manager()
            if mgr:
                status = mgr.get_status()
                return jsonify(status)
            return jsonify({
                'mode': 'none',
                'mode_display': 'Not Running',
                'is_active': False,
            })
        except Exception as e:
            logger.error(f"Error getting interface status: {e}")
            return jsonify({
                'mode': 'none',
                'mode_display': '❌ Error',
                'interface': None,
                'ip_address': None,
                'description': f'Error detecting interface: {str(e)}',
                'is_active': False,
                'error': str(e)
            })
    
    @app.route('/api/interface/refresh', methods=['POST'])
    @handle_errors
    def refresh_interface():
        """
        Refresh network interface detection.
        Re-scans for available interfaces and selects the best monitoring mode.
        """
        try:
            mgr = _get_iface_manager()
            if mgr:
                mode = mgr.refresh_now()
                return jsonify({
                    'success': True,
                    'message': 'Interface detection refreshed',
                    'status': mgr.get_status()
                })
            return jsonify({
                'success': False,
                'message': 'Interface manager not running'
            }), 503
        except Exception as e:
            logger.error(f"Error refreshing interface: {e}")
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
    
    @app.route('/api/interface/list')
    @handle_errors
    def list_interfaces():
        """
        List all available network interfaces.
        Returns detailed information about each interface.
        """
        try:
            from packet_capture.mode_detector import ModeDetector
            detector = ModeDetector()
            interfaces = detector._enumerate_interfaces()
            mgr = _get_iface_manager()
            current_mode = mgr.get_current_mode() if mgr else None
            return jsonify({
                'interfaces': [{'name': i.name, 'friendly_name': i.friendly_name,
                                'ip_address': i.ip_address, 'is_active': i.is_active}
                               for i in interfaces],
                'count': len(interfaces),
                'current': current_mode.interface.name if current_mode else None,
                'mode': current_mode.get_mode_name().value if current_mode else 'none'
            })
        except Exception as e:
            logger.error(f"Error listing interfaces: {e}")
            return jsonify({
                'interfaces': [],
                'count': 0,
                'error': str(e)
            })
    
    @app.route('/api/interface/select', methods=['POST'])
    @handle_errors
    def select_interface():
        """
        Manually select a network interface for monitoring.
        """
        data = request.get_json()
        
        if not data or 'interface' not in data:
            return jsonify({'error': 'interface parameter required'}), 400
        
        interface_name = data['interface']
        
        try:
            # This would require restarting the monitor with the new interface
            # For now, just acknowledge the request
            return jsonify({
                'success': True,
                'message': f'Interface {interface_name} selected. Restart monitoring to apply.',
                'interface': interface_name
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error: {str(e)}'
            }), 500
    
    # =========================================================================
    # METRICS ENDPOINT (Combined stats for dashboard)
    # =========================================================================
    
    @app.route('/api/metrics')
    @handle_errors
    def get_metrics():
        """
        Get combined metrics for dashboard (current bandwidth, active devices, etc.)
        """
        stats = get_realtime_stats()
        return jsonify(stats)
    
    # =========================================================================
    # RECENT ALERTS ENDPOINT
    # =========================================================================
    # RECENT ALERTS ENDPOINT
    # =========================================================================
    
    @app.route('/api/alerts/recent')
    @handle_errors
    def get_recent_alerts():
        """
        Get recent alerts for the dashboard widget.
        """
        limit = request.args.get('limit', 5, type=int)
        limit = min(max(limit, 1), 20)
        
        alerts = get_alerts(limit=limit, severity=None, acknowledged=False)
        
        return jsonify({
            'alerts': alerts,
            'count': len(alerts)
        })

    # =========================================================================
    # SSE — Server-Sent Events for Real-Time Push
    # =========================================================================

    @app.route('/api/stream')
    def sse_stream():
        """
        Push real-time updates via Server-Sent Events.

        The client opens a single persistent connection and receives JSON
        payloads every ``interval`` seconds (default 3).  This replaces
        the 5-second polling loop with a push model.
        """
        from flask import Response, stream_with_context
        import json as _json, time as _time

        interval = request.args.get('interval', 3, type=int)
        interval = min(max(interval, 1), 30)

        def _generate():
            while True:
                try:
                    data = {}
                    # Stats
                    engine = _get_engine()
                    live_bw = None
                    if engine and engine.is_running:
                        live_bw = engine.bandwidth.get_current_bps()
                        # Push live bandwidth data points for real-time chart
                        try:
                            bw_stats = engine.bandwidth.get_stats()
                            data['bandwidth_live'] = {
                                'stats': bw_stats,
                                'history': engine.bandwidth.get_recent_history(
                                    bucket_seconds=2, max_points=10,
                                ),
                            }
                        except Exception:
                            pass
                    data['stats'] = get_realtime_stats(live_bandwidth_bps=live_bw)

                    # Alerts badge
                    data['alert_stats'] = {
                        'total_unresolved': count_alerts(resolved=False),
                        'unacknowledged': count_alerts(resolved=False, acknowledged=False),
                    }

                    # Health
                    data['health'] = get_health_score()

                    payload = _json.dumps(data, default=str)
                    yield f"data: {payload}\n\n"
                except GeneratorExit:
                    return
                except Exception as exc:
                    logger.warning("SSE error: %s", exc)
                    yield f"event: error\ndata: {{}}\n\n"

                _time.sleep(interval)

        return Response(
            stream_with_context(_generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive',
            },
        )

    # =========================================================================
    # DATA EXPORT — CSV / JSON download
    # =========================================================================

    @app.route('/api/geoip/<ip_address>')
    @handle_errors
    def get_geoip(ip_address):
        """Return GeoIP info for an external IP."""
        from packet_capture.geoip import lookup_ip
        info = lookup_ip(ip_address)
        if info:
            return jsonify(info)
        return jsonify({'error': 'No GeoIP data available', 'ip': ip_address}), 404

    @app.route('/api/geoip/batch', methods=['POST'])
    @handle_errors
    def get_geoip_batch():
        """Return GeoIP info for up to 100 IPs."""
        data = request.get_json()
        if not data or 'ips' not in data:
            return jsonify({'error': 'ips array required'}), 400
        from packet_capture.geoip import lookup_batch
        ips = data['ips'][:100]
        results = lookup_batch(ips)
        return jsonify(results)

    # =========================================================================
    # CUSTOM ALERT RULES — CRUD
    # =========================================================================

    _VALID_METRICS = {'bandwidth_bps', 'device_count', 'packet_rate', 'protocol_bytes'}
    _VALID_OPS = {'>', '<', '>=', '<=', '=='}
    _VALID_SEV = {'info', 'warning', 'critical'}

    @app.route('/api/alert-rules', methods=['GET'])
    @handle_errors
    def list_alert_rules():
        """List all custom alert rules."""
        from database.connection import get_connection
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    metric TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'warning',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    cooldown_seconds INTEGER NOT NULL DEFAULT 300,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_triggered_at TIMESTAMP DEFAULT NULL
                )
            """)
            cursor = conn.execute("SELECT * FROM alert_rules ORDER BY created_at DESC")
            cols = [d[0] for d in cursor.description]
            rules = [dict(zip(cols, row)) for row in cursor.fetchall()]
        return jsonify({'rules': rules, 'count': len(rules)})

    @app.route('/api/alert-rules', methods=['POST'])
    @handle_errors
    def create_alert_rule():
        """Create a custom alert rule."""
        import re as _re
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        name = (data.get('name') or '').strip()
        metric = (data.get('metric') or '').strip()
        operator = (data.get('operator') or '').strip()
        threshold = data.get('threshold')
        severity = (data.get('severity') or 'warning').strip()
        description = (data.get('description') or '').strip()
        cooldown = data.get('cooldown_seconds', 300)

        # Validation
        errors = []
        if not name or len(name) > 200:
            errors.append('name is required (max 200 chars)')
        if metric not in _VALID_METRICS:
            errors.append(f'metric must be one of {sorted(_VALID_METRICS)}')
        if operator not in _VALID_OPS:
            errors.append(f'operator must be one of {sorted(_VALID_OPS)}')
        if threshold is None or not isinstance(threshold, (int, float)):
            errors.append('threshold must be a number')
        if severity not in _VALID_SEV:
            errors.append(f'severity must be one of {sorted(_VALID_SEV)}')
        if errors:
            return jsonify({'error': 'Validation failed', 'details': errors}), 400

        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO alert_rules (name, description, metric, operator, threshold, severity, cooldown_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, description, metric, operator, threshold, severity, cooldown))
            conn.commit()
            rule_id = cursor.lastrowid

        return jsonify({'success': True, 'id': rule_id}), 201

    @app.route('/api/alert-rules/<int:rule_id>', methods=['PUT'])
    @handle_errors
    def update_alert_rule(rule_id):
        """Update an existing alert rule."""
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        allowed = {'name', 'description', 'metric', 'operator', 'threshold', 'severity', 'enabled', 'cooldown_seconds'}
        fields = {k: v for k, v in data.items() if k in allowed}

        if 'metric' in fields and fields['metric'] not in _VALID_METRICS:
            return jsonify({'error': f'metric must be one of {sorted(_VALID_METRICS)}'}), 400
        if 'operator' in fields and fields['operator'] not in _VALID_OPS:
            return jsonify({'error': f'operator must be one of {sorted(_VALID_OPS)}'}), 400
        if 'severity' in fields and fields['severity'] not in _VALID_SEV:
            return jsonify({'error': f'severity must be one of {sorted(_VALID_SEV)}'}), 400

        if not fields:
            return jsonify({'error': 'No valid fields to update'}), 400

        fields['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        set_clause = ', '.join(f'{k} = ?' for k in fields)
        values = list(fields.values()) + [rule_id]

        from database.connection import get_connection
        with get_connection() as conn:
            conn.execute(f"UPDATE alert_rules SET {set_clause} WHERE id = ?", values)
            conn.commit()

        return jsonify({'success': True, 'id': rule_id})

    @app.route('/api/alert-rules/<int:rule_id>', methods=['DELETE'])
    @handle_errors
    def delete_alert_rule(rule_id):
        """Delete an alert rule."""
        from database.connection import get_connection
        with get_connection() as conn:
            conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            conn.commit()
        return jsonify({'success': True})

    @app.route('/api/export/<fmt>')
    @handle_errors
    def export_data(fmt):
        """
        Export traffic or device data as CSV or JSON.

        Query params:
            type   — ``devices`` (default) or ``traffic``
            hours  — look-back window for traffic (default 24)
        """
        if not ENABLE_DATA_EXPORT:
            return jsonify({'error': 'Data export is disabled'}), 403

        if fmt not in ('csv', 'json'):
            return jsonify({'error': "Format must be 'csv' or 'json'"}), 400

        export_type = request.args.get('type', 'devices')
        hours = request.args.get('hours', 24, type=int)
        hours = min(max(hours, 1), 168)

        if export_type == 'traffic':
            rows = get_traffic_summary(hours=hours)
            filename = f'netwatch_traffic_{datetime.now():%Y%m%d_%H%M%S}'
        else:
            result = get_all_devices(limit=10000, offset=0)
            rows = result if isinstance(result, list) else result.get('devices', [])
            filename = f'netwatch_devices_{datetime.now():%Y%m%d_%H%M%S}'

        if fmt == 'json':
            import json as _json
            from flask import Response
            payload = _json.dumps(rows, indent=2, default=str)
            return Response(
                payload,
                mimetype='application/json',
                headers={'Content-Disposition': f'attachment; filename="{filename}.json"'},
            )

        # CSV
        import csv, io
        from flask import Response

        if not rows:
            return Response('', mimetype='text/csv',
                            headers={'Content-Disposition': f'attachment; filename="{filename}.csv"'})

        # Flatten dict keys as header row
        first = rows[0] if isinstance(rows[0], dict) else {}
        fieldnames = list(first.keys())

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            if isinstance(row, dict):
                writer.writerow(row)

        return Response(
            buf.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}.csv"'},
        )

    # =========================================================================
    # SYSTEM HEALTH & MAINTENANCE ENDPOINTS (Phase 2)
    # =========================================================================

    @app.route('/api/system/health')
    @handle_errors
    def get_system_health():
        """
        Get system-level health metrics (CPU, memory, DB size, threads).
        Different from /api/health which returns network health score.
        """
        monitor = app.config.get('HEALTH_MONITOR')
        if monitor:
            metrics = monitor.get_metrics()
            return jsonify(metrics)

        # Fallback: collect basic metrics inline
        try:
            from utils.health_monitor import (
                get_cpu_usage, get_memory_usage, get_thread_count,
            )
            from database.queries.maintenance import (
                get_database_size_mb, get_table_row_counts,
            )
            return jsonify({
                "status": "good",
                "cpu_percent": round(get_cpu_usage(), 1),
                "memory": get_memory_usage(),
                "database": {
                    "size_mb": round(get_database_size_mb(), 1),
                    "row_counts": get_table_row_counts(),
                },
                "threads": {"count": get_thread_count()},
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.error("System health error: %s", e)
            return jsonify({"status": "unknown", "error": str(e)}), 500

    @app.route('/api/system/health/history')
    @handle_errors
    def get_system_health_history():
        """Get system health metrics history for trend charts."""
        monitor = app.config.get('HEALTH_MONITOR')
        if monitor:
            return jsonify({
                'history': monitor.get_history(),
                'count': len(monitor.get_history()),
            })
        return jsonify({'history': [], 'count': 0})

    @app.route('/api/system/maintenance')
    @handle_errors
    def get_maintenance_report():
        """Get database maintenance report."""
        try:
            from database.queries.maintenance import get_maintenance_report as _get_report
            report = _get_report()
            return jsonify(report)
        except Exception as e:
            logger.error("Maintenance report error: %s", e)
            return jsonify({"error": str(e)}), 500

    @app.route('/api/system/maintenance/cleanup', methods=['POST'])
    @handle_errors
    def run_manual_cleanup():
        """
        Trigger a manual database cleanup.
        Accepts optional JSON body with retention_days.
        """
        try:
            from database.queries.maintenance import run_full_cleanup

            data = request.get_json(silent=True) or {}
            traffic_days = data.get('traffic_retention_days', 7)
            alert_days = data.get('alert_retention_days', 30)

            # Validate inputs
            traffic_days = max(1, min(traffic_days, 365))
            alert_days = max(1, min(alert_days, 365))

            result = run_full_cleanup(
                traffic_retention_days=traffic_days,
                alert_retention_days=alert_days,
            )
            return jsonify({
                'success': True,
                'message': 'Cleanup completed',
                'result': result,
            })
        except Exception as e:
            logger.error("Manual cleanup error: %s", e)
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/anomaly/status')
    @handle_errors
    def get_anomaly_status():
        """Get ML anomaly detector status and diagnostics."""
        detector = app.config.get('ANOMALY_DETECTOR')
        if detector:
            stats = detector.get_stats()
            return jsonify({
                'available': True,
                **stats,
            })
        return jsonify({
            'available': False,
            'message': 'Anomaly detector not running',
        })

    # =========================================================================
    # PRODUCTION HEALTH / METRICS / STATUS (Phase 3)
    # =========================================================================

    @app.route('/api/system/healthcheck', methods=['GET'])
    def production_health_check():
        """
        Comprehensive health check endpoint.

        Returns component-level health and system resources.
        HTTP 200 = healthy, 503 = degraded.
        """
        from database.connection import get_connection as _gc

        health = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': APP_VERSION,
            'components': {},
        }

        # Database
        try:
            with _gc() as conn:
                conn.execute("SELECT 1").fetchone()
            health['components']['database'] = {'status': 'UP'}
        except Exception as e:
            health['components']['database'] = {'status': 'DOWN', 'error': str(e)}
            health['status'] = 'degraded'

        # Packet capture
        engine = _get_engine()
        try:
            if engine:
                running = engine.is_running
                health['components']['packet_capture'] = {
                    'status': 'UP' if running else 'STOPPED',
                }
            else:
                health['components']['packet_capture'] = {'status': 'NOT_CONFIGURED'}
        except Exception as e:
            health['components']['packet_capture'] = {'status': 'DOWN', 'error': str(e)}
            health['status'] = 'degraded'

        # Anomaly detector
        detector = app.config.get('ANOMALY_DETECTOR')
        try:
            if detector:
                det_stats = detector.get_stats()
                health['components']['anomaly_detector'] = {
                    'status': 'UP',
                    'trained': det_stats.get('model_trained', False),
                    'samples': det_stats.get('training_samples', 0),
                }
            else:
                health['components']['anomaly_detector'] = {'status': 'NOT_CONFIGURED'}
        except Exception as e:
            health['components']['anomaly_detector'] = {'status': 'DOWN', 'error': str(e)}

        # System resources
        try:
            import psutil
            proc = psutil.Process()
            health['resources'] = {
                'cpu_percent': psutil.cpu_percent(interval=0),
                'memory_mb': round(proc.memory_info().rss / (1024 * 1024), 1),
                'disk_usage_percent': psutil.disk_usage('.').percent,
            }
        except ImportError:
            health['resources'] = {}
        except Exception:
            health['resources'] = {}

        code = 200 if health['status'] == 'healthy' else 503
        return jsonify(health), code

    @app.route('/api/metrics', methods=['GET'])
    @handle_errors
    def get_production_metrics():
        """
        Expose collected application metrics.

        Includes request counts, response-time percentiles, error rate,
        and per-endpoint breakdowns.
        """
        try:
            from utils.metrics import metrics_collector
            return jsonify(metrics_collector.get_metrics())
        except ImportError:
            return jsonify({'error': 'Metrics module not available'}), 503

    @app.route('/api/status', methods=['GET'])
    @handle_errors
    def get_production_status():
        """
        Complete system status — combines health, metrics, capture stats,
        and database info in one payload.
        """
        import time as _time

        uptime = (datetime.now() - API_START_TIME).total_seconds()

        status_payload: dict = {
            'uptime_seconds': round(uptime, 1),
            'version': APP_VERSION,
            'timestamp': datetime.now().isoformat(),
        }

        # Health from HealthMonitor
        monitor = app.config.get('HEALTH_MONITOR')
        if monitor:
            status_payload['health'] = monitor.get_metrics()
        else:
            status_payload['health'] = {'status': 'unknown'}

        # Application metrics
        try:
            from utils.metrics import metrics_collector
            status_payload['metrics'] = metrics_collector.get_metrics()
        except ImportError:
            status_payload['metrics'] = {}

        # Capture stats
        engine = _get_engine()
        if engine and engine.is_running:
            try:
                status_payload['capture'] = {
                    'running': True,
                    'packets_per_second': getattr(engine, 'packets_per_second', 0),
                }
            except Exception:
                status_payload['capture'] = {'running': True}
        else:
            status_payload['capture'] = {'running': False}

        # Database info
        try:
            from database.queries.maintenance import get_database_size_mb
            status_payload['database'] = {
                'size_mb': round(get_database_size_mb(), 1),
            }
        except Exception:
            status_payload['database'] = {}

        # Active alerts from AlertManager
        try:
            from utils.alerting import alert_manager
            status_payload['system_alerts'] = alert_manager.get_active_alerts()
        except ImportError:
            status_payload['system_alerts'] = []

        return jsonify(status_payload)

    logger.info("API routes registered successfully")
