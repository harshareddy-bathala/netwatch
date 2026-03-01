"""
helpers.py - Shared Route Helpers & Decorators
================================================

Common utilities shared across all Blueprint modules:
- Response caching with TTL
- Error handling decorator
- Response envelope helpers
- IP validation
- Engine/manager accessors
- Active subnet detection
"""

import csv
import io
import json
import logging
import re
import threading
import time
import ipaddress as _ipaddress
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import current_app, jsonify, request, Response

from config import APP_VERSION

logger = logging.getLogger(__name__)

# =============================================================================
# Shared start time (consolidates APP_START_TIME / API_START_TIME — #38)
# =============================================================================
APP_START_TIME = datetime.now()

# =============================================================================
# RESPONSE CACHING - Reduces database load for frequently requested data
# =============================================================================

_response_cache: dict = {}
_response_cache_lock = threading.Lock()
_discovery_lock = threading.Lock()
CACHE_TTL = 2
CACHE_MAX_SIZE = 50


def cached_response(cache_key: str, ttl: int = CACHE_TTL):
    """Decorator for caching API responses with TTL."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            now = time.time()
            with _response_cache_lock:
                if cache_key in _response_cache:
                    cached_data, timestamp = _response_cache[cache_key]
                    if now - timestamp < ttl:
                        return jsonify(cached_data)
            result = f(*args, **kwargs)
            try:
                with _response_cache_lock:
                    if hasattr(result, 'get_json'):
                        if len(_response_cache) >= CACHE_MAX_SIZE:
                            # Evict expired entries first before falling back to LRU
                            expired = [k for k, (_, ts) in _response_cache.items()
                                       if now - ts >= ttl]
                            for k in expired:
                                del _response_cache[k]
                            # If still at capacity, evict oldest
                            if len(_response_cache) >= CACHE_MAX_SIZE:
                                oldest_key = min(_response_cache,
                                                 key=lambda k: _response_cache[k][1])
                                del _response_cache[oldest_key]
                        _response_cache[cache_key] = (result.get_json(), now)
                    elif isinstance(result, tuple):
                        if len(_response_cache) >= CACHE_MAX_SIZE:
                            expired = [k for k, (_, ts) in _response_cache.items()
                                       if now - ts >= ttl]
                            for k in expired:
                                del _response_cache[k]
                            if len(_response_cache) >= CACHE_MAX_SIZE:
                                oldest_key = min(_response_cache,
                                                 key=lambda k: _response_cache[k][1])
                                del _response_cache[oldest_key]
                        _response_cache[cache_key] = (result[0].get_json(), now)
            except Exception:
                pass
            return result
        return wrapper
    return decorator


def clear_response_cache():
    """Clear all cached responses."""
    with _response_cache_lock:
        _response_cache.clear()


# =============================================================================
# ERROR HANDLING
# =============================================================================

def handle_errors(f):
    """Decorator to handle errors in API endpoints. Never leaks exception details."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except RuntimeError as e:
            # Connection pool exhaustion → 503 Service Unavailable
            if 'pool exhausted' in str(e).lower():
                logger.critical("DB pool exhausted in %s: %s", f.__name__, e)
                return jsonify({
                    'error': 'Service Unavailable',
                    'code': 'DB_POOL_EXHAUSTED',
                    'message': 'Database connection pool is exhausted. Please retry shortly.',
                }), 503
            logger.error("API error in %s: %s", f.__name__, e, exc_info=True)
            return jsonify({
                'error': 'Internal Server Error',
                'code': 'INTERNAL_ERROR',
                'message': 'An unexpected error occurred. Check server logs for details.',
                'warnings': ['An internal error occurred processing this request.'],
            }), 500
        except Exception as e:
            logger.error("API error in %s: %s", f.__name__, e, exc_info=True)
            return jsonify({
                'error': 'Internal Server Error',
                'code': 'INTERNAL_ERROR',
                'message': 'An unexpected error occurred. Check server logs for details.',
                'warnings': ['An internal error occurred processing this request.'],
            }), 500
    return decorated


# =============================================================================
# RESPONSE ENVELOPE HELPERS (#37)
# =============================================================================

def success_list(data: list, **meta) -> Response:
    """Return a standardized list response: {'data': [...], 'meta': {'count': N, ...}}."""
    envelope = {
        'data': data,
        'meta': {'count': len(data), **meta},
    }
    return jsonify(envelope)


def success_detail(data: dict) -> Response:
    """Return a standardized detail response: {'data': {...}}."""
    return jsonify({'data': data})


def error_response(message: str, code: str = 'ERROR', status: int = 400) -> tuple:
    """Return a standardized error response: {'error': '...', 'code': '...'}."""
    return jsonify({'error': message, 'code': code}), status


# =============================================================================
# VALIDATION HELPERS
# =============================================================================

def is_valid_ip(ip_str: str) -> bool:
    """Return True if ip_str is a valid IPv4 or IPv6 address."""
    try:
        _ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False


# =============================================================================
# ENGINE / MANAGER ACCESSORS
# =============================================================================

def get_engine():
    """Return the current CaptureEngine (or None)."""
    return current_app.config.get('CAPTURE_ENGINE')


def get_iface_manager():
    """Return the current InterfaceManager (or None)."""
    return current_app.config.get('INTERFACE_MANAGER')


# =============================================================================
# ACTIVE SUBNET DETECTION (#30 — shared helper)
# =============================================================================

def get_active_subnet(ip: str) -> tuple:
    """
    Detect the active subnet for the given IP address.

    Returns (network_str, prefix_len) e.g. ('192.168.1.0/24', 24).
    Falls back to /24 if netifaces is unavailable.
    """
    prefix_len = 24
    try:
        import netifaces
        import ipaddress as _ipaddr
        for iface_n in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface_n)
            for entry in addrs.get(netifaces.AF_INET, []):
                if entry.get('addr') == ip:
                    netmask = entry.get('netmask', '255.255.255.0')
                    prefix_len = _ipaddr.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
                    break
    except Exception:
        pass
    parts = ip.split('.')
    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix_len}"
    return network, prefix_len
