"""
bandwidth_bp.py - Bandwidth & Stats Endpoints Blueprint
=========================================================
"""

import json
import logging
import threading
import time
from datetime import datetime
from typing import Optional

from flask import Blueprint, Response, jsonify, request, stream_with_context

from database.db_handler import (
    get_realtime_stats, get_protocol_distribution,
    get_bandwidth_history, get_traffic_summary,
    get_bandwidth_history_dual, get_recent_activity,
    get_dashboard_data, get_health_score,
)
from database.queries.alert_queries import get_alert_stats_aggregated
from backend.helpers import (
    handle_errors, cached_response, get_engine, get_iface_manager,
)

logger = logging.getLogger(__name__)

bandwidth_bp = Blueprint('bandwidth', __name__)


@bandwidth_bp.route('/api/stats/realtime')
@cached_response('realtime_stats')
@handle_errors
def get_realtime():
    """Get real-time network statistics."""
    engine = get_engine()
    live_bw = None
    if engine and engine.is_running:
        live_bw = engine.bandwidth.get_current_bps() * 8
    stats = get_realtime_stats(live_bandwidth_bps=live_bw)
    return jsonify({'data': stats})


@bandwidth_bp.route('/api/dashboard')
@handle_errors
def get_dashboard():
    """Get comprehensive dashboard data in a single call."""
    base = get_dashboard_data()

    result = {
        'stats': base.get('stats'),
        'health': base.get('health'),
        'devices': base.get('top_devices'),
        'protocols': base.get('protocols'),
        'bandwidth': base.get('bandwidth_history'),
        'alerts': base.get('alerts'),
    }

    engine = get_engine()
    if engine and engine.is_running:
        bw_stats = engine.bandwidth.get_stats()
        if result.get('stats'):
            result['stats']['bandwidth_bps'] = round(bw_stats['total_bps'] * 8, 2)
            result['stats']['bandwidth_mbps'] = bw_stats['total_mbps']
            result['stats']['upload_bps'] = round(bw_stats['upload_bps'] * 8, 2)
            result['stats']['download_bps'] = round(bw_stats['download_bps'] * 8, 2)
            result['stats']['upload_mbps'] = bw_stats['upload_mbps']
            result['stats']['download_mbps'] = bw_stats['download_mbps']
            result['stats']['packets_per_second'] = bw_stats['packets_per_second']

    # Alert stats — uses query module instead of raw SQL (#29)
    try:
        result['alert_stats'] = get_alert_stats_aggregated()
    except Exception:
        result['alert_stats'] = None

    # Interface / mode info
    try:
        mgr = get_iface_manager()
        result['mode'] = mgr.get_status() if mgr else {'mode': 'none', 'mode_display': 'Unknown'}
    except Exception:
        result['mode'] = {'mode': 'none', 'mode_display': 'Unknown'}

    # Dual bandwidth
    try:
        result['bandwidth'] = {'history': get_bandwidth_history_dual(hours=1, interval='10s')}
    except Exception:
        raw_bw = result.get('bandwidth')
        if isinstance(raw_bw, list):
            result['bandwidth'] = {'history': raw_bw}
        elif not isinstance(raw_bw, dict) or 'history' not in (raw_bw or {}):
            result['bandwidth'] = {'history': []}

    return jsonify(result)


@bandwidth_bp.route('/api/protocols')
@handle_errors
def get_protocols():
    """Get protocol distribution statistics."""
    hours = request.args.get('hours', 1, type=int)
    hours = min(max(hours, 1), 168)
    protocols = get_protocol_distribution(hours=hours)
    if not protocols:
        logger.warning('Protocol distribution returned empty (hours=%d)', hours)
    return jsonify({
        'data': protocols,
        'meta': {'count': len(protocols), 'hours': hours},
    })


@bandwidth_bp.route('/api/bandwidth/history')
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
        'data': history,
        'meta': {'count': len(history), 'hours': hours, 'interval': interval},
    })


@bandwidth_bp.route('/api/stats/bandwidth/realtime')
@handle_errors
def get_realtime_bandwidth():
    """Get real-time bandwidth from CaptureEngine."""
    engine = get_engine()
    if engine and engine.is_running:
        bw = engine.bandwidth.get_stats()
        bw['engine_running'] = True
        bw['engine_stats'] = engine.get_stats()
        return jsonify({'data': bw})
    return jsonify({'data': {
        'total_bps': 0, 'total_mbps': 0,
        'upload_bps': 0, 'upload_mbps': 0,
        'download_bps': 0, 'download_mbps': 0,
        'packets_per_second': 0,
        'engine_running': False,
    }})


@bandwidth_bp.route('/api/traffic')
@handle_errors
def get_traffic():
    """Get traffic summary."""
    hours = request.args.get('hours', 24, type=int)
    hours = min(max(hours, 1), 168)
    traffic = get_traffic_summary(hours=hours)
    return jsonify({'data': traffic})


@bandwidth_bp.route('/api/bandwidth/dual')
@handle_errors
def get_bandwidth_dual_endpoint():
    """Get bandwidth history with separate download/upload."""
    hours = request.args.get('hours', 1, type=int)
    interval = request.args.get('interval', 'minute', type=str)
    hours = min(max(hours, 1), 168)
    if interval not in ['10s', '30s', 'minute', 'hour', 'day']:
        interval = 'minute'
    history = get_bandwidth_history_dual(hours=hours, interval=interval)
    return jsonify({
        'data': history,
        'meta': {'count': len(history), 'hours': hours, 'interval': interval},
    })


@bandwidth_bp.route('/api/activity')
@handle_errors
def get_activity():
    """Get recent network activity."""
    limit = request.args.get('limit', 20, type=int)
    limit = min(max(limit, 1), 100)
    activities = get_recent_activity(limit=limit)
    return jsonify({
        'data': activities,
        'meta': {'count': len(activities)},
    })


@bandwidth_bp.route('/api/health')
@cached_response('health')
@handle_errors
def get_health():
    """Get network health score and factors."""
    health = get_health_score()
    return jsonify({'data': health})


@bandwidth_bp.route('/api/metrics')
@handle_errors
def get_metrics():
    """Get combined metrics for dashboard."""
    stats = get_realtime_stats()
    return jsonify({'data': stats})


# =========================================================================
# SSE — Server-Sent Events for Real-Time Push
# =========================================================================

_sse_cache_lock = threading.Lock()
_sse_cached_payload: Optional[str] = None
_sse_cache_time: float = 0.0
_SSE_CACHE_TTL = 3.0
_sse_building = False

# SSE connection limiting
_sse_active = 0
_sse_active_lock = threading.Lock()
_SSE_MAX_CONNECTIONS = 10


def _build_sse_payload() -> str:
    """Build the SSE JSON payload with 3-second server-side cache."""
    global _sse_cached_payload, _sse_cache_time, _sse_building

    now = time.time()

    with _sse_cache_lock:
        if _sse_cached_payload and (now - _sse_cache_time) < _SSE_CACHE_TTL:
            return _sse_cached_payload
        if _sse_building:
            return _sse_cached_payload or '{}'
        _sse_building = True

    try:
        data = {}

        engine = get_engine()
        live_bw = None
        if engine and engine.is_running:
            live_bw = engine.bandwidth.get_current_bps()
            try:
                bw_stats = engine.bandwidth.get_stats()
                data['bandwidth_live'] = {
                    'stats': bw_stats,
                    'history': engine.bandwidth.get_recent_history(bucket_seconds=2, max_points=10),
                }
            except Exception:
                pass

        dashboard = get_dashboard_data()

        stats = dashboard.get('stats', {})
        if live_bw is not None and stats:
            stats['bandwidth_bps'] = round(live_bw * 8, 2)
            stats['bandwidth_mbps'] = round((live_bw * 8) / 1_000_000, 4)
            if engine and engine.is_running:
                try:
                    bw = engine.bandwidth.get_stats()
                    stats['upload_bps'] = round(bw['upload_bps'] * 8, 2)
                    stats['download_bps'] = round(bw['download_bps'] * 8, 2)
                    stats['upload_mbps'] = bw['upload_mbps']
                    stats['download_mbps'] = bw['download_mbps']
                    stats['packets_per_second'] = bw['packets_per_second']
                except Exception:
                    pass
        data['stats'] = stats
        data['health'] = dashboard.get('health', {})

        alert_counts = dashboard.get('alert_counts', {})
        data['alert_stats'] = {
            'total_unresolved': alert_counts.get('total', 0),
            'unacknowledged': alert_counts.get('unacknowledged', 0),
            'by_severity': {
                k: v for k, v in alert_counts.items()
                if k not in ('total', 'unacknowledged')
            },
        }
        data['alerts'] = dashboard.get('alerts', [])
        data['protocols'] = dashboard.get('protocols', [])
        data['devices'] = dashboard.get('top_devices', [])

        try:
            mgr = get_iface_manager()
            data['mode'] = mgr.get_status() if mgr else {'mode': 'none', 'mode_display': 'Unknown'}
        except Exception:
            data['mode'] = {'mode': 'none', 'mode_display': 'Unknown'}

        try:
            data['bandwidth_history'] = get_bandwidth_history_dual(hours=1, interval='10s')
        except Exception:
            data['bandwidth_history'] = []

        payload = json.dumps(data, default=str)

        with _sse_cache_lock:
            _sse_cached_payload = payload
            _sse_cache_time = time.time()
            _sse_building = False

        return payload
    except Exception:
        with _sse_cache_lock:
            _sse_building = False
        raise


@bandwidth_bp.route('/api/stream')
def sse_stream():
    """Push real-time updates via Server-Sent Events."""
    global _sse_active

    with _sse_active_lock:
        if _sse_active >= _SSE_MAX_CONNECTIONS:
            return jsonify({'error': 'Too many SSE connections'}), 429
        _sse_active += 1

    interval = request.args.get('interval', 3, type=int)
    interval = min(max(interval, 1), 30)

    def _generate():
        global _sse_active
        try:
            while True:
                try:
                    payload = _build_sse_payload()
                    yield f"data: {payload}\n\n"
                except GeneratorExit:
                    return
                except Exception as exc:
                    logger.warning("SSE error: %s", exc)
                    yield f"event: error\ndata: {{}}\n\n"
                # Sleep in small increments so client disconnects are noticed
                for _ in range(interval * 5):
                    time.sleep(0.2)
        finally:
            with _sse_active_lock:
                _sse_active = max(0, _sse_active - 1)

    return Response(
        stream_with_context(_generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )
