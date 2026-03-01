"""
bandwidth_bp.py - Bandwidth & Stats Endpoints Blueprint
=========================================================
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
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
from utils.realtime_state import dashboard_state

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
    """Get comprehensive dashboard data in a single call.

    When the capture engine is running, serves stats / alerts / health
    from the in-memory ``dashboard_state`` snapshot (zero DB queries for
    the hot path).  Falls back to the full ``get_dashboard_data()`` DB
    query when the engine is stopped.
    """
    engine = get_engine()

    if engine and engine.is_running:
        # ── Fast path: in-memory state ──────────────────────────────
        mem = dashboard_state.snapshot()
        bw_stats = engine.bandwidth.get_recent_rate(seconds=5)

        result = {
            'stats': {
                'today_bytes': mem.get('today_bytes', 0),
                'today_packets': mem.get('today_packets', 0),
                'active_devices': mem.get('active_devices', 0),
                'bandwidth_bps': round(bw_stats['total_bps'] * 8, 2),
                'bandwidth_mbps': bw_stats['total_mbps'],
                'upload_bps': round(bw_stats['upload_bps'] * 8, 2),
                'download_bps': round(bw_stats['download_bps'] * 8, 2),
                'upload_mbps': bw_stats['upload_mbps'],
                'download_mbps': bw_stats['download_mbps'],
                'packets_per_second': engine.bandwidth.get_stats()['packets_per_second'],
            },
            'health': mem.get('health_score', {'score': 0, 'status': 'unknown'}),
            'devices': mem.get('top_devices', []),
            'protocols': mem.get('protocols', []),
            'alerts': mem.get('recent_alerts', []),
        }

        # Alert stats from in-memory cache
        acounts = mem.get('alert_counts', {})
        result['alert_stats'] = {
            'total_unresolved': acounts.get('total', 0),
            'unacknowledged': acounts.get('unacknowledged', 0),
            'by_severity': {
                k: v for k, v in acounts.items()
                if k not in ('total', 'unacknowledged', 'error')
            },
        }
    else:
        # ── Slow path: DB fallback (engine stopped / --no-capture) ──
        base = get_dashboard_data()
        bw_hist = base.get('bandwidth_history')
        result = {
            'stats': base.get('stats'),
            'health': base.get('health'),
            'devices': base.get('top_devices'),
            'protocols': base.get('protocols'),
            'bandwidth': {'history': bw_hist} if isinstance(bw_hist, list) else bw_hist,
            'alerts': base.get('alerts'),
        }
        try:
            result['alert_stats'] = get_alert_stats_aggregated()
        except Exception:
            result['alert_stats'] = None

    # Interface / mode info (lightweight — reads cached state)
    try:
        mgr = get_iface_manager()
        result['mode'] = mgr.get_status() if mgr else {'mode': 'none', 'mode_display': 'Unknown'}
    except Exception:
        result['mode'] = {'mode': 'none', 'mode_display': 'Unknown'}

    # Dual bandwidth (throttled in SSE path; full query in fallback)
    if 'bandwidth' not in result or result.get('bandwidth') is None:
        try:
            result['bandwidth'] = {'history': get_bandwidth_history_dual(hours=1, interval='10s')}
        except Exception:
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
# Phase 3: lowered from 3s → 1s.  Build cost is negligible since
# bandwidth data now comes from in-memory BandwidthCalculator.
_SSE_CACHE_TTL = 1.0
_sse_building = False

# Bandwidth history DB cache — throttled to one query per 10 seconds.
_bw_history_cache: list = []
_bw_history_cache_time: float = 0.0
_BW_HISTORY_CACHE_TTL = 10.0

# SSE connection limiting
_sse_active = 0
_sse_active_lock = threading.Lock()
try:
    from config import SSE_MAX_CONNECTIONS as _SSE_MAX_CONNECTIONS
except ImportError:
    _SSE_MAX_CONNECTIONS = 10


def invalidate_sse_cache():
    """
    Invalidate the SSE payload cache.

    Called after mode changes / engine restarts so that the next SSE push
    fetches fresh data instead of serving stale cached values from the
    old engine.

    NOTE: Does NOT clear in-memory dashboard state — device data, usage
    counters, and protocol records must persist across SSE cache resets.
    Only mode_handler.on_mode_change() clears dashboard state when the
    network actually changes (different subnet/gateway).
    """
    global _sse_cached_payload, _sse_cache_time, _bw_history_cache_time
    with _sse_cache_lock:
        _sse_cached_payload = None
        _sse_cache_time = 0.0
    _bw_history_cache_time = 0.0  # force DB re-query on next SSE tick


def expire_sse_cache():
    """Lightweight cache expiry — just mark the payload as stale.

    Use this when the in-memory state was already updated directly
    (e.g. after alert acknowledge) and you only need the next SSE
    frame to rebuild from the fresh state.  Does NOT clear any data.
    """
    global _sse_cache_time
    with _sse_cache_lock:
        _sse_cache_time = 0.0


# Phase 5: pending out-of-band events pushed alongside the next SSE frame
_sse_pending_events: list = []
_sse_pending_lock = threading.Lock()


def _sse_push_event(payload: str) -> None:
    """Queue an out-of-band SSE event (e.g. ``mode_changed``).

    The pending event will be sent alongside the next regular SSE frame
    in ``_generate()``.  This avoids needing a separate push channel.

    Also force-expires the SSE cache so the next ``_build_sse_payload()``
    call rebuilds immediately with updated mode data instead of serving
    a stale cached payload.
    """
    with _sse_pending_lock:
        _sse_pending_events.append(payload)
    # Force-expire SSE cache so the next build picks up the mode change
    with _sse_cache_lock:
        global _sse_cache_time
        _sse_cache_time = 0.0


def _build_sse_payload() -> str:
    """Build the SSE JSON payload with 1-second server-side cache.

    Phase 4 zero-DB hot path:
    * Health, alerts, protocols, and top devices are served entirely from
      the in-memory ``dashboard_state`` snapshot — zero DB queries.
    * ``get_bandwidth_history_dual()`` is the **only** remaining DB call
      and is throttled to once per 10 seconds via ``_bw_history_cache``.
    * Bandwidth live stats come from the in-memory ``BandwidthCalculator``.
    """
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

        # Phase 4: Read dashboard data from in-memory state (zero DB queries)
        # instead of calling get_dashboard_data() which scans traffic_summary.
        mem_state = dashboard_state.snapshot()

        # Detect current mode early — needed for public_network fallbacks below.
        current_mode = ''
        mode_info = {}
        try:
            mgr = get_iface_manager()
            mode_info = mgr.get_status() if mgr else {}
            current_mode = mode_info.get('mode', '')
        except Exception:
            pass

        # Build stats dict from in-memory bandwidth + state
        # Use get_recent_rate(5) for the card so the displayed value
        # matches the chart's latest 5-second bucket (not the 30 s average
        # which dilutes bursts and causes the card-vs-chart mismatch).
        stats = {}
        if engine and engine.is_running:
            bw = engine.bandwidth.get_recent_rate(seconds=5)
            bw_full = engine.bandwidth.get_stats()
            stats['bandwidth_bps'] = round(bw['total_bps'] * 8, 2)
            stats['bandwidth_mbps'] = bw['total_mbps']
            stats['upload_bps'] = round(bw['upload_bps'] * 8, 2)
            stats['download_bps'] = round(bw['download_bps'] * 8, 2)
            stats['upload_mbps'] = bw['upload_mbps']
            stats['download_mbps'] = bw['download_mbps']
            stats['packets_per_second'] = bw_full['packets_per_second']
        elif live_bw is not None:
            stats['bandwidth_bps'] = round(live_bw * 8, 2)
            stats['bandwidth_mbps'] = round((live_bw * 8) / 1_000_000, 4)
        else:
            stats['bandwidth_bps'] = 0
            stats['bandwidth_mbps'] = 0

        stats['active_devices'] = mem_state.get('active_devices', 0)
        stats['total_bytes_today'] = mem_state.get('today_bytes', 0)
        stats['total_packets_today'] = mem_state.get('today_packets', 0)
        stats['timestamp'] = datetime.now().isoformat()

        data['stats'] = stats

        # Phase 4: health from in-memory cache (updated by HealthMonitor)
        data['health'] = mem_state.get('health_score', {'score': 0, 'status': 'unknown'})

        # Phase 4: alerts from in-memory cache (updated by AlertEngine)
        alert_counts = mem_state.get('alert_counts', {})
        data['alert_stats'] = {
            'total_unresolved': alert_counts.get('total', 0),
            'unacknowledged': alert_counts.get('unacknowledged', 0),
            'by_severity': {
                k: v for k, v in alert_counts.items()
                if k not in ('total', 'unacknowledged', 'error')
            },
        }
        data['alerts'] = mem_state.get('recent_alerts', [])

        # Phase 4: protocols + top devices from in-memory state
        data['protocols'] = mem_state.get('protocols', [])
        data['devices'] = mem_state.get('top_devices', [])

        data['mode'] = mode_info if mode_info else {'mode': 'none', 'mode_display': 'Unknown'}

        # Unified bandwidth history: merge DB (long tail) + live (recent).
        # All merging happens server-side so the frontend just uses the
        # array directly — no client-side merge logic, no chart instability.
        global _bw_history_cache, _bw_history_cache_time
        if (now - _bw_history_cache_time) >= _BW_HISTORY_CACHE_TTL:
            try:
                db_history = get_bandwidth_history_dual(hours=1, interval='10s')
                _bw_history_cache = db_history[-360:] if len(db_history) > 360 else db_history
                _bw_history_cache_time = now
            except Exception:
                if not _bw_history_cache:
                    _bw_history_cache = []

        unified = list(_bw_history_cache)
        if engine and engine.is_running:
            try:
                live_points = engine.bandwidth.get_recent_history(
                    bucket_seconds=5, max_points=40,
                )
                if live_points:
                    # Cut-over: keep DB points before the first live timestamp,
                    # then append the full live tail for seamless higher resolution.
                    first_live_ts = live_points[0].get('timestamp', '')
                    if first_live_ts:
                        unified = [p for p in unified if p.get('timestamp', '') < first_live_ts]
                    unified.extend(live_points)
            except Exception:
                pass
        data['bandwidth_history'] = unified[-360:]

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
                # Break out of the SSE loop when the app is shutting down
                # so the Waitress worker thread can exit and shutdown
                # completes without the watchdog firing.
                try:
                    from main import shutdown_event as _shutdown_evt
                    if _shutdown_evt.is_set():
                        return
                except Exception:
                    pass

                try:
                    # Phase 5: drain any pending out-of-band events first
                    with _sse_pending_lock:
                        pending = list(_sse_pending_events)
                        _sse_pending_events.clear()
                    for evt in pending:
                        yield f"event: mode_changed\ndata: {evt}\n\n"

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
                    try:
                        from main import shutdown_event as _sd
                        if _sd.is_set():
                            return
                    except Exception:
                        pass
        finally:
            with _sse_active_lock:
                _sse_active = max(0, _sse_active - 1)

    return Response(
        stream_with_context(_generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )
