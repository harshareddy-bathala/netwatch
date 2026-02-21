"""
system_bp.py - System Health, Maintenance & Status Endpoints Blueprint
========================================================================
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

from config import APP_VERSION
from backend.helpers import handle_errors, get_engine, get_iface_manager, APP_START_TIME

logger = logging.getLogger(__name__)

system_bp = Blueprint('system', __name__)


@system_bp.route('/api/system/health')
@handle_errors
def get_system_health():
    """Get system-level health metrics."""
    from flask import current_app
    monitor = current_app.config.get('HEALTH_MONITOR')
    if monitor:
        return jsonify({'data': monitor.get_metrics()})
    try:
        from utils.health_monitor import get_cpu_usage, get_memory_usage, get_thread_count
        from database.queries.maintenance import get_database_size_mb, get_table_row_counts
        return jsonify({'data': {
            "status": "good",
            "cpu_percent": round(get_cpu_usage(), 1),
            "memory": get_memory_usage(),
            "database": {"size_mb": round(get_database_size_mb(), 1), "row_counts": get_table_row_counts()},
            "threads": {"count": get_thread_count()},
            "timestamp": datetime.now().isoformat(),
        }})
    except Exception as e:
        logger.error("System health error: %s", e)
        return jsonify({'error': 'Failed to collect system health metrics', 'code': 'FAILED'}), 500


@system_bp.route('/api/system/health/history')
@handle_errors
def get_system_health_history():
    """Get system health metrics history."""
    from flask import current_app
    monitor = current_app.config.get('HEALTH_MONITOR')
    if monitor:
        history = monitor.get_history()
        return jsonify({'data': history, 'meta': {'count': len(history)}})
    return jsonify({'data': [], 'meta': {'count': 0}})


@system_bp.route('/api/system/maintenance')
@handle_errors
def get_maintenance_report():
    """Get database maintenance report."""
    try:
        from database.queries.maintenance import get_maintenance_report as _get_report
        return jsonify({'data': _get_report()})
    except Exception as e:
        logger.error("Maintenance report error: %s", e)
        return jsonify({'error': 'Failed to generate maintenance report', 'code': 'FAILED'}), 500


@system_bp.route('/api/system/maintenance/cleanup', methods=['POST'])
@handle_errors
def run_manual_cleanup():
    """Trigger a manual database cleanup."""
    try:
        from database.queries.maintenance import run_full_cleanup
        data = request.get_json(silent=True) or {}
        traffic_days = max(1, min(data.get('traffic_retention_days', 7), 365))
        alert_days = max(1, min(data.get('alert_retention_days', 30), 365))
        result = run_full_cleanup(traffic_retention_days=traffic_days, alert_retention_days=alert_days)
        return jsonify({'data': {'success': True, 'message': 'Cleanup completed', 'result': result}})
    except Exception as e:
        logger.error("Manual cleanup error: %s", e)
        return jsonify({'error': 'Cleanup operation failed', 'code': 'FAILED'}), 500


@system_bp.route('/api/anomaly/status')
@handle_errors
def get_anomaly_status():
    """Get ML anomaly detector status."""
    from flask import current_app
    detector = current_app.config.get('ANOMALY_DETECTOR')
    if detector:
        stats = detector.get_stats()
        return jsonify({'data': {'available': True, **stats}})
    return jsonify({'data': {'available': False, 'message': 'Anomaly detector not running'}})


@system_bp.route('/api/system/healthcheck', methods=['GET'])
def production_health_check():
    """Comprehensive health check endpoint."""
    from flask import current_app
    from database.connection import get_connection as _gc

    health = {
        'status': 'healthy', 'timestamp': datetime.now().isoformat(),
        'version': APP_VERSION, 'components': {},
    }

    try:
        with _gc() as conn:
            conn.execute("SELECT 1").fetchone()
        health['components']['database'] = {'status': 'UP'}
    except Exception as e:
        health['components']['database'] = {'status': 'DOWN', 'error': str(e)}
        health['status'] = 'degraded'

    engine = get_engine()
    try:
        if engine:
            health['components']['packet_capture'] = {'status': 'UP' if engine.is_running else 'STOPPED'}
        else:
            health['components']['packet_capture'] = {'status': 'NOT_CONFIGURED'}
    except Exception as e:
        health['components']['packet_capture'] = {'status': 'DOWN', 'error': str(e)}
        health['status'] = 'degraded'

    detector = current_app.config.get('ANOMALY_DETECTOR')
    try:
        if detector:
            det_stats = detector.get_stats()
            health['components']['anomaly_detector'] = {
                'status': 'UP', 'trained': det_stats.get('model_trained', False),
                'samples': det_stats.get('training_samples', 0),
            }
        else:
            health['components']['anomaly_detector'] = {'status': 'NOT_CONFIGURED'}
    except Exception as e:
        health['components']['anomaly_detector'] = {'status': 'DOWN', 'error': str(e)}

    try:
        import psutil
        proc = psutil.Process()
        health['resources'] = {
            'cpu_percent': psutil.cpu_percent(interval=0),
            'memory_mb': round(proc.memory_info().rss / (1024 * 1024), 1),
            'disk_usage_percent': psutil.disk_usage('.').percent,
        }
    except (ImportError, Exception):
        health['resources'] = {}

    code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), code


@system_bp.route('/api/metrics/internal', methods=['GET'])
@handle_errors
def get_production_metrics():
    """Expose collected application metrics."""
    try:
        from utils.metrics import metrics_collector
        return jsonify({'data': metrics_collector.get_metrics()})
    except ImportError:
        return jsonify({'error': 'Metrics module not available', 'code': 'UNAVAILABLE'}), 503


@system_bp.route('/api/status', methods=['GET'])
@handle_errors
def get_production_status():
    """Complete system status."""
    from flask import current_app

    uptime = (datetime.now() - APP_START_TIME).total_seconds()
    status_payload = {
        'uptime_seconds': round(uptime, 1),
        'version': APP_VERSION,
        'timestamp': datetime.now().isoformat(),
    }

    monitor = current_app.config.get('HEALTH_MONITOR')
    status_payload['health'] = monitor.get_metrics() if monitor else {'status': 'unknown'}

    try:
        from utils.metrics import metrics_collector
        status_payload['metrics'] = metrics_collector.get_metrics()
    except ImportError:
        status_payload['metrics'] = {}

    engine = get_engine()
    if engine and engine.is_running:
        try:
            status_payload['capture'] = {'running': True, 'packets_per_second': getattr(engine, 'packets_per_second', 0)}
        except Exception:
            status_payload['capture'] = {'running': True}
    else:
        status_payload['capture'] = {'running': False}

    try:
        from database.queries.maintenance import get_database_size_mb
        status_payload['database'] = {'size_mb': round(get_database_size_mb(), 1)}
    except Exception:
        status_payload['database'] = {}

    # Use AlertEngine stats instead of deprecated AlertManager (#32)
    status_payload['system_alerts'] = []

    return jsonify(status_payload)
