"""
alerts_bp.py - Alerts Endpoints Blueprint
==========================================
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

from database.db_handler import (
    get_alerts, get_alert_summary, acknowledge_alert, create_alert,
    resolve_alert, count_alerts,
)
from database.queries.alert_queries import (
    get_alert_stats_aggregated,
    list_alert_rules, create_alert_rule, update_alert_rule, delete_alert_rule,
    _VALID_METRICS, _VALID_OPS, _VALID_SEV,
)
from backend.helpers import handle_errors, cached_response, clear_response_cache

logger = logging.getLogger(__name__)

alerts_bp = Blueprint('alerts', __name__)


def _refresh_inmemory_alert_state():
    """Refresh the in-memory dashboard alert cache after acknowledge/resolve.

    Without this, the SSE push loop sends stale alert data from
    ``dashboard_state._recent_alerts`` which overwrites the frontend's
    fresh fetch — making it appear that acknowledge/resolve had no effect.
    """
    try:
        from utils.realtime_state import dashboard_state
        summary = get_alert_summary()
        recent = get_alerts(limit=5, severity=None, acknowledged=False)
        dashboard_state.set_alerts(summary, recent)
        # Refresh health score immediately — health depends on unresolved
        # alert counts which just changed.  Without this the dashboard card
        # only updates on the next HealthMonitor cycle (up to 60 s later).
        try:
            from database.queries.stats_queries import get_health_score
            health = get_health_score()
            dashboard_state.set_health_score(health)
        except Exception:
            pass
    except Exception as e:
        logger.debug("Failed to refresh in-memory alert state: %s", e)
    # Also expire the SSE payload cache so the next push uses fresh data.
    # Use expire (not invalidate) — alert state was already updated above,
    # we only need the cached SSE payload to rebuild.
    try:
        from backend.blueprints.bandwidth_bp import expire_sse_cache
        expire_sse_cache()
    except Exception:
        pass


@alerts_bp.route('/api/alerts')
@cached_response('alerts')
@handle_errors
def get_alerts_endpoint():
    """Get alerts list."""
    limit = request.args.get('limit', 50, type=int)
    severity = request.args.get('severity', None, type=str)
    acknowledged = request.args.get('acknowledged', None)
    limit = min(max(limit, 1), 500)
    if acknowledged is not None:
        acknowledged = acknowledged.lower() in ('true', '1', 'yes')
    alerts = get_alerts(limit=limit, severity=severity, acknowledged=acknowledged)
    return jsonify({
        'data': alerts,
        'meta': {'count': len(alerts), 'limit': limit},
    })


@alerts_bp.route('/api/alerts/summary')
@cached_response('alerts_summary')
@handle_errors
def get_alerts_summary():
    """Get alerts summary."""
    summary = get_alert_summary()
    return jsonify({'data': summary})


@alerts_bp.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@handle_errors
def acknowledge_alert_endpoint(alert_id):
    """Acknowledge an alert."""
    success = acknowledge_alert(alert_id)
    clear_response_cache()
    if success:
        _refresh_inmemory_alert_state()
        return jsonify({'data': {'success': True, 'message': f'Alert {alert_id} acknowledged'}})
    return jsonify({'error': 'Failed to acknowledge alert', 'code': 'FAILED'}), 400


@alerts_bp.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@handle_errors
def resolve_alert_endpoint(alert_id):
    """Resolve an alert."""
    success = resolve_alert(alert_id)
    clear_response_cache()
    if success:
        _refresh_inmemory_alert_state()
        return jsonify({'data': {'success': True, 'message': f'Alert {alert_id} resolved'}})
    return jsonify({'error': 'Failed to resolve alert', 'code': 'FAILED'}), 400


@alerts_bp.route('/api/alerts/stats', methods=['GET'])
@handle_errors
def get_alert_stats():
    """Get alert statistics for badge counts."""
    stats = get_alert_stats_aggregated()
    return jsonify({'data': stats})


@alerts_bp.route('/api/alerts', methods=['POST'])
@handle_errors
def create_alert_endpoint():
    """Create a new alert (for testing)."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data provided', 'code': 'NO_DATA'}), 400

    ALLOWED_ALERT_TYPES = {
        'bandwidth', 'anomaly', 'device_count', 'health',
        'protocol', 'connection', 'security', 'new_device', 'custom',
    }
    ALLOWED_SEVERITIES = {
        'info', 'low', 'medium', 'warning', 'high', 'critical',
    }

    alert_type = data.get('type', 'custom')
    severity = data.get('severity', 'info')
    message = data.get('message', 'Test alert')
    source_ip = data.get('source_ip')
    details = data.get('details', {})

    if alert_type not in ALLOWED_ALERT_TYPES:
        return jsonify({'error': f'Invalid alert_type. Must be one of: {sorted(ALLOWED_ALERT_TYPES)}', 'code': 'VALIDATION'}), 400
    if severity not in ALLOWED_SEVERITIES:
        return jsonify({'error': f'Invalid severity. Must be one of: {sorted(ALLOWED_SEVERITIES)}', 'code': 'VALIDATION'}), 400
    if not message or len(message) > 500:
        return jsonify({'error': 'message is required and must be 500 characters or fewer', 'code': 'VALIDATION'}), 400

    alert_id = create_alert(
        alert_type=alert_type, severity=severity,
        message=message, source_ip=source_ip, details=details,
    )
    if alert_id:
        return jsonify({'data': {'success': True, 'alert_id': alert_id, 'message': 'Alert created'}}), 201
    return jsonify({'error': 'Failed to create alert', 'code': 'FAILED'}), 400


@alerts_bp.route('/api/alerts/recent')
@handle_errors
def get_recent_alerts():
    """Get recent alerts for the dashboard widget."""
    limit = request.args.get('limit', 5, type=int)
    limit = min(max(limit, 1), 20)
    alerts = get_alerts(limit=limit, severity=None, acknowledged=False)
    return jsonify({
        'data': alerts,
        'meta': {'count': len(alerts)},
    })


# =========================================================================
# CUSTOM ALERT RULES — CRUD
# =========================================================================

@alerts_bp.route('/api/alert-rules', methods=['GET'])
@handle_errors
def list_alert_rules_endpoint():
    """List all custom alert rules."""
    rules = list_alert_rules()
    return jsonify({'data': rules, 'meta': {'count': len(rules)}})


@alerts_bp.route('/api/alert-rules', methods=['POST'])
@handle_errors
def create_alert_rule_endpoint():
    """Create a custom alert rule."""
    import re
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data provided', 'code': 'NO_DATA'}), 400

    name = (data.get('name') or '').strip()
    metric = (data.get('metric') or '').strip()
    operator = (data.get('operator') or '').strip()
    threshold = data.get('threshold')
    severity = (data.get('severity') or 'warning').strip()
    description = (data.get('description') or '').strip()
    cooldown = data.get('cooldown_seconds', 300)

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
        return jsonify({'error': 'Validation failed', 'code': 'VALIDATION', 'details': errors}), 400

    rule_id = create_alert_rule(name, description, metric, operator, threshold, severity, cooldown)
    if rule_id:
        return jsonify({'data': {'success': True, 'id': rule_id}}), 201
    return jsonify({'error': 'Failed to create rule', 'code': 'FAILED'}), 400


@alerts_bp.route('/api/alert-rules/<int:rule_id>', methods=['PUT'])
@handle_errors
def update_alert_rule_endpoint(rule_id):
    """Update an existing alert rule."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data provided', 'code': 'NO_DATA'}), 400

    allowed = {'name', 'description', 'metric', 'operator', 'threshold', 'severity', 'enabled', 'cooldown_seconds'}
    fields = {k: v for k, v in data.items() if k in allowed}

    if 'metric' in fields and fields['metric'] not in _VALID_METRICS:
        return jsonify({'error': f'metric must be one of {sorted(_VALID_METRICS)}', 'code': 'VALIDATION'}), 400
    if 'operator' in fields and fields['operator'] not in _VALID_OPS:
        return jsonify({'error': f'operator must be one of {sorted(_VALID_OPS)}', 'code': 'VALIDATION'}), 400
    if 'severity' in fields and fields['severity'] not in _VALID_SEV:
        return jsonify({'error': f'severity must be one of {sorted(_VALID_SEV)}', 'code': 'VALIDATION'}), 400
    if not fields:
        return jsonify({'error': 'No valid fields to update', 'code': 'VALIDATION'}), 400

    success = update_alert_rule(rule_id, fields)
    if success:
        return jsonify({'data': {'success': True, 'id': rule_id}})
    return jsonify({'error': 'Failed to update rule', 'code': 'FAILED'}), 400


@alerts_bp.route('/api/alert-rules/<int:rule_id>', methods=['DELETE'])
@handle_errors
def delete_alert_rule_endpoint(rule_id):
    """Delete an alert rule."""
    success = delete_alert_rule(rule_id)
    if success:
        return jsonify({'data': {'success': True}})
    return jsonify({'error': 'Failed to delete rule', 'code': 'FAILED'}), 400
