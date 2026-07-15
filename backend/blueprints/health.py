"""
health.py - Phase 5 Idle Baseline Health Endpoints
===================================================
"""

from flask import Blueprint, jsonify, request

from backend.helpers import handle_errors
from utils.idle_baseline import collect_idle_baseline_metrics

health_bp = Blueprint('idle_health', __name__)


@health_bp.route('/api/health/idle-client-baseline', methods=['GET'])
@handle_errors
def get_idle_client_baseline_health():
    """Return baseline app/control metrics for idle-client validation."""
    hours = request.args.get('hours', 24, type=int)
    hours = min(max(hours, 1), 24 * 7)
    metrics = collect_idle_baseline_metrics(hours=hours)
    return jsonify({'data': metrics})
