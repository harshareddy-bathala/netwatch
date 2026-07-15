"""
twin_bp.py - Digital Twin & Intelligence Endpoints (Phase 1, AI-first)
=======================================================================

Read-only views over the intelligence layer:

* ``GET /api/twin``                 — graph snapshot (nodes + edges)
* ``GET /api/twin/stats``           — twin/behavior/bus diagnostics
* ``GET /api/flows/recent``         — recent flow records
* ``GET /api/dns/recent``           — recent DNS query events
* ``GET /api/behavior/profiles/<mac>`` — learned baselines for a device

All endpoints degrade gracefully to empty payloads when the
intelligence services are not running (e.g. ``--no-capture``).
"""

import logging

from flask import Blueprint, jsonify, request

from backend.helpers import handle_errors
from database.queries.flow_queries import (
    get_recent_flows, get_recent_dns_queries,
)

logger = logging.getLogger(__name__)

twin_bp = Blueprint('twin', __name__)

_EMPTY_TWIN = {
    "generated_at": 0,
    "mode": "unknown",
    "stats": {"node_count": 0, "edge_count": 0, "device_count": 0,
              "external_count": 0, "events_consumed": 0},
    "mode_timeline": [],
    "nodes": [],
    "edges": [],
}


def _get_twin():
    from orchestration import state
    return getattr(state, 'twin_builder', None)


def _get_behavior():
    from orchestration import state
    return getattr(state, 'behavior_analyzer', None)


def _get_threats():
    from orchestration import state
    return getattr(state, 'threat_detector', None)


@twin_bp.route('/api/twin', methods=['GET'])
@handle_errors
def get_twin():
    """Return the current digital-twin graph snapshot."""
    twin = _get_twin()
    if twin is None:
        return jsonify({'data': dict(_EMPTY_TWIN)})
    max_edges = request.args.get('max_edges', 500, type=int)
    max_edges = min(max(max_edges, 1), 2000)
    return jsonify({'data': twin.snapshot(max_edges=max_edges)})


@twin_bp.route('/api/twin/stats', methods=['GET'])
@handle_errors
def get_twin_stats():
    """Diagnostics for the intelligence layer (twin, behavior, threats, bus)."""
    twin = _get_twin()
    behavior = _get_behavior()
    threats = _get_threats()
    try:
        from intelligence.event_bus import event_bus
        bus_stats = event_bus.get_stats()
    except Exception:
        bus_stats = {}
    return jsonify({'data': {
        'twin': twin.get_stats() if twin else {'running': False},
        'behavior': behavior.get_stats() if behavior else {'running': False},
        'threats': threats.get_stats() if threats else {'running': False},
        'event_bus': bus_stats,
    }})


@twin_bp.route('/api/flows/recent', methods=['GET'])
@handle_errors
def get_flows_recent():
    """Recent flow records (Phase 0 telemetry)."""
    limit = min(max(request.args.get('limit', 100, type=int), 1), 1000)
    mac = request.args.get('mac')
    since = request.args.get('since')
    return jsonify({'data': get_recent_flows(limit=limit, since=since, mac=mac)})


@twin_bp.route('/api/dns/recent', methods=['GET'])
@handle_errors
def get_dns_recent():
    """Recent DNS query events (Phase 0 telemetry)."""
    limit = min(max(request.args.get('limit', 100, type=int), 1), 1000)
    mac = request.args.get('mac')
    since = request.args.get('since')
    return jsonify({'data': get_recent_dns_queries(limit=limit, since=since, mac=mac)})


@twin_bp.route('/api/behavior/profiles/<mac>', methods=['GET'])
@handle_errors
def get_behavior_profile(mac):
    """Learned hour-of-week baselines for one device."""
    behavior = _get_behavior()
    if behavior is None:
        return jsonify({'data': {'mac': mac, 'metrics': {}}})
    return jsonify({'data': behavior.get_profile_summary(mac)})
