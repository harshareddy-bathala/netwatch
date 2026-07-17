"""
incidents_bp.py - Incident Triage Endpoints (Phase 2, AI-first)
================================================================

* ``GET  /api/incidents``               — list incidents (newest activity
  first; ``?status=open|resolved`` filters, ``?limit=N``)
* ``GET  /api/incidents/<id>``          — one incident with member alerts
* ``POST /api/incidents/<id>/resolve``  — mark an incident resolved
* ``GET  /api/incidents/stats``         — triage counters

Reads work even when the IncidentManager is not attached — incidents are
plain rows; only fusion of *new* alerts needs the manager.
"""

import logging

from flask import Blueprint, request

from backend.helpers import handle_errors, success_detail, success_list, error_response
from database.queries import incident_queries
from intelligence.incidents import risk_score, risk_band


def _with_risk(incident: dict) -> dict:
    """Attach the Security-view risk score/band to an incident row."""
    if incident is not None:
        s = risk_score(incident)
        incident["risk_score"] = s
        incident["risk_band"] = risk_band(s)
    return incident

logger = logging.getLogger(__name__)

incidents_bp = Blueprint('incidents', __name__)


@incidents_bp.route('/api/incidents', methods=['GET'])
@handle_errors
def list_incidents():
    """List incidents, optionally filtered by status."""
    status = request.args.get('status')
    if status not in (None, 'open', 'resolved'):
        return error_response("status must be 'open' or 'resolved'",
                              code='BAD_STATUS', status=400)
    limit = request.args.get('limit', default=50, type=int)
    incidents = [_with_risk(i) for i in incident_queries.get_incidents(status=status, limit=limit)]
    # Highest risk first — the Security view leads with what matters.
    incidents.sort(key=lambda i: i.get("risk_score", 0), reverse=True)
    return success_list(incidents)


@incidents_bp.route('/api/incidents/stats', methods=['GET'])
@handle_errors
def incident_stats():
    """Triage counters (zeros when the manager is not running)."""
    from orchestration import state
    manager = getattr(state, 'incident_manager', None)
    open_incidents = incident_queries.get_incidents(status='open', limit=500)
    payload = {
        "open_count": len(open_incidents),
        "triage": manager.get_stats() if manager else None,
    }
    return success_detail(payload)


@incidents_bp.route('/api/incidents/<int:incident_id>', methods=['GET'])
@handle_errors
def get_incident(incident_id: int):
    """One incident plus its member alerts."""
    incident = incident_queries.get_incident(incident_id)
    if incident is None:
        return error_response('Incident not found', code='NOT_FOUND', status=404)
    return success_detail(_with_risk(incident))


@incidents_bp.route('/api/incidents/<int:incident_id>/resolve', methods=['POST'])
@handle_errors
def resolve_incident(incident_id: int):
    """Mark an incident resolved."""
    if not incident_queries.resolve_incident(incident_id):
        return error_response('Incident not found or already resolved',
                              code='NOT_FOUND', status=404)
    return success_detail({"id": incident_id, "status": "resolved"})
