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


@incidents_bp.route('/api/incidents/<int:incident_id>/assess', methods=['GET'])
@handle_errors
def assess_incident(incident_id: int):
    """AI assessment of one incident: what it looks like, and what to do.

    A *proposal* only. Nothing is enforced here — applying the recommendation
    is a separate, explicit call the operator makes, so the human always
    holds the trigger.
    """
    incident = incident_queries.get_incident(incident_id)
    if incident is None:
        return error_response('Incident not found', code='NOT_FOUND', status=404)

    from intelligence.responder import assess_incident, assessment_store
    from intelligence.responder import incident_fingerprint

    force = request.args.get('refresh') in ('1', 'true', 'yes')

    # The background assessor normally has a verdict ready before anyone opens
    # the incident. If it does, return it immediately — recomputing on every
    # view is what made this show "Assessing…" for seconds and throw the answer
    # away whenever the page was left and revisited.
    if not force:
        cached = assessment_store.get(incident_id, incident_fingerprint(incident))
        if cached is not None:
            return success_detail(dict(cached, cached=True))

        # Not ready yet (assessor hasn't reached it, or it just changed).
        # Say so rather than blocking the request behind a model run.
        if request.args.get('wait') not in ('1', 'true', 'yes'):
            return success_detail({
                "incident_id": incident_id,
                "pending": True,
                "reason": "Assessment is being prepared.",
            })

    return success_detail(assess_incident(incident, force=force))


@incidents_bp.route('/api/incidents/<int:incident_id>/apply', methods=['POST'])
@handle_errors
def apply_recommendation(incident_id: int):
    """Act on an assessment the operator approved.

    Deliberately routed through the ordinary policy path rather than a
    special "AI" one: a quarantine is a normal timed pause, scoped to the
    device, visible on the Controls page, and reversible by the same button
    that releases any other block. An action a human cannot see or undo is
    not one an AI should be allowed to take.
    """
    payload = request.get_json(silent=True) or {}
    action = (payload.get('action') or '').strip().lower()

    from intelligence.responder import VALID_ACTIONS
    if action not in VALID_ACTIONS:
        return error_response(
            f"action must be one of {', '.join(VALID_ACTIONS)}",
            code='BAD_REQUEST', status=400)

    incident = incident_queries.get_incident(incident_id)
    if incident is None:
        return error_response('Incident not found', code='NOT_FOUND', status=404)

    mac = incident.get('device_mac')
    result = {"incident_id": incident_id, "action": action, "applied": False}

    if action == 'dismiss_benign':
        incident_queries.resolve_incident(incident_id)
        result.update(applied=True, effect='incident resolved as benign')

    elif action == 'quarantine':
        if not mac:
            return error_response('Incident has no device to quarantine',
                                  code='BAD_REQUEST', status=400)
        from datetime import datetime, timedelta
        from database.queries.policy_queries import upsert_policy
        minutes = int(payload.get('minutes') or 60)
        until = (datetime.now() + timedelta(minutes=minutes)).strftime(
            '%Y-%m-%d %H:%M:%S')
        upsert_policy(mac, paused=True, pause_expires_at=until,
                      note=f'Quarantined from incident #{incident_id}')
        try:
            from orchestration.background_tasks import apply_blocking_rules_now
            apply_blocking_rules_now()
        except Exception as exc:
            logger.warning("Quarantine applied but enforcement kick failed: %s",
                           exc)
        result.update(applied=True, device_mac=mac, expires_at=until,
                      effect=f'device paused for {minutes} minutes')

    else:
        # monitor / throttle change nothing on the wire today. Say that
        # plainly rather than returning a success that did nothing.
        result.update(applied=False,
                      effect=f"'{action}' is advisory — no enforcement change")

    return success_detail(result)
