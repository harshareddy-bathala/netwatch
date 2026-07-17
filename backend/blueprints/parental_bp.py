"""
parental_bp.py - Parental controls / quotas (W5)
=================================================

Per-client policy the operator sets from the dashboard:

* ``GET    /api/parental/policies``       — list policies (+ live block state)
* ``PUT    /api/parental/policies/<mac>``  — set/update a device's policy
* ``POST   /api/parental/policies/<mac>/pause``   — pause internet now
* ``POST   /api/parental/policies/<mac>/resume``  — resume
* ``DELETE /api/parental/policies/<mac>``  — clear a device's policy

Policies (pause / daily data cap / blocked time windows) are enforced by the
same DNS sinkhole as domain blocking, at the whole-device level — so, like
blocking, they only apply in **hotspot** mode; the response says so plainly.
"""

import logging

from flask import Blueprint, jsonify, request

from backend.helpers import handle_errors
from database.queries.policy_queries import (
    get_policies, get_policy, upsert_policy, delete_policy,
    get_usage_today_by_mac, evaluate_blocked_macs,
)

logger = logging.getLogger(__name__)

parental_bp = Blueprint('parental', __name__)


def _enforcement_status() -> dict:
    """Reuse the blocking blueprint's honest hotspot-only status."""
    try:
        from backend.blueprints.blocking_bp import _enforcement_status as s
        return s()
    except Exception:
        return {"enforcing": False, "mode": None, "reason": None}


def _kick_enforcer() -> None:
    """Recompute the blocked set immediately after a change (don't wait for
    the periodic tick), so a 'pause now' takes effect at once."""
    try:
        from orchestration import state
        blocker = getattr(state, 'dns_blocker', None)
        if blocker is None:
            return
        policies = get_policies()
        blocked = evaluate_blocked_macs(policies, get_usage_today_by_mac())
        blocker.set_blocked_macs(set(blocked.keys()))
    except Exception as e:
        logger.debug("parental enforce kick failed: %s", e)


def _policies_with_state() -> list:
    policies = get_policies()
    usage = get_usage_today_by_mac()
    blocked = evaluate_blocked_macs(policies, usage)
    for p in policies:
        mac = (p.get("device_mac") or "").lower()
        p["usage_today_bytes"] = usage.get(mac, 0)
        p["blocked_now"] = mac in blocked
        p["block_reason"] = blocked.get(mac)
    return policies


@parental_bp.route('/api/parental/policies', methods=['GET'])
@handle_errors
def list_policies():
    return jsonify({'data': _policies_with_state(), 'status': _enforcement_status()})


@parental_bp.route('/api/parental/policies/<mac>', methods=['PUT'])
@handle_errors
def set_policy(mac):
    payload = request.get_json(silent=True) or {}
    quota = payload.get('daily_quota_mb')
    windows = payload.get('blocked_windows')
    paused = payload.get('paused')
    note = payload.get('note')
    if quota is not None:
        try:
            quota = int(quota) or None
        except (TypeError, ValueError):
            return jsonify({'error': 'daily_quota_mb must be a number'}), 400
    if windows is not None and not isinstance(windows, list):
        return jsonify({'error': 'blocked_windows must be a list of {start,end}'}), 400
    upsert_policy(mac, paused=paused, daily_quota_mb=quota,
                  blocked_windows=windows, note=note)
    _kick_enforcer()
    return jsonify({'data': get_policy(mac), 'status': _enforcement_status()})


@parental_bp.route('/api/parental/policies/<mac>/pause', methods=['POST'])
@handle_errors
def pause_device(mac):
    upsert_policy(mac, paused=True)
    _kick_enforcer()
    return jsonify({'data': get_policy(mac), 'status': _enforcement_status()})


@parental_bp.route('/api/parental/policies/<mac>/resume', methods=['POST'])
@handle_errors
def resume_device(mac):
    upsert_policy(mac, paused=False)
    _kick_enforcer()
    return jsonify({'data': get_policy(mac), 'status': _enforcement_status()})


@parental_bp.route('/api/parental/policies/<mac>', methods=['DELETE'])
@handle_errors
def clear_policy(mac):
    ok = delete_policy(mac)
    _kick_enforcer()
    if not ok:
        return jsonify({'error': f'No policy for {mac}.'}), 404
    return jsonify({'data': {'device_mac': mac, 'deleted': True}})
