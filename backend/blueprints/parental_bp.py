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
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

from backend.helpers import handle_errors
from database.queries.policy_queries import (
    get_policies, get_policy, upsert_policy, delete_policy,
    get_usage_today_by_mac, evaluate_blocked_macs,
)

logger = logging.getLogger(__name__)

parental_bp = Blueprint('parental', __name__)


def _enforcement_status() -> dict:
    """Honest status: hotspot-only + which enforcement level is actually active
    (windivert packet-drop > arp blackhole > dns sinkhole)."""
    try:
        from backend.blueprints.blocking_bp import _enforcement_status as s
        status = s()
    except Exception:
        status = {"enforcing": False, "mode": None, "reason": None}
    try:
        from orchestration import state
        tb = getattr(state, 'traffic_blocker', None)
        if tb is not None:
            ts = tb.get_status()
            status["enforcement_level"] = ts.get("mode")       # windivert|arp|off|unavailable
            status["windivert_available"] = ts.get("windivert_available")
            if not ts.get("windivert_available"):
                status["enforcement_note"] = (
                    "Install WinDivert (pip install pydivert) for kernel-level "
                    "packet blocking. Without it, blocking falls back to DNS, "
                    "which encrypted-DNS/QUIC clients can bypass."
                )
    except Exception:
        pass
    return status


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


# A pause with no end outlives the session that created it: the live database
# carried one set at 10:12 that was still dropping a phone's traffic hours
# later, across restarts, with nothing in the UI to explain it. Pauses are
# therefore bounded by default; open-ended is still available, but only by
# asking for it.
DEFAULT_PAUSE_MINUTES = 60
MAX_PAUSE_MINUTES = 24 * 60


@parental_bp.route('/api/parental/policies/<mac>/pause', methods=['POST'])
@handle_errors
def pause_device(mac):
    payload = request.get_json(silent=True) or {}
    minutes = payload.get('minutes', DEFAULT_PAUSE_MINUTES)
    until = None

    if minutes is None:
        # Explicit null = "until I resume it". Deliberate, not the default.
        pass
    else:
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            return jsonify({'error': 'minutes must be a number or null'}), 400
        if minutes < 1 or minutes > MAX_PAUSE_MINUTES:
            return jsonify({
                'error': f'minutes must be between 1 and {MAX_PAUSE_MINUTES}',
            }), 400
        until = (datetime.now() + timedelta(minutes=minutes)).strftime(
            '%Y-%m-%d %H:%M:%S')

    upsert_policy(mac, paused=True, pause_expires_at=until,
                  clear_pause_expiry=(until is None))
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
