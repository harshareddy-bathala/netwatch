"""
blocking_bp.py - Client Blocking Policy Endpoints
=================================================

Admin control over what connected clients are allowed to reach:

* ``GET    /api/blocking/rules``       — list rules (+ enforcement status)
* ``POST   /api/blocking/rules``       — block a domain (optionally per-client)
* ``PATCH  /api/blocking/rules/<id>``  — enable/disable a rule
* ``DELETE /api/blocking/rules/<id>``  — remove a rule

Rules are enforced by ``packet_capture.dns_blocker`` on the capture thread.
Every mutation reloads the blocker's in-memory index so changes take effect
on the next lookup rather than at the next restart.
"""

import logging

from flask import Blueprint, jsonify, request

from backend.helpers import handle_errors
from database.queries.blocking_queries import (
    add_rule, delete_rule, get_rules, set_rule_enabled,
)

logger = logging.getLogger(__name__)

blocking_bp = Blueprint('blocking', __name__)


def _get_blocker():
    from orchestration import state
    return getattr(state, 'dns_blocker', None)


def _reload_blocker() -> None:
    """Push rule changes into the running blockers (no-op when not capturing).

    Two enforcement layers, both refreshed here so a rule takes effect on the
    next packet rather than at the next 30s policy sweep:
      * DNS sinkhole — forges NXDOMAIN for plaintext lookups.
      * Packet blocker — drops the domain's server IPs, which is the only
        layer that stops DoH/QUIC apps (Instagram, YouTube) that never ask us
        to resolve anything.
    """
    blocker = _get_blocker()
    if blocker is not None:
        try:
            blocker.reload()
        except Exception as e:
            logger.error("Could not reload DNS blocker rules: %s", e)
    try:
        from orchestration.background_tasks import apply_blocking_rules_now
        apply_blocking_rules_now()
    except Exception as e:
        logger.error("Could not apply packet-level blocking rules: %s", e)


def _enforcement_status() -> dict:
    """Tell the UI whether these rules are actually being applied.

    Blocking depends on NetWatch sitting between the client and its
    resolver, which is only true in hotspot mode. Saying so plainly beats a
    rules page that silently does nothing.
    """
    from orchestration import state

    blocker = _get_blocker()
    mode = None
    try:
        if state.interface_manager:
            cur = state.interface_manager.get_current_mode()
            if cur:
                mode = cur.get_mode_name().value
    except Exception:
        mode = None

    # Packet-level enforcement (WinDivert) is what actually stops DoH/QUIC
    # apps; DNS sinkholing alone only catches plaintext lookups.
    traffic = getattr(state, 'traffic_blocker', None)
    packet_mode = None
    if traffic is not None:
        try:
            packet_mode = traffic.get_status().get("mode")
        except Exception:
            packet_mode = None
    packet_active = packet_mode == "windivert"

    active = (blocker is not None and mode == "hotspot") or packet_active
    if packet_active:
        reason = None
    elif blocker is not None and mode == "hotspot":
        reason = (
            "Enforcing by DNS only. Apps using encrypted DNS (DoH) or cached "
            "IPs over QUIC — Instagram, YouTube, Brave — can bypass this. "
            "Install pydivert and run as Administrator for packet-level "
            "blocking that they cannot bypass."
        )
    elif blocker is None:
        reason = "Capture is not running, so blocking rules are not being enforced."
    else:
        reason = (
            f"Blocking only applies in hotspot mode, where clients route "
            f"through this host. Current mode is '{mode or 'unknown'}', so "
            f"rules are saved but not enforced."
        )
    return {"enforcing": active, "mode": mode, "reason": reason,
            "packet_mode": packet_mode, "level": "packet" if packet_active
            else ("dns" if blocker is not None and mode == "hotspot" else "none")}


@blocking_bp.route('/api/blocking/rules', methods=['GET'])
@handle_errors
def list_rules():
    return jsonify({
        'data': get_rules(),
        'status': _enforcement_status(),
    })


@blocking_bp.route('/api/blocking/rules', methods=['POST'])
@handle_errors
def create_rule():
    payload = request.get_json(silent=True) or {}
    domain = payload.get('domain') or ''
    mac = payload.get('device_mac') or None
    note = payload.get('note') or None
    # 'device' (default) drops only this client's traffic to the domain;
    # 'network' drops it for every client and for this host too.
    scope = payload.get('scope') or None

    rule = add_rule(domain, device_mac=mac, note=note, scope=scope)
    if rule is None:
        return jsonify({
            'error': f"'{domain}' is not a valid domain name.",
        }), 400

    _reload_blocker()
    return jsonify({'data': rule, 'status': _enforcement_status()}), 201


@blocking_bp.route('/api/blocking/rules/<int:rule_id>', methods=['PATCH'])
@handle_errors
def update_rule(rule_id: int):
    payload = request.get_json(silent=True) or {}
    if 'enabled' not in payload:
        return jsonify({'error': "Nothing to update; expected 'enabled'."}), 400

    if not set_rule_enabled(rule_id, bool(payload['enabled'])):
        return jsonify({'error': f'No blocking rule with id {rule_id}.'}), 404

    _reload_blocker()
    return jsonify({'data': {'id': rule_id, 'enabled': bool(payload['enabled'])}})


@blocking_bp.route('/api/blocking/rules/<int:rule_id>', methods=['DELETE'])
@handle_errors
def remove_rule(rule_id: int):
    if not delete_rule(rule_id):
        return jsonify({'error': f'No blocking rule with id {rule_id}.'}), 404

    _reload_blocker()
    return jsonify({'data': {'id': rule_id, 'deleted': True}})
