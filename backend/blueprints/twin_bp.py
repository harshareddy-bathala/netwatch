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
    get_recent_flows, get_recent_dns_queries, get_recent_activity,
    get_recent_client_destinations,
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


def _get_vpn():
    from orchestration import state
    return getattr(state, 'vpn_detector', None)


def _get_incidents():
    from orchestration import state
    return getattr(state, 'incident_manager', None)


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
    incidents = _get_incidents()
    try:
        from intelligence.event_bus import event_bus
        bus_stats = event_bus.get_stats()
    except Exception:
        bus_stats = {}
    vpn = _get_vpn()
    return jsonify({'data': {
        'twin': twin.get_stats() if twin else {'running': False},
        'behavior': behavior.get_stats() if behavior else {'running': False},
        'threats': threats.get_stats() if threats else {'running': False},
        'incidents': incidents.get_stats() if incidents else {'running': False},
        'vpn': vpn.get_stats() if vpn else {'running': False},
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


@twin_bp.route('/api/activity/recent', methods=['GET'])
@handle_errors
def get_activity_recent():
    """Live per-client activity feed: recent DNS lookups (site/app usage)
    enriched with each client's friendly name. Newest first."""
    minutes = min(max(request.args.get('minutes', 5, type=int), 1), 1440)
    limit = min(max(request.args.get('limit', 300, type=int), 1), 1000)
    mac = request.args.get('mac')
    # Exclude the monitoring host / gateway so it never shows as a client
    # (hotspot: the host IS the gateway). Same identity the dashboard uses.
    exclude_macs = exclude_ips = None
    try:
        from utils.realtime_state import dashboard_state
        ident = dashboard_state.get_host_identity()
        exclude_macs, exclude_ips = ident.get("macs"), ident.get("ips")
    except Exception:
        pass
    rows = get_recent_activity(
        minutes=minutes, limit=limit, mac=mac,
        exclude_macs=exclude_macs, exclude_ips=exclude_ips)
    rows.extend(_org_fallback_rows(minutes, exclude_macs, exclude_ips, mac))
    rows.extend(_vpn_rows(mac))
    _annotate_sites(rows)
    rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return jsonify({'data': rows})


def _annotate_sites(rows):
    """Add friendly site/app/org to each row from its domain, so the feed can
    show 'Instagram'/'Meta' (works with plain DNS too, not just IP→org)."""
    try:
        from intelligence.app_catalog import classify_site
    except Exception:
        return
    for r in rows:
        if r.get("app") or r.get("protocol") == "VPN":
            continue
        site = classify_site(r.get("qname") or "")
        r["site"] = site["domain"]
        if site["app"]:
            r["app"] = site["app"]
        if site["org"] and not r.get("org"):
            r["org"] = site["org"]


def _vpn_rows(mac):
    """One synthetic activity row per device currently using a VPN, so the
    Activity feed shows the tunnel (provider + the honest 'contents hidden'
    note) alongside whatever plaintext names remain."""
    vpn = _get_vpn()
    if vpn is None:
        return []
    import time as _t
    out = []
    for dmac, badge in list(getattr(vpn, 'active_vpns', {}).items()):
        if mac and dmac.lower() != mac.lower():
            continue
        label = badge.get("protocol") or "encrypted tunnel"
        if badge.get("provider") and badge["provider"] != "unknown provider":
            label += f" → {badge['provider']}"
        out.append({
            "timestamp": _t.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": None,
            "source_mac": dmac,
            "qname": f"VPN: {label} (contents hidden)",
            "qtype": None,
            "protocol": "VPN",
            "device_name": None,
        })
    return out


def _org_fallback_rows(minutes, exclude_macs, exclude_ips, mac):
    """Synthetic activity rows naming the *organization* a device reached,
    for traffic with no recovered DNS/SNI name (encrypted DNS + ECH/QUIC or
    a VPN tunnel). protocol='ORG' so the UI tags them 'via IP'. Deduped per
    (device, org)."""
    try:
        from intelligence.ip_org import lookup_org
        dests = get_recent_client_destinations(
            minutes=minutes, exclude_macs=exclude_macs, exclude_ips=exclude_ips)
    except Exception:
        return []
    seen = set()
    out = []
    for d in dests:
        if mac and (d.get("source_mac") or "").lower() != mac.lower():
            continue
        org = lookup_org(d.get("dest_ip") or "")
        if not org:
            continue
        key = ((d.get("source_mac") or d.get("source_ip") or ""), org)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "timestamp": d.get("last_seen"),
            "source_ip": d.get("source_ip"),
            "source_mac": d.get("source_mac"),
            "qname": org,
            "qtype": None,
            "protocol": "ORG",
            "device_name": d.get("device_name"),
        })
    return out


@twin_bp.route('/api/threats/recent', methods=['GET'])
@handle_errors
def get_threats_recent():
    """Recent fired threat detections (+ VPN), with parsed evidence, for the
    standalone Threats view. Reads the alert stream and unpacks the detector
    metadata each carries."""
    import json
    from database.queries.alert_queries import get_alerts
    limit = min(max(request.args.get('limit', 100, type=int), 1), 500)
    out = []
    for a in get_alerts(limit=limit, include_resolved=False):
        details = a.get("details")
        meta = {}
        if details:
            try:
                meta = json.loads(details) if isinstance(details, str) else details
            except (ValueError, TypeError):
                meta = {}
        ttype = meta.get("threat_type")
        if not ttype:
            continue        # only detector-produced alerts belong here
        out.append({
            "id": a.get("id"),
            "timestamp": a.get("timestamp"),
            "severity": a.get("severity"),
            "threat_type": ttype,
            "message": a.get("message"),
            "device_mac": meta.get("device_mac"),
            "confidence": meta.get("confidence"),
            "evidence": meta.get("evidence") or [],
            "incident_id": a.get("incident_id"),
        })
    return jsonify({'data': out})


@twin_bp.route('/api/behavior/profiles/<mac>', methods=['GET'])
@handle_errors
def get_behavior_profile(mac):
    """Learned hour-of-week baselines for one device."""
    behavior = _get_behavior()
    if behavior is None:
        return jsonify({'data': {'mac': mac, 'metrics': {}}})
    return jsonify({'data': behavior.get_profile_summary(mac)})
