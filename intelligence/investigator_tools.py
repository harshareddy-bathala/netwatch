"""
investigator_tools.py - Grounding Tools for LLM Investigations (Phase 3)
========================================================================

The only way the investigator LLM can touch NetWatch data: three
read-only tools that return structured, provenance-tagged JSON.  The
model never sees the database — it must *call a tool* and cite what the
tool returned, which is what makes an answer auditable and keeps the
whole thing offline.

Tools
-----
* ``query_metrics``  — current network metrics (bandwidth, devices,
  protocols, health) and short-horizon bandwidth history.
* ``query_graph``    — the digital-twin graph: nodes (devices/external)
  and their communication edges, optionally filtered to one device.
* ``list_incidents`` — fused incidents and, on request, one incident's
  full alert timeline.

Every result carries a ``provenance`` field naming the source table /
service and the time it was read, so the investigator can cite it and a
reviewer can check it.
"""

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _provenance(source: str, **extra) -> Dict[str, Any]:
    return {"source": source, "read_at": _now_iso(), **extra}


# ---------------------------------------------------------------------------
# Tool: query_metrics
# ---------------------------------------------------------------------------

def query_metrics(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Current network metrics + optional bandwidth history.

    params: {"history_minutes": int (optional, default 0 = none)}
    """
    params = params or {}
    result: Dict[str, Any] = {"provenance": _provenance("stats_queries")}

    try:
        from database.queries.stats_queries import get_realtime_stats
        stats = get_realtime_stats() or {}
        result["current"] = {
            "bandwidth_mbps": stats.get("bandwidth_mbps", 0),
            "download_mbps": stats.get("download_mbps", 0),
            "upload_mbps": stats.get("upload_mbps", 0),
            "active_devices": stats.get("active_devices", 0),
            "packets_per_second": stats.get("packets_per_second", 0),
            "timestamp": stats.get("timestamp"),
        }
    except Exception as exc:
        logger.warning("query_metrics: stats unavailable: %s", exc)
        result["current"] = {}

    try:
        from database.queries.traffic_queries import get_protocol_distribution
        dist = get_protocol_distribution(hours=1) or []
        result["top_protocols"] = [
            {"protocol": d.get("protocol") or d.get("name"),
             "bytes": d.get("bytes") or d.get("total_bytes") or 0}
            for d in dist[:5]
        ]
    except Exception:
        result["top_protocols"] = []

    history_minutes = int(params.get("history_minutes") or 0)
    if history_minutes > 0:
        try:
            from database.queries.traffic_queries import get_bandwidth_history
            hours = max(1, (history_minutes + 59) // 60)
            hist = get_bandwidth_history(hours=hours, interval="minute") or []
            # Summarise rather than dump every bucket, to keep the prompt small.
            mbps = [(b.get("bytes_per_second", 0) * 8 / 1_000_000) for b in hist]
            if mbps:
                result["history_summary"] = {
                    "minutes": len(mbps),
                    "avg_mbps": round(sum(mbps) / len(mbps), 4),
                    "peak_mbps": round(max(mbps), 4),
                }
        except Exception:
            pass
    return result


# ---------------------------------------------------------------------------
# Tool: query_graph
# ---------------------------------------------------------------------------

def query_graph(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Digital-twin graph snapshot, optionally focused on one device.

    params: {"device_mac": str (optional), "max_edges": int (optional)}
    """
    params = params or {}
    result: Dict[str, Any] = {"provenance": _provenance("twin_builder")}

    twin = _get_twin()
    if twin is None:
        result["available"] = False
        result["reason"] = "digital twin is not running"
        result["nodes"] = []
        result["edges"] = []
        return result

    try:
        snap = twin.snapshot(max_edges=int(params.get("max_edges") or 100))
    except Exception as exc:
        logger.warning("query_graph: snapshot failed: %s", exc)
        return {"available": False, "reason": str(exc),
                "nodes": [], "edges": [],
                "provenance": _provenance("twin_builder")}

    nodes = snap.get("nodes", [])
    edges = snap.get("edges", [])
    device_mac = (params.get("device_mac") or "").lower().strip()
    if device_mac:
        nodes = [n for n in nodes if (n.get("mac") or "").lower() == device_mac]
        edges = [e for e in edges
                 if (e.get("source") or "").lower() == device_mac
                 or (e.get("target") or "").lower() == device_mac]

    result["available"] = True
    result["stats"] = snap.get("stats", {})
    result["mode"] = snap.get("mode")
    # Trim node/edge payloads to the fields an investigator needs.
    result["nodes"] = [
        {"mac": n.get("mac"), "ip": n.get("ip"), "type": n.get("type"),
         "hostname": n.get("hostname"), "bytes": n.get("bytes")}
        for n in nodes[:40]
    ]
    result["edges"] = [
        {"source": e.get("source"), "target": e.get("target"),
         "bytes": e.get("bytes"), "protocols": e.get("protocols")}
        for e in edges[:60]
    ]
    return result


# ---------------------------------------------------------------------------
# Tool: list_incidents
# ---------------------------------------------------------------------------

def list_incidents(params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fused incidents, or one incident's full alert timeline.

    params: {"status": "open"|"resolved" (optional),
             "incident_id": int (optional — returns that incident's detail),
             "limit": int (optional)}
    """
    params = params or {}
    result: Dict[str, Any] = {"provenance": _provenance("incident_queries")}
    try:
        from database.queries import incident_queries
    except Exception as exc:
        return {"available": False, "reason": str(exc), "incidents": [],
                "provenance": _provenance("incident_queries")}

    incident_id = params.get("incident_id")
    if incident_id is not None:
        detail = incident_queries.get_incident(int(incident_id))
        result["incident"] = detail
        result["available"] = detail is not None
        if detail is None:
            result["reason"] = f"incident {incident_id} not found"
        return result

    status = params.get("status")
    if status not in (None, "open", "resolved"):
        status = None
    limit = int(params.get("limit") or 20)
    incidents = incident_queries.get_incidents(status=status, limit=limit)
    result["available"] = True
    result["incidents"] = [
        {"id": i["id"], "title": i["title"], "severity": i["severity"],
         "status": i["status"], "device_mac": i.get("device_mac"),
         "alert_count": i.get("alert_count"), "categories": i.get("categories"),
         "updated_at": i.get("updated_at")}
        for i in incidents
    ]
    result["count"] = len(result["incidents"])
    return result


def _get_twin():
    try:
        from orchestration import state
        return getattr(state, "twin_builder", None)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tool registry — the schema the LLM is given
# ---------------------------------------------------------------------------

TOOLS: Dict[str, Dict[str, Any]] = {
    "query_metrics": {
        "fn": query_metrics,
        "description": (
            "Get current network metrics: bandwidth (Mbps), active device "
            "count, packets/sec, top protocols, and optional recent "
            "bandwidth history. Params: {\"history_minutes\": int optional}."
        ),
    },
    "query_graph": {
        "fn": query_graph,
        "description": (
            "Get the network digital-twin graph: device/external nodes and "
            "their communication edges (bytes, protocols). Optionally focus "
            "on one device. Params: {\"device_mac\": str optional, "
            "\"max_edges\": int optional}."
        ),
    },
    "list_incidents": {
        "fn": list_incidents,
        "description": (
            "List fused security/operational incidents, or fetch one "
            "incident's full alert timeline. Params: {\"status\": "
            "\"open\"|\"resolved\" optional, \"incident_id\": int optional, "
            "\"limit\": int optional}."
        ),
    },
}


def tool_schema() -> List[Dict[str, str]]:
    """The tool list handed to the model (name + description only)."""
    return [{"name": name, "description": spec["description"]}
            for name, spec in TOOLS.items()]


def run_tool(name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a tool by name; raises KeyError for an unknown tool."""
    spec = TOOLS.get(name)
    if spec is None:
        raise KeyError(f"unknown tool: {name}")
    return spec["fn"](params or {})
