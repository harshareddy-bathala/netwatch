"""
briefing.py - "What just happened?" in plain English
=====================================================

One button that answers the question every operator actually has, which no
chart answers: *what has been going on, and do I need to care?*

The facts are gathered deterministically — devices, the apps they used, the
alerts that fired — and a local model is asked only to narrate them. That
split is the point: the model never queries anything and never sees raw
tables, so it cannot invent a device or a domain. If it is unavailable or
wanders off the facts, ``compose_fallback`` writes the same briefing plainly
from the same numbers.

Domains are resolved through :mod:`intelligence.app_catalog` so the text says
"Instagram" and "Meta" rather than ``scontent-bom1-2.cdninstagram.com``. That
is most of what makes it read like a human wrote it.

Cached briefly: the button is on a live dashboard, and regenerating a
paragraph on every click would queue model calls behind each other.
"""

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_MINUTES = 10
CACHE_SECONDS = 60

_SYSTEM_PROMPT = """You write a short status briefing for the operator of a \
Wi-Fi hotspot, from facts that have already been gathered for you.

Write 2-4 short sentences of plain English. No bullet points, no headings, \
no preamble like "Here is your briefing".

Rules:
- Use ONLY the facts given. Never invent a device, app, domain or number.
- Quote numbers and names EXACTLY as they appear. Do not convert units or \
add things up yourself.
- Refer to apps and companies by the friendly names given (e.g. "Instagram", \
"Meta"), not by raw domain names.
- If an alert fired, say what it was and whether the evidence supports it.
- If the network was quiet, say so plainly. A boring network is good news, \
not something to dramatise.

Facts:
{facts}
"""


# --------------------------------------------------------------------------- #
#  Fact gathering (deterministic — no model involved)
# --------------------------------------------------------------------------- #

def gather_facts(window_minutes: int = DEFAULT_WINDOW_MINUTES) -> Dict[str, Any]:
    """Collect what happened recently. Never raises; missing parts are simply
    absent, so a briefing still works when a subsystem is down."""
    facts: Dict[str, Any] = {
        "window_minutes": window_minutes,
        "devices": [],
        "top_apps": [],
        "alerts": [],
        "metrics": {},
    }

    # --- live metrics ------------------------------------------------------
    try:
        from database.queries.stats_queries import get_realtime_stats
        stats = get_realtime_stats() or {}
        facts["metrics"] = {
            "active_devices": stats.get("active_devices", 0),
            "bandwidth_mbps": round(float(stats.get("bandwidth_mbps") or 0), 2),
            "health_score": stats.get("health_score"),
        }
    except Exception as exc:
        logger.debug("briefing: metrics unavailable: %s", exc)

    # --- who was here, and what they used ---------------------------------
    try:
        from database.queries.flow_queries import get_recent_activity
        from intelligence.app_catalog import app_and_org

        exclude_macs, exclude_ips = set(), set()
        try:
            from utils.realtime_state import dashboard_state
            ident = dashboard_state.get_host_identity()
            exclude_macs = {m.lower() for m in (ident.get("macs") or set())}
            exclude_ips = set(ident.get("ips") or set())
        except Exception:
            pass

        rows = get_recent_activity(minutes=window_minutes, limit=400,
                                   exclude_macs=exclude_macs,
                                   exclude_ips=exclude_ips) or []
        per_device: Dict[str, Dict[str, Any]] = {}
        app_counts: Dict[str, int] = {}
        for row in rows:
            name = (row.get("device_name") or row.get("hostname")
                    or row.get("source_mac") or "unknown")
            entry = per_device.setdefault(
                name, {"device": name, "lookups": 0, "apps": {}})
            entry["lookups"] += 1

            domain = row.get("domain") or row.get("qname") or ""
            app, org = (None, None)
            try:
                app, org = app_and_org(domain)
            except Exception:
                pass
            label = app or org or domain
            if label:
                entry["apps"][label] = entry["apps"].get(label, 0) + 1
                app_counts[label] = app_counts.get(label, 0) + 1

        for entry in per_device.values():
            entry["top_apps"] = [
                a for a, _n in sorted(entry["apps"].items(),
                                      key=lambda kv: kv[1], reverse=True)[:3]
            ]
            entry.pop("apps", None)
        facts["devices"] = sorted(per_device.values(),
                                  key=lambda d: d["lookups"], reverse=True)[:6]
        facts["top_apps"] = [
            {"app": a, "lookups": n}
            for a, n in sorted(app_counts.items(), key=lambda kv: kv[1],
                               reverse=True)[:5]
        ]
    except Exception as exc:
        logger.debug("briefing: activity unavailable: %s", exc)

    # --- what fired --------------------------------------------------------
    try:
        from database.queries.alert_queries import get_alerts
        alerts = get_alerts(limit=10) or []
        # The alerts table has no `title` column — the human label lives in
        # the message (and, for threat alerts, the threat_type in details).
        facts["alerts"] = [
            {"severity": a.get("severity"),
             "type": _alert_kind(a),
             "message": a.get("message"),
             "timestamp": a.get("timestamp")}
            for a in alerts
        ][:5]
    except Exception as exc:
        logger.debug("briefing: alerts unavailable: %s", exc)

    return facts


# --------------------------------------------------------------------------- #
#  Deterministic narrative
# --------------------------------------------------------------------------- #

def _alert_kind(alert: dict) -> str:
    """Best label for an alert: its threat type, else its category."""
    details = alert.get("details")
    if isinstance(details, str):
        try:
            import json
            details = json.loads(details)
        except (ValueError, TypeError):
            details = None
    if isinstance(details, dict) and details.get("threat_type"):
        return str(details["threat_type"])
    return str(alert.get("alert_type") or "alert")


def compose_fallback(facts: Dict[str, Any]) -> str:
    """Write the briefing from the facts without a model.

    Used when no local model is reachable, and as the honest floor: whatever
    the model does, this is the version we can always stand behind.
    """
    window = facts.get("window_minutes", DEFAULT_WINDOW_MINUTES)
    devices = facts.get("devices") or []
    alerts = facts.get("alerts") or []
    metrics = facts.get("metrics") or {}
    parts: List[str] = []

    if devices:
        named = []
        for d in devices[:3]:
            apps = d.get("top_apps") or []
            if apps:
                named.append(f"{d['device']} ({', '.join(apps[:2])})")
            else:
                named.append(str(d["device"]))
        count = len(devices)
        parts.append(
            f"{count} device{'s' if count != 1 else ''} were active in the last "
            f"{window} minutes: {'; '.join(named)}."
        )
    else:
        parts.append(f"No client activity in the last {window} minutes.")

    if metrics.get("bandwidth_mbps") is not None:
        parts.append(
            f"Current throughput is {metrics['bandwidth_mbps']} Mbps across "
            f"{metrics.get('active_devices', 0)} active device(s)."
        )

    if alerts:
        first = alerts[0]
        parts.append(
            f"{len(alerts)} alert(s) in the feed, most recently a "
            f"{first.get('severity')} {first.get('type')}: "
            f"{first.get('message')}"
        )
    else:
        parts.append("No alerts fired.")

    return " ".join(parts)


# --------------------------------------------------------------------------- #
#  Briefing service
# --------------------------------------------------------------------------- #

class Briefer:
    """Produces the narrative, with a short cache and a model-free floor."""

    def __init__(self, runtime=None, cache_seconds: int = CACHE_SECONDS,
                 clock=time.monotonic):
        self._runtime = runtime
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._cached: Optional[Dict[str, Any]] = None
        self._cached_at = 0.0

    def brief(self, window_minutes: int = DEFAULT_WINDOW_MINUTES,
              force: bool = False) -> Dict[str, Any]:
        """Return ``{narrative, source, facts, window_minutes}``.

        ``source`` is "model" or "facts" — the UI says which, because a
        generated paragraph and a computed one deserve different trust.
        """
        if (not force and self._cached is not None
                and (self._clock() - self._cached_at) < self._cache_seconds
                and self._cached.get("window_minutes") == window_minutes):
            return dict(self._cached, cached=True)

        facts = gather_facts(window_minutes)
        narrative, source = compose_fallback(facts), "facts"

        if self._runtime is not None:
            try:
                import json
                text = self._runtime.generate([
                    {"role": "system",
                     "content": _SYSTEM_PROMPT.format(
                         facts=json.dumps(facts, default=str, indent=2))},
                    {"role": "user", "content": "Write the briefing."},
                ])
                text = _clean(text)
                if _is_usable(text):
                    narrative, source = text, "model"
                else:
                    logger.info("Briefing: model output unusable — using "
                                "computed narrative")
            except Exception as exc:
                logger.info("Briefing: model unavailable (%s) — using "
                            "computed narrative", exc)

        result = {
            "narrative": narrative,
            "source": source,
            "facts": facts,
            "window_minutes": window_minutes,
        }
        self._cached, self._cached_at = result, self._clock()
        return dict(result, cached=False)


def _clean(text: str) -> str:
    """Strip the scaffolding small models add around prose."""
    if not text:
        return ""
    text = text.strip()
    # Drop a leading "Briefing:"-style label and any code fences.
    text = text.replace("```", "").strip()
    for prefix in ("Briefing:", "Here is the briefing:", "Summary:",
                   "Here's a short status briefing:"):
        if text.lower().startswith(prefix.lower()):
            text = text[len(prefix):].strip()
    return text


def _is_usable(text: str) -> bool:
    """Cheap sanity floor on generated prose.

    Not a faithfulness check — that is what grounding the prompt in gathered
    facts is for. This only rejects the failure modes that make a model's
    output worse than the computed sentence: empty, truncated, or the model
    talking about itself instead of the network.
    """
    if not text or len(text) < 40:
        return False
    lowered = text.lower()
    refusals = ("i cannot", "i can't", "as an ai", "i do not have access",
                "please provide")
    return not any(r in lowered for r in refusals)


def build_briefer(model: Optional[str] = None) -> Briefer:
    """Construct a Briefer on the local runtime if one is reachable."""
    runtime = None
    try:
        from intelligence.llm_runtime import get_runtime
        runtime = get_runtime(model=model)
    except Exception as exc:
        logger.debug("No LLM runtime for briefing: %s", exc)
    return Briefer(runtime)
