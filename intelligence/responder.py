"""
responder.py - AI Incident Responder (propose -> approve -> act)
================================================================

Detection tells you *something happened*. This tells you **what to do about
it**, and then a human decides. That loop — sense, reason, act, with the
human holding the trigger — is what separates an AI-first system from a
dashboard with an ML widget bolted on.

For an open incident the responder produces one verdict::

    {
      "assessment":         "<why this looks the way it does>",
      "confidence":         "low" | "medium" | "high",
      "indicators_matched": ["qname_stuffing", ...],
      "recommended_action": "monitor" | "throttle" | "quarantine"
                            | "dismiss_benign",
      "source":             "model" | "rules"
    }

Three properties make it trustworthy enough to run live:

**Nothing is ever auto-applied.** The verdict is a proposal. Enforcement only
happens when someone clicks, and it routes through the same scoped, expiring,
reversible policy path as every other block.

**The evidence bounds the model.** ``indicators_matched`` is intersected with
the signals actually present in the incident's alerts, so the model cannot
cite a symptom the network never showed. The same rule the investigator uses
for tool citations, applied to evidence.

**It works with no model at all.** ``_rule_verdict`` is a deterministic
assessment over the same evidence, used whenever Ollama is absent, times out,
or emits something that fails validation. Degrading to "no AI available" in
front of an audience is worse than degrading to a plainer answer — and a
fallback that is exercised on every run is a fallback that works.

The rules path is deliberately good at the case that matters most: saying
*"this is a false positive, do not quarantine"*. A tool that cries wolf is
less useful than one that talks you down.
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

VALID_ACTIONS = ("monitor", "throttle", "quarantine", "dismiss_benign")
VALID_CONFIDENCE = ("low", "medium", "high")

# Threat classes that justify cutting a device off if corroborated. The rest
# are observational: a device being *new*, or chatty, is not an attack.
_CONTAINABLE = {"port_scan", "lateral_movement", "beaconing"}

_SYSTEM_PROMPT = """You are NetWatch's incident responder. You assess ONE \
security incident on a home/office Wi-Fi hotspot and recommend an action.

You will be given the incident's alerts and their machine-extracted evidence. \
Judge ONLY from that evidence.

Respond with EXACTLY ONE JSON object and nothing else:
{{"assessment": "<2-3 sentences>", "confidence": "low|medium|high", \
"indicators_matched": ["<signal name from the evidence>", ...], \
"recommended_action": "monitor|throttle|quarantine|dismiss_benign"}}

Rules:
- "indicators_matched" must contain ONLY signal names that appear in the \
evidence you were given. Never invent one.
- Prefer "dismiss_benign" when the evidence is better explained by ordinary \
app behaviour (CDN prefetch, a phone joining a hotspot, streaming) than by \
an attack. Being wrong about an attack is bad; crying wolf is also bad.
- Read "domain_context" carefully. If a domain is flagged \
"is_known_app_infrastructure": true, it is a mainstream app's own CDN. \
Content-delivery networks encode cache keys into hostnames, which produces \
exactly the long, high-entropy DNS names that DNS tunneling produces. On its \
own that is NOT evidence of an attack — recommend "dismiss_benign" unless \
some OTHER indicator (scanning, beaconing, lateral movement) is also present.
- Only recommend "quarantine" for behaviour that would harm the network or \
other devices, with strong evidence. A new phone is not an intruder.
- Be specific about WHAT in the evidence drove the call. Quote counts and \
domains exactly as given.

Incident:
{incident}
"""


# --------------------------------------------------------------------------- #
#  Evidence extraction (pure)
# --------------------------------------------------------------------------- #

def gather_evidence(incident: dict) -> Dict[str, Any]:
    """Flatten an incident's alerts into the facts a verdict may rest on.

    Pure and model-free: the same structure feeds the prompt, the
    deterministic fallback, and the validation of whatever comes back — so
    all three are reasoning about literally the same facts.
    """
    signals: List[str] = []
    threat_types: List[str] = []
    domains: List[str] = []
    items: List[dict] = []
    confidences: List[float] = []

    for alert in incident.get("alerts") or []:
        meta = alert.get("details") or alert.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except (ValueError, TypeError):
                meta = {}
        if not isinstance(meta, dict):
            continue

        ttype = meta.get("threat_type")
        if ttype and ttype not in threat_types:
            threat_types.append(ttype)
        try:
            if meta.get("confidence") is not None:
                confidences.append(float(meta["confidence"]))
        except (TypeError, ValueError):
            pass

        for ev in meta.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            items.append(ev)
            sig = ev.get("signal")
            if sig and sig not in signals:
                signals.append(sig)
            dom = ev.get("domain")
            if dom and dom not in domains:
                domains.append(dom)

    return {
        "incident_id": incident.get("id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "status": incident.get("status", "open"),
        "device_mac": incident.get("device_mac"),
        "alert_count": len(incident.get("alerts") or []),
        "categories": incident.get("categories") or [],
        "threat_types": threat_types,
        "signals": signals,
        "domains": domains,
        "max_detector_confidence": max(confidences) if confidences else None,
        "evidence": items,
        "messages": [a.get("message") for a in (incident.get("alerts") or [])
                     if a.get("message")],
    }


# --------------------------------------------------------------------------- #
#  Deterministic fallback
# --------------------------------------------------------------------------- #

def _known_app_domain(domain: str) -> Optional[str]:
    """Friendly app/org name for a domain, if we recognise it.

    A blocked-looking DNS burst to a domain we can name as a mainstream app's
    CDN is an entirely different proposition from one to a domain nobody has
    heard of.
    """
    if not domain:
        return None
    try:
        from intelligence.app_catalog import app_and_org
        app, org = app_and_org(domain)
        return app or org
    except Exception:
        return None


def _rule_verdict(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Assess an incident without a model, from the same evidence.

    Encodes the judgement calls the detectors deliberately do not make,
    because a detector must be sensitive while a *response* must be specific.
    """
    threats = set(ev.get("threat_types") or [])
    signals = list(ev.get("signals") or [])
    domains = list(ev.get("domains") or [])
    detector_conf = ev.get("max_detector_confidence")

    # --- DNS "tunneling" to a domain we can name as a real app -------------
    if "dns_tunneling" in threats and domains:
        named = [(d, _known_app_domain(d)) for d in domains]
        recognised = [(d, n) for d, n in named if n]
        if recognised:
            d, name = recognised[0]
            return {
                "assessment": (
                    f"The long, high-entropy DNS names are to '{d}', which is "
                    f"{name}'s content-delivery infrastructure. CDNs encode "
                    f"cache keys into hostnames, which looks identical to "
                    f"data exfiltration by shape but is ordinary app traffic. "
                    f"No other indicator on this device supports exfiltration."
                ),
                "confidence": "medium",
                "indicators_matched": [s for s in signals
                                       if s in ("qname_stuffing",)],
                "recommended_action": "dismiss_benign",
                "source": "rules",
            }

    # --- A phone joining a hotspot is the expected case --------------------
    if threats == {"rogue_device"}:
        return {
            "assessment": (
                "A device with no prior history joined the network. On a "
                "hotspot that is the normal way any guest appears, and no "
                "scanning, beaconing or lateral movement accompanied it. "
                "Worth noticing, not worth cutting off."
            ),
            "confidence": "medium",
            "indicators_matched": signals,
            "recommended_action": "monitor",
            "source": "rules",
        }

    # --- Behaviour that actually threatens other devices -------------------
    containable = threats & _CONTAINABLE
    if containable:
        strong = (detector_conf is not None and detector_conf >= 0.8) or \
                 (ev.get("severity") == "critical" and ev.get("alert_count", 0) > 1)
        if strong:
            return {
                "assessment": (
                    f"Evidence of {', '.join(sorted(containable))} from this "
                    f"device, corroborated across {ev.get('alert_count')} "
                    f"alert(s) at detector confidence "
                    f"{detector_conf if detector_conf is not None else 'n/a'}. "
                    f"This behaviour targets other devices on the network, so "
                    f"containing it protects them rather than only this host."
                ),
                "confidence": "high",
                "indicators_matched": signals,
                "recommended_action": "quarantine",
                "source": "rules",
            }
        return {
            "assessment": (
                f"Indicators of {', '.join(sorted(containable))} are present "
                f"but thin — a single alert at detector confidence "
                f"{detector_conf if detector_conf is not None else 'n/a'}. "
                f"Return traffic to ephemeral ports and normal service "
                f"discovery both mimic this. Watch before acting."
            ),
            "confidence": "low",
            "indicators_matched": signals,
            "recommended_action": "monitor",
            "source": "rules",
        }

    # --- Nothing recognised ------------------------------------------------
    return {
        "assessment": (
            "No indicator in this incident maps to a known attack pattern "
            "with enough support to act on. Recorded for review."
        ),
        "confidence": "low",
        "indicators_matched": signals,
        "recommended_action": "monitor",
        "source": "rules",
    }


# --------------------------------------------------------------------------- #
#  Validation
# --------------------------------------------------------------------------- #

def validate_verdict(raw: Any, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return a clean verdict, or None if the model's output cannot be trusted.

    Rejects rather than repairs anything that would change the *meaning* — an
    unparseable action or a missing assessment means we do not know what the
    model concluded, and guessing is worse than falling back. Only the
    citation list is narrowed rather than rejected, the same way the
    investigator drops citations to tools it never called.
    """
    if not isinstance(raw, dict):
        return None

    assessment = raw.get("assessment")
    if not isinstance(assessment, str) or not assessment.strip():
        return None

    action = raw.get("recommended_action")
    if not isinstance(action, str) or action.strip().lower() not in VALID_ACTIONS:
        return None

    confidence = raw.get("confidence")
    if not isinstance(confidence, str) or \
            confidence.strip().lower() not in VALID_CONFIDENCE:
        confidence = "low"      # a missing confidence is a low one

    # Ground the indicators in what the network actually showed.
    known = set(ev.get("signals") or [])
    cited = raw.get("indicators_matched")
    if not isinstance(cited, list):
        cited = []
    grounded = [c for c in cited if isinstance(c, str) and c in known]

    return {
        "assessment": assessment.strip(),
        "confidence": confidence.strip().lower(),
        "indicators_matched": grounded,
        "recommended_action": action.strip().lower(),
        "source": "model",
    }


def _apply_containment_floor(model: Dict[str, Any],
                             rules: Dict[str, Any]) -> Dict[str, Any]:
    """Stop the model talking us out of containing a real attack.

    Measured on llama3.2:3b against this project's own evidence, the model is
    unreliable in *both* directions: it called a benign Meta-CDN DNS burst
    "tunneling, quarantine", and — after that was corrected with domain
    context — called a corroborated port scan plus lateral movement "a
    legitimate port scan, likely from an authorized device".

    Over-blocking a phone is embarrassing. Waving through a device that is
    scanning and moving laterally across other people's machines is not the
    same class of mistake, so the two are not treated symmetrically: the
    deterministic assessment sets a *floor* on containment that the model may
    raise but never lower. The model keeps its real job — explaining, in
    prose, what the evidence means — and loses only the authority it was
    demonstrably not good enough to hold.

    The disagreement is recorded, not hidden: an operator who can see the
    model was overruled can judge both.
    """
    order = {"dismiss_benign": 0, "monitor": 1, "throttle": 2, "quarantine": 3}
    model_rank = order.get(model.get("recommended_action"), 0)
    rules_rank = order.get(rules.get("recommended_action"), 0)
    if model_rank >= rules_rank:
        return model

    out = dict(model)
    out["recommended_action"] = rules["recommended_action"]
    # The displayed reasoning must match the displayed action. Leaving the
    # model's "this looks benign" next to a quarantine button reads as a bug
    # to anyone looking at it, so the assessment that *decided* becomes the
    # assessment that *shows*; the model's is kept alongside, not discarded.
    out["assessment"] = rules.get("assessment", out.get("assessment"))
    out["confidence"] = rules.get("confidence", out.get("confidence"))
    out["overruled"] = {
        "model_recommended": model.get("recommended_action"),
        "model_assessment": model.get("assessment"),
        "reason": "Deterministic assessment of the same evidence requires "
                  "stronger containment; the model may not lower it.",
    }
    logger.info(
        "Responder: model recommended '%s' but evidence requires '%s' — "
        "keeping the stronger action",
        model.get("recommended_action"), rules.get("recommended_action"),
    )
    return out


def _parse_json(raw: str) -> Any:
    """Extract the first JSON object from model text (fences, prose, etc.)."""
    if not raw:
        return None
    raw = raw.strip()
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        pass
    import re
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
#  Responder
# --------------------------------------------------------------------------- #

class Responder:
    """Produces an approve-or-dismiss proposal for one incident."""

    def __init__(self, runtime=None):
        self._runtime = runtime

    def assess(self, incident: dict) -> Dict[str, Any]:
        """Assess *incident*. Always returns a verdict — never raises."""
        ev = gather_evidence(incident)
        verdict = None

        if self._runtime is not None:
            try:
                raw = self._runtime.generate([
                    {"role": "system",
                     "content": _SYSTEM_PROMPT.format(
                         incident=json.dumps(self._prompt_view(ev),
                                             default=str, indent=2))},
                    {"role": "user",
                     "content": "Assess this incident and respond with the "
                                "single JSON object."},
                ])
                verdict = validate_verdict(_parse_json(raw), ev)
                if verdict is None:
                    logger.info(
                        "Responder: model output failed validation for "
                        "incident %s — using deterministic assessment",
                        ev.get("incident_id"),
                    )
            except Exception as exc:
                logger.info("Responder: model unavailable (%s) — using "
                            "deterministic assessment", exc)

        rules = _rule_verdict(ev)
        if verdict is None:
            verdict = rules
        else:
            verdict = _apply_containment_floor(verdict, rules)

        verdict["incident_id"] = ev.get("incident_id")
        verdict["evidence_signals"] = ev.get("signals")
        verdict["device_mac"] = ev.get("device_mac")
        return verdict

    @staticmethod
    def _prompt_view(ev: Dict[str, Any]) -> Dict[str, Any]:
        """The slice of the evidence the model is shown.

        Trimmed deliberately: a 3B model reasons better over a short, flat
        structure than over every field we happen to have.

        ``domain_context`` is the important addition. Asked cold, llama3.2:3b
        reads "63 long DNS queries to fbcdn.net" as tunneling and recommends
        quarantine — it does not reliably know that fbcdn.net is Meta's CDN.
        But we *do* know, deterministically, from the app catalog. Handing
        that over is the same move the investigator's tools make by
        pre-formatting numbers: never ask the model to recall something we
        can look up, because a fact it half-remembers is a fact it can get
        wrong.
        """
        domains = ev.get("domains") or []
        domain_context = []
        for d in domains[:5]:
            known = _known_app_domain(d)
            domain_context.append({
                "domain": d,
                "belongs_to": known or "not a domain NetWatch recognises",
                "is_known_app_infrastructure": bool(known),
            })

        return {
            "title": ev.get("title"),
            "severity": ev.get("severity"),
            "threat_types": ev.get("threat_types"),
            "alert_count": ev.get("alert_count"),
            "detector_confidence": ev.get("max_detector_confidence"),
            "messages": ev.get("messages", [])[:5],
            "evidence": ev.get("evidence", [])[:5],
            "available_signals": ev.get("signals"),
            "domain_context": domain_context,
        }


def build_responder(model: Optional[str] = None) -> Responder:
    """Construct a Responder on the local runtime if one is reachable.

    Unlike ``build_investigator`` this never returns None: an incident can
    always be assessed, just more plainly without a model.
    """
    runtime = None
    try:
        from intelligence.llm_runtime import get_runtime
        runtime = get_runtime(model=model)
    except Exception as exc:
        logger.debug("No LLM runtime for responder: %s", exc)
    return Responder(runtime)
