"""
investigator.py - Tool-Grounded LLM Investigator (Phase 3)
===========================================================

"Ask NetWatch": answer natural-language questions about the network by
letting a local LLM call the read-only grounding tools
(:mod:`intelligence.investigator_tools`) and cite what they return.

The model never sees raw data — it must request a tool, receive the
tool's JSON, and ground its final answer in those results.  Every
investigation returns the answer *plus* the full trace of tool calls and
their results, so any claim can be checked against its source — the
explainability property Phase 3 is about.

Protocol (engine-agnostic, works with any instruct model)
---------------------------------------------------------
Each turn the model must emit a single JSON object:

    {"action": "tool", "tool": "<name>", "params": {...}}   # call a tool
    {"action": "answer", "answer": "...", "citations": [...]}  # finish

The loop executes tools, feeds results back, and stops at the first
``answer`` or after ``max_steps`` tool calls (bounded, so a confused
model can never loop forever).
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from intelligence.investigator_tools import TOOLS, run_tool, tool_schema
from intelligence.llm_runtime import LLMUnavailable

logger = logging.getLogger(__name__)

DEFAULT_MAX_STEPS = 5

_SYSTEM_PROMPT = """You are NetWatch's network investigator. You answer \
questions about a live network strictly from data you retrieve with tools \
— never from prior knowledge or assumptions.

You have these tools:
{tools}

Rules:
- Respond with EXACTLY ONE JSON object and nothing else.
- To use a tool: {{"action": "tool", "tool": "<name>", "params": {{...}}}}
- To answer: {{"action": "answer", "answer": "<text>", "citations": \
["<tool name you used>", ...]}}
- You start with NO data about this network. You MUST call at least one \
tool and read its result before you may answer. Answering before calling \
a tool is always wrong, even for a yes/no question.
- "answer" must be a STRING of prose — never a bare true/false or number.
- "citations" must contain ONLY tool names you actually called, exactly as \
spelled above. Never cite a tool you did not call, and never put \
parameters in citations. Always cite the tools you used.
- Quote numbers EXACTLY as they appear in the tool result. Do NOT convert \
units, do not turn bytes into MB, do not turn Mbps into kbps, do not add \
up numbers yourself. If a result gives a "human" or "summary" field, use \
its wording. A number you calculated is not evidence.
- Base every factual claim on tool results you actually received. If the \
tools do not contain the answer, say so plainly.
- If a tool reports it is unavailable, do NOT call it again — say that \
part is unavailable and answer with what you do have.
- Once you have the data you need, answer. Do not call tools needlessly.
"""


class Investigator:
    """Runs the tool-grounded investigation loop against an LLM runtime."""

    def __init__(self, runtime, max_steps: int = DEFAULT_MAX_STEPS):
        self._runtime = runtime
        self._max_steps = max_steps

    def investigate(self, question: str) -> Dict[str, Any]:
        """Answer *question*.  Returns a structured, auditable result."""
        messages = [
            {"role": "system",
             "content": _SYSTEM_PROMPT.format(tools=self._render_tools())},
            {"role": "user", "content": question},
        ]
        trace: List[Dict[str, Any]] = []
        nudged_to_ground = False
        tool_calls_made = 0
        step = 0
        # The budget counts *tool calls*. Protocol corrections (grounding
        # nudge, unparseable retry, unknown-tool feedback) are common on
        # small models and must not eat the retrieval budget — but they
        # still need a hard ceiling so a model that never emits valid JSON
        # cannot loop forever.
        max_iterations = self._max_steps * 2 + 2

        while step < max_iterations:
            step += 1
            try:
                raw = self._runtime.generate(messages)
            except LLMUnavailable as exc:
                # The backend died or the model isn't pulled — degrade
                # gracefully instead of surfacing a 500. Preserve any tool
                # results already gathered.
                logger.warning("Investigation aborted — LLM unavailable: %s", exc)
                return {
                    "available": False,
                    "question": question,
                    "reason": f"The local model became unavailable mid-"
                              f"investigation: {exc}",
                    "answer": "",
                    "citations": [],
                    "tool_calls": trace,
                    "steps": step,
                }
            action = self._parse_action(raw)

            if action is None:
                # Model emitted unparseable output — ask it to retry once,
                # then give up gracefully.
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": "Respond with a single valid JSON object as "
                               "instructed (action = tool or answer).",
                })
                trace.append({"step": step, "error": "unparseable",
                              "raw": raw[:500]})
                continue

            if action.get("action") == "answer":
                # Grounding is enforced here, not just requested in the
                # prompt: small instruct models will happily answer a
                # network question at step 0 — citing tools they never
                # called. Push back once; if the model still insists it
                # has nothing to look up, let the answer through (some
                # questions genuinely need no data) and let the trace show
                # it was ungrounded.
                if not nudged_to_ground and not self._called_a_tool(trace):
                    nudged_to_ground = True
                    trace.append({"step": step,
                                  "error": "ungrounded_answer_rejected",
                                  "raw": raw[:500]})
                    messages.append({"role": "assistant", "content": raw})
                    messages.append({
                        "role": "user",
                        "content": "You have not called any tool yet, so you "
                                   "have no data about this network and "
                                   "cannot answer or cite anything. Call a "
                                   "tool now: respond with a single JSON "
                                   'object {"action": "tool", "tool": '
                                   '"<name>", "params": {}}.',
                    })
                    continue
                return {
                    "available": True,
                    "question": question,
                    "answer": self._coerce_answer(action.get("answer")),
                    "citations": self._valid_citations(action.get("citations")),
                    "tool_calls": trace,
                    "steps": step,
                }

            if action.get("action") == "tool":
                name = action.get("tool")
                params = action.get("params") or {}
                if tool_calls_made >= self._max_steps:
                    # Budget spent. Don't just give up — the model has real
                    # results in hand, so require it to answer from them.
                    trace.append({"step": step,
                                  "error": "tool_budget_exhausted",
                                  "raw": raw[:500]})
                    messages.append({"role": "assistant", "content": raw})
                    messages.append({
                        "role": "user",
                        "content": "You have used your entire tool budget. "
                                   "Answer now using only the tool results "
                                   "you already received, and cite them. If "
                                   "they do not cover the question, say so.",
                    })
                    continue
                if name not in TOOLS:
                    # A protocol error, not retrieval — feed the real tool
                    # names back without charging the budget (max_iterations
                    # still bounds it).
                    result = {"error": f"unknown tool '{name}'",
                              "available_tools": list(TOOLS)}
                else:
                    tool_calls_made += 1
                    try:
                        result = run_tool(name, params)
                    except Exception as exc:  # tool must never crash the loop
                        logger.warning("tool %s failed: %s", name, exc)
                        result = {"error": str(exc)}
                trace.append({"step": step, "tool": name, "params": params,
                              "result": result})
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": f"Tool {name} returned:\n"
                               f"{json.dumps(result, default=str)}",
                })
                continue

            # Unknown action verb — show the exact shape rather than just
            # naming the rule; a 3B model repeats its mistake otherwise.
            trace.append({"step": step, "error": "unknown action",
                          "raw": raw[:500]})
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": '"action" must be the literal string "tool" or '
                           '"answer" — not a tool name. To call a tool: '
                           '{"action": "tool", "tool": "query_graph", '
                           '"params": {}}. Try again.',
            })

        # Ran out of budget without a final answer. The trace still holds
        # everything retrieved, so the caller can show its work.
        return {
            "available": True,
            "question": question,
            "answer": "I couldn't reach a grounded answer within the tool "
                      "budget for this question.",
            "citations": [],
            "tool_calls": trace,
            "steps": step,
            "truncated": True,
        }

    # -- helpers ----------------------------------------------------------

    def _render_tools(self) -> str:
        return "\n".join(f"- {t['name']}: {t['description']}"
                         for t in tool_schema())

    @classmethod
    def _parse_action(cls, raw: str) -> Optional[Dict[str, Any]]:
        """Extract the first JSON object from the model's text."""
        if not raw:
            return None
        raw = raw.strip()
        # Fast path: whole response is JSON.
        try:
            obj = json.loads(raw)
            return cls._normalise_action(obj) if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
        # Fallback: find the first {...} block (models often wrap in prose
        # or ```json fences).
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return None
        try:
            obj = json.loads(match.group(0))
            return cls._normalise_action(obj) if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _normalise_action(obj: Dict[str, Any]) -> Dict[str, Any]:
        """Repair near-miss protocol deviations from small models.

        llama3.2:3b reliably emits the *tool name* in the ``action`` field
        instead of the literal "tool"::

            {"action": "query_graph", "tool": "query_graph", "params": {...}}

        The intent is unambiguous — it names a real tool — but a strict
        reading calls this an unknown verb, and the model repeats the same
        malformed call every turn (observed: 14 iterations, zero tool calls,
        investigation truncated). Rewriting the verb is strictly better than
        rejecting a request whose meaning is certain.

        Only unambiguous repairs are made: the value must name a registered
        tool. Anything else is left alone for the loop to reject.
        """
        verb = obj.get("action")
        if verb in ("tool", "answer") or not isinstance(verb, str):
            return obj
        if verb in TOOLS:
            # "action" holds a tool name. Trust an explicit "tool" field if
            # it also names a real tool; otherwise the verb *is* the tool.
            named = obj.get("tool")
            obj = dict(obj)
            obj["tool"] = named if named in TOOLS else verb
            obj["action"] = "tool"
        elif "answer" in obj and verb.lower() in ("respond", "reply", "final"):
            obj = dict(obj)
            obj["action"] = "answer"
        return obj

    @staticmethod
    def _called_a_tool(trace: List[Dict[str, Any]]) -> bool:
        """True once the investigation has actually run a tool."""
        return any(entry.get("tool") for entry in trace)

    @staticmethod
    def _coerce_answer(answer: Any) -> str:
        """The answer contract is a string. Instruct models occasionally
        emit a bool/number/object for the ``answer`` field — coerce it so
        no downstream consumer (API, frontend, faithfulness metric) sees a
        non-string."""
        if answer is None:
            return ""
        if isinstance(answer, str):
            return answer
        if isinstance(answer, bool):
            return "yes" if answer else "no"
        if isinstance(answer, (int, float)):
            return str(answer)
        # dict/list — serialise so the text is still inspectable.
        try:
            return json.dumps(answer, default=str)
        except (TypeError, ValueError):
            return str(answer)

    @staticmethod
    def _valid_citations(citations: Any) -> List[str]:
        """Keep only citations that name real tools — an answer can't cite
        a source it never had."""
        if not isinstance(citations, list):
            return []
        return [c for c in citations if c in TOOLS]


def build_investigator(model: Optional[str] = None,
                       max_steps: int = DEFAULT_MAX_STEPS) -> Optional[Investigator]:
    """Construct an Investigator on a live local runtime, or None when no
    LLM backend is available (caller treats None as 'investigations off')."""
    from intelligence.llm_runtime import get_runtime
    runtime = get_runtime(model=model)
    if runtime is None:
        return None
    return Investigator(runtime, max_steps=max_steps)
