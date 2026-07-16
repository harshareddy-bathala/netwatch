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
parameters in citations.
- Base every factual claim on tool results you actually received. If the \
tools do not contain the answer, say so plainly.
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

        for step in range(self._max_steps):
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
                    "steps": step + 1,
                }

            if action.get("action") == "tool":
                name = action.get("tool")
                params = action.get("params") or {}
                if name not in TOOLS:
                    result = {"error": f"unknown tool '{name}'",
                              "available_tools": list(TOOLS)}
                else:
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

            # Unknown action verb — nudge and continue.
            trace.append({"step": step, "error": "unknown action",
                          "raw": raw[:500]})
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user",
                             "content": "action must be 'tool' or 'answer'."})

        # Ran out of steps without a final answer.
        return {
            "available": True,
            "question": question,
            "answer": "I couldn't reach a grounded answer within the tool "
                      "budget for this question.",
            "citations": [],
            "tool_calls": trace,
            "steps": self._max_steps,
            "truncated": True,
        }

    # -- helpers ----------------------------------------------------------

    def _render_tools(self) -> str:
        return "\n".join(f"- {t['name']}: {t['description']}"
                         for t in tool_schema())

    @staticmethod
    def _parse_action(raw: str) -> Optional[Dict[str, Any]]:
        """Extract the first JSON object from the model's text."""
        if not raw:
            return None
        raw = raw.strip()
        # Fast path: whole response is JSON.
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
        # Fallback: find the first {...} block (models often wrap in prose
        # or ```json fences).
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return None
        try:
            obj = json.loads(match.group(0))
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None

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
