"""
faithfulness.py - Citation-Faithfulness Measurement (Phase 4)
==============================================================

Measures whether the investigator's *answer* is actually grounded in the
tool results it retrieved — the research contribution behind
"tool-grounded local-LLM network investigation with citation-faithfulness
measurement".

Three metrics per investigation:

* **citation_validity** — fraction of cited tools that the investigation
  actually called.  A citation to a tool it never ran is unfaithful.
* **grounded** — whether the answer rests on at least one tool call
  (vs answered from nothing).
* **claim_support** — fraction of the answer's *checkable facts* (numbers,
  IP and MAC addresses) that appear in the concatenated tool results.  An
  unsupported number in the answer is a hallucination.

The metric is deterministic and model-agnostic: it consumes the
structured investigation result, so it runs in CI with the scripted
runtime and produces real numbers against a local llama3 alike.

The **ablation** contrasts a tool-grounded investigation with an
ungrounded one (the model answering with no tools) over the same
questions, showing that grounding raises claim support.
"""

import json
import re
from dataclasses import dataclass
from statistics import mean
from typing import Any, Callable, Dict, List, Optional

# Checkable facts: decimals, IPv4, and MAC addresses.  These are the
# claims a network answer makes that can be verified against tool output.
_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")


def checkable_facts(text: str) -> List[str]:
    """Extract verifiable tokens (MACs, IPs, numbers) from *text*.

    MACs and IPs are matched first and their numeric fragments removed so
    an IP isn't also counted as four bare numbers.
    """
    if not text:
        return []
    facts: List[str] = []
    remaining = text
    for pattern in (_MAC, _IPV4):
        for m in pattern.findall(remaining):
            facts.append(m)
        remaining = pattern.sub(" ", remaining)
    facts.extend(_NUMBER.findall(remaining))
    return facts


def _tool_results_text(tool_calls: List[dict]) -> str:
    """Concatenate every tool result into one searchable blob."""
    parts = []
    for call in tool_calls or []:
        if "result" in call:
            parts.append(json.dumps(call["result"], default=str))
    return " ".join(parts)


@dataclass
class Faithfulness:
    citation_validity: float
    grounded: bool
    claim_support: float
    checkable_facts: int
    unsupported_facts: List[str]


def evaluate_faithfulness(result: Dict[str, Any]) -> Faithfulness:
    """Score one investigation result dict (answer + tool_calls + citations)."""
    tool_calls = result.get("tool_calls") or []
    called_tools = {c.get("tool") for c in tool_calls if c.get("tool")}
    citations = result.get("citations") or []

    if citations:
        valid = sum(1 for c in citations if c in called_tools)
        citation_validity = valid / len(citations)
    else:
        # No citations: valid only if no tools were used either (an answer
        # that needed no data).  Otherwise it used data without crediting it.
        citation_validity = 1.0 if not called_tools else 0.0

    results_text = _tool_results_text(tool_calls)
    facts = checkable_facts(result.get("answer", ""))
    unsupported = [f for f in facts if f not in results_text]
    if facts:
        claim_support = 1.0 - len(unsupported) / len(facts)
    else:
        claim_support = 1.0   # nothing checkable → nothing to contradict

    return Faithfulness(
        citation_validity=round(citation_validity, 4),
        grounded=bool(called_tools),
        claim_support=round(claim_support, 4),
        checkable_facts=len(facts),
        unsupported_facts=unsupported,
    )


@dataclass
class FaithfulnessReport:
    n: int
    mean_citation_validity: float
    grounded_rate: float
    mean_claim_support: float
    per_question: List[Dict[str, Any]]


def evaluate_batch(investigator, questions: List[str]) -> FaithfulnessReport:
    """Run *questions* through *investigator* and aggregate faithfulness."""
    per: List[Dict[str, Any]] = []
    for q in questions:
        result = investigator.investigate(q)
        f = evaluate_faithfulness(result)
        per.append({
            "question": q,
            "answer": result.get("answer", ""),
            "citation_validity": f.citation_validity,
            "grounded": f.grounded,
            "claim_support": f.claim_support,
            "checkable_facts": f.checkable_facts,
            "unsupported_facts": f.unsupported_facts,
        })
    return FaithfulnessReport(
        n=len(per),
        mean_citation_validity=round(mean(p["citation_validity"] for p in per), 4) if per else 0.0,
        grounded_rate=round(mean(1.0 if p["grounded"] else 0.0 for p in per), 4) if per else 0.0,
        mean_claim_support=round(mean(p["claim_support"] for p in per), 4) if per else 0.0,
        per_question=per,
    )


# ---------------------------------------------------------------------------
# Ablation: tool-grounded vs ungrounded
# ---------------------------------------------------------------------------

def ablation(grounded_investigator, ungrounded_answer_fn,
             questions: List[str],
             reference_tool_calls_fn: Optional[Callable[[str], List[dict]]] = None
             ) -> Dict[str, Any]:
    """Compare grounded vs ungrounded answers on the same questions.

    Parameters
    ----------
    grounded_investigator : Investigator
        The real tool-grounded investigator.
    ungrounded_answer_fn : callable(question) -> str
        Produces an answer with NO tools (the model answering blind).
    reference_tool_calls_fn : callable(question) -> tool_calls, optional
        Supplies the tool results to score the ungrounded answer against.
        Defaults to the grounded run's own tool calls, so both answers are
        judged against the same retrieved facts.
    """
    grounded_scores: List[float] = []
    ungrounded_scores: List[float] = []
    rows: List[Dict[str, Any]] = []

    for q in questions:
        g_result = grounded_investigator.investigate(q)
        g_faith = evaluate_faithfulness(g_result)
        grounded_scores.append(g_faith.claim_support)

        u_answer = ungrounded_answer_fn(q)
        ref_calls = (reference_tool_calls_fn(q) if reference_tool_calls_fn
                     else g_result.get("tool_calls"))
        u_result = {"answer": u_answer, "tool_calls": ref_calls, "citations": []}
        u_faith = evaluate_faithfulness(u_result)
        ungrounded_scores.append(u_faith.claim_support)

        rows.append({
            "question": q,
            "grounded_claim_support": g_faith.claim_support,
            "ungrounded_claim_support": u_faith.claim_support,
            "grounded_answer": g_result.get("answer", ""),
            "ungrounded_answer": u_answer,
        })

    g_mean = round(mean(grounded_scores), 4) if grounded_scores else 0.0
    u_mean = round(mean(ungrounded_scores), 4) if ungrounded_scores else 0.0
    return {
        "n": len(questions),
        "grounded_mean_claim_support": g_mean,
        "ungrounded_mean_claim_support": u_mean,
        "delta": round(g_mean - u_mean, 4),
        "per_question": rows,
    }
