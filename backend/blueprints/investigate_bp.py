"""
investigate_bp.py - Ask NetWatch Endpoints (Phase 3, AI-first)
===============================================================

* ``GET  /api/investigate/tools`` — the grounding tools the model may use
* ``GET  /api/investigate/status`` — whether a local LLM backend is ready
* ``POST /api/investigate`` — ``{"question": "..."}`` → grounded answer
  with citations and the full tool-call trace

Fully local: the investigator only ever talks to a local Ollama server.
When no model is reachable the endpoints return ``available: false`` with
a reason instead of failing — same graceful-degradation contract as
forecasting.
"""

import logging

from flask import Blueprint, request

from backend.helpers import handle_errors, success_detail, error_response
from intelligence.investigator_tools import tool_schema

logger = logging.getLogger(__name__)

investigate_bp = Blueprint('investigate', __name__)

_UNAVAILABLE = {
    "available": False,
    "reason": "No local LLM runtime is reachable. Install Ollama and pull a "
              "model (e.g. `ollama pull llama3`) to enable Ask NetWatch.",
}


def _build_investigator():
    from config import LLM_MODEL, LLM_MAX_STEPS
    from intelligence.investigator import build_investigator
    return build_investigator(model=LLM_MODEL, max_steps=LLM_MAX_STEPS)


@investigate_bp.route('/api/investigate/tools', methods=['GET'])
@handle_errors
def get_tools():
    """List the read-only grounding tools available to the investigator."""
    return success_detail({"tools": tool_schema()})


@investigate_bp.route('/api/investigate/status', methods=['GET'])
@handle_errors
def get_status():
    """Report whether a local LLM backend is currently reachable."""
    available = _build_investigator() is not None
    return success_detail({
        "available": available,
        "tools": [t["name"] for t in tool_schema()],
    })


@investigate_bp.route('/api/investigate', methods=['POST'])
@handle_errors
def investigate():
    """Answer a natural-language question, grounded in the tools."""
    body = request.get_json(silent=True) or {}
    question = (body.get("question") or "").strip()
    if not question:
        return error_response("question is required", code="NO_QUESTION",
                              status=400)
    if len(question) > 1000:
        return error_response("question too long (max 1000 chars)",
                              code="QUESTION_TOO_LONG", status=400)

    investigator = _build_investigator()
    if investigator is None:
        return success_detail({**_UNAVAILABLE, "question": question})

    result = investigator.investigate(question)
    return success_detail(result)
