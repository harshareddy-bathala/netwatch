"""
briefing_bp.py - "What just happened?" endpoint
================================================

* ``GET /api/briefing`` — a short plain-English account of the last N minutes

``?minutes=N`` (default 10, capped) selects the window; ``?force=1`` bypasses
the short cache. The response says whether the narrative was written by the
local model or computed from the facts, because those deserve different
trust — and the raw facts travel with it so the claim can be checked.
"""

import logging

from flask import Blueprint, request

from backend.helpers import handle_errors, success_detail

logger = logging.getLogger(__name__)

briefing_bp = Blueprint('briefing', __name__)

MAX_WINDOW_MINUTES = 120

# One Briefer per process: it holds the short cache, and rebuilding it per
# request would also re-probe the Ollama socket on every click.
_briefer = None


def _get_briefer():
    global _briefer
    if _briefer is None:
        from intelligence.briefing import build_briefer
        _briefer = build_briefer()
    return _briefer


@briefing_bp.route('/api/briefing', methods=['GET'])
@handle_errors
def get_briefing():
    try:
        minutes = int(request.args.get('minutes', 10))
    except (TypeError, ValueError):
        minutes = 10
    minutes = max(1, min(MAX_WINDOW_MINUTES, minutes))
    force = request.args.get('force') in ('1', 'true', 'yes')

    return success_detail(_get_briefer().brief(window_minutes=minutes,
                                               force=force))
