"""
test_briefing.py - "What just happened?" must never invent anything
====================================================================

The briefing's whole value is that it can be believed. The facts are gathered
deterministically and the model is only asked to narrate them, so these tests
check the seam: that a missing subsystem degrades instead of erroring, that a
useless or refusing model is discarded rather than shown, and that the
computed narrative — the floor we can always stand behind — reads correctly.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.briefing import (
    Briefer, _clean, _is_usable, compose_fallback,
)


def _facts(devices=None, alerts=None, mbps=1.5, active=2):
    return {
        "window_minutes": 10,
        "devices": devices if devices is not None else [
            {"device": "Nothing-Phone-2a-Plus", "lookups": 41,
             "top_apps": ["Instagram", "Meta"]},
            {"device": "moto-g34-5G", "lookups": 6, "top_apps": ["Google"]},
        ],
        "top_apps": [{"app": "Instagram", "lookups": 30}],
        "alerts": alerts if alerts is not None else [],
        "metrics": {"active_devices": active, "bandwidth_mbps": mbps},
    }


class TestComposedNarrative:
    def test_names_devices_and_their_apps(self):
        text = compose_fallback(_facts())
        assert "Nothing-Phone-2a-Plus" in text
        assert "Instagram" in text
        assert "2 devices were active" in text

    def test_quiet_network_is_stated_plainly(self):
        text = compose_fallback(_facts(devices=[], active=0, mbps=0.0))
        assert "No client activity" in text
        assert "No alerts fired." in text

    def test_alert_is_described_by_kind_not_a_missing_title(self):
        """The alerts table has no `title` column — an earlier version of this
        printed a literal "None" into the briefing."""
        text = compose_fallback(_facts(alerts=[{
            "severity": "critical", "type": "dns_tunneling",
            "message": "63 queries to fbcdn.net", "timestamp": "now",
        }]))
        assert "None" not in text
        assert "dns_tunneling" in text
        assert "critical" in text

    def test_units_are_stated_and_not_converted(self):
        text = compose_fallback(_facts(mbps=12.34))
        assert "12.34 Mbps" in text


class TestModelGuards:
    def test_refusal_is_rejected(self):
        assert _is_usable("I cannot help with that request, as an AI.") is False

    def test_truncated_output_is_rejected(self):
        assert _is_usable("The network") is False

    def test_reasonable_prose_is_accepted(self):
        assert _is_usable(
            "Two devices were active in the last ten minutes, mostly using "
            "Instagram. No alerts fired and throughput was low."
        ) is True

    def test_scaffolding_is_stripped(self):
        assert _clean("```\nBriefing: All quiet.\n```") == "All quiet."
        assert _clean("Here is the briefing: All quiet.").startswith("Here is") is False


class _Runtime:
    def __init__(self, text):
        self._text = text
        self.calls = []

    def generate(self, messages):
        self.calls.append(messages)
        return self._text


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class TestBriefer:
    def test_model_narrative_is_used_when_usable(self, monkeypatch):
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())
        b = Briefer(_Runtime("Two phones were busy on Instagram for the last "
                             "ten minutes. Nothing alarming happened at all."))
        out = b.brief()
        assert out["source"] == "model"
        assert "Instagram" in out["narrative"]

    def test_unusable_model_falls_back_to_computed(self, monkeypatch):
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())
        out = Briefer(_Runtime("I cannot do that.")).brief()
        assert out["source"] == "facts"
        assert "Nothing-Phone-2a-Plus" in out["narrative"]

    def test_exploding_model_falls_back(self, monkeypatch):
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())

        class Boom:
            def generate(self, messages):
                raise RuntimeError("ollama gone")
        out = Briefer(Boom()).brief()
        assert out["source"] == "facts"

    def test_no_runtime_still_briefs(self, monkeypatch):
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())
        out = Briefer(None).brief()
        assert out["source"] == "facts"
        assert out["narrative"]

    def test_facts_travel_with_the_narrative(self, monkeypatch):
        """So any claim in the prose can be checked against its source."""
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())
        out = Briefer(None).brief()
        assert out["facts"]["devices"][0]["device"] == "Nothing-Phone-2a-Plus"

    def test_cache_avoids_re_running_the_model(self, monkeypatch):
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())
        rt = _Runtime("Two phones were busy on Instagram for ten minutes "
                      "and nothing alarming happened.")
        clock = _Clock()
        b = Briefer(rt, cache_seconds=60, clock=clock)
        b.brief()
        b.brief()
        assert len(rt.calls) == 1
        clock.t = 61
        b.brief()
        assert len(rt.calls) == 2

    def test_force_bypasses_cache(self, monkeypatch):
        import intelligence.briefing as m
        monkeypatch.setattr(m, "gather_facts", lambda w: _facts())
        rt = _Runtime("Two phones were busy on Instagram for ten minutes "
                      "and nothing alarming happened.")
        b = Briefer(rt, cache_seconds=60, clock=_Clock())
        b.brief()
        b.brief(force=True)
        assert len(rt.calls) == 2


class TestFactGathering:
    def test_missing_subsystems_degrade_rather_than_raise(self, monkeypatch):
        """A briefing must still work when the DB or twin is unavailable."""
        from intelligence.briefing import gather_facts
        facts = gather_facts(window_minutes=5)
        assert facts["window_minutes"] == 5
        for key in ("devices", "top_apps", "alerts", "metrics"):
            assert key in facts
