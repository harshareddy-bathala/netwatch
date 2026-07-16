"""
test_investigator.py - Tool-Grounded LLM Investigator (Phase 3)
================================================================

Exercises the grounding tools and the full tool-calling loop with a
deterministic ScriptedRuntime — no model, no Ollama, no network.
"""

import sys
import os
import json

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence import investigator_tools as tools
from intelligence.investigator import Investigator
from intelligence.llm_runtime import ScriptedRuntime, OllamaRuntime, get_runtime


# ===================================================================
# Grounding tools
# ===================================================================

class TestTools:

    def test_registry_shape(self):
        schema = tools.tool_schema()
        names = {t["name"] for t in schema}
        assert names == {"query_metrics", "query_graph", "list_incidents"}
        for t in schema:
            assert t["description"]

    def test_run_unknown_tool_raises(self):
        with pytest.raises(KeyError):
            tools.run_tool("no_such_tool", {})

    def test_query_metrics_shape(self, initialized_db):
        result = tools.query_metrics({})
        assert "provenance" in result
        assert result["provenance"]["source"] == "stats_queries"
        assert "current" in result
        assert "top_protocols" in result

    def test_query_graph_twin_off(self, initialized_db):
        # No twin running → graceful unavailable, not an exception.
        result = tools.query_graph({})
        assert result["available"] is False
        assert result["nodes"] == []

    def test_list_incidents_empty(self, initialized_db):
        result = tools.list_incidents({})
        assert result["available"] is True
        assert result["incidents"] == []
        assert result["count"] == 0

    def test_list_incidents_returns_seeded(self, initialized_db):
        from database.queries import incident_queries
        iid = incident_queries.create_incident(
            title="Port scan on aa:bb", severity="critical",
            device_mac="aa:bb:cc:00:00:01", categories=["security"])
        assert iid is not None
        result = tools.list_incidents({"status": "open"})
        assert result["count"] == 1
        assert result["incidents"][0]["title"] == "Port scan on aa:bb"

    def test_list_incidents_detail(self, initialized_db):
        from database.queries import incident_queries
        iid = incident_queries.create_incident(
            title="X", severity="warning", categories=["anomaly"])
        result = tools.list_incidents({"incident_id": iid})
        assert result["available"] is True
        assert result["incident"]["id"] == iid

    def test_list_incidents_detail_missing(self, initialized_db):
        result = tools.list_incidents({"incident_id": 99999})
        assert result["available"] is False


# ===================================================================
# Investigation loop (ScriptedRuntime — deterministic, no model)
# ===================================================================

def _tool(name, params=None):
    return json.dumps({"action": "tool", "tool": name, "params": params or {}})


def _answer(text, citations=None):
    return json.dumps({"action": "answer", "answer": text,
                       "citations": citations or []})


class TestInvestigationLoop:

    def test_single_tool_then_answer(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            _answer("Bandwidth is low.", ["query_metrics"]),
        ])
        inv = Investigator(runtime)
        result = inv.investigate("How's the network?")
        assert result["available"] is True
        assert result["answer"] == "Bandwidth is low."
        assert result["citations"] == ["query_metrics"]
        assert result["steps"] == 2
        assert result["tool_calls"][0]["tool"] == "query_metrics"
        assert "result" in result["tool_calls"][0]

    def test_multi_step(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("list_incidents", {"status": "open"}),
            _tool("query_metrics"),
            _answer("No open incidents; traffic nominal.",
                    ["list_incidents", "query_metrics"]),
        ])
        result = Investigator(runtime).investigate("Anything wrong?")
        assert len(result["tool_calls"]) == 2
        assert set(result["citations"]) == {"list_incidents", "query_metrics"}

    def test_ungrounded_answer_is_nudged_then_accepted(self, initialized_db):
        # Answering with no data gets pushed back once; a model that
        # insists still gets through, with the rejection visible in the
        # trace. (Real llama3 behaviour: it answers at step 0 otherwise.)
        runtime = ScriptedRuntime([
            _answer("42 devices.", []),
            _answer("42 devices.", []),
        ])
        result = Investigator(runtime).investigate("Count?")
        assert result["answer"] == "42 devices."
        assert result["steps"] == 2
        assert any(t.get("error") == "ungrounded_answer_rejected"
                   for t in result["tool_calls"])

    def test_nudge_makes_model_call_a_tool(self, initialized_db):
        # The pushback's purpose: the model retries with a real tool call.
        runtime = ScriptedRuntime([
            _answer("Everything is fine.", ["query_metrics"]),
            _tool("query_metrics"),
            _answer("Bandwidth is low.", ["query_metrics"]),
        ])
        result = Investigator(runtime).investigate("How's the network?")
        assert result["answer"] == "Bandwidth is low."
        assert [t.get("tool") for t in result["tool_calls"]
                if t.get("tool")] == ["query_metrics"]

    def test_grounded_answer_is_not_nudged(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            _answer("All good.", ["query_metrics"]),
        ])
        result = Investigator(runtime).investigate("q")
        assert result["steps"] == 2
        assert not any(t.get("error") == "ungrounded_answer_rejected"
                       for t in result["tool_calls"])

    def test_unknown_tool_fed_back(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("bogus_tool"),
            _answer("Recovered.", []),
        ])
        result = Investigator(runtime).investigate("q")
        # The bad call is recorded with an error, then the model recovers.
        assert result["tool_calls"][0]["result"]["error"].startswith("unknown tool")
        assert result["answer"] == "Recovered."

    def test_unparseable_then_retry(self, initialized_db):
        runtime = ScriptedRuntime([
            "I think the network is fine, no JSON here",
            _tool("query_metrics"),
            _answer("Fine.", ["query_metrics"]),
        ])
        result = Investigator(runtime).investigate("q")
        assert result["answer"] == "Fine."
        assert any(t.get("error") == "unparseable" for t in result["tool_calls"])

    def test_json_in_prose_is_extracted(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            'Sure! ```json\n{"action":"answer","answer":"hi","citations":[]}\n```',
        ])
        result = Investigator(runtime).investigate("q")
        assert result["answer"] == "hi"

    def test_invalid_citations_dropped(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            _answer("x", ["query_metrics", "made_up_source", 123]),
        ])
        result = Investigator(runtime).investigate("q")
        # Only real tool names survive — an answer can't cite a phantom source.
        assert result["citations"] == ["query_metrics"]

    def test_max_steps_truncation(self, initialized_db):
        # Model loops forever calling tools, never answers.
        runtime = ScriptedRuntime([_tool("query_metrics")] * 20)
        result = Investigator(runtime, max_steps=3).investigate("q")
        assert result["truncated"] is True
        assert result["steps"] == 3
        assert len(result["tool_calls"]) == 3

    def test_bool_answer_coerced_to_string(self, initialized_db):
        # Real llama3 behaviour: a yes/no question can come back as a JSON
        # boolean in the answer field. Downstream (API, frontend, metric)
        # requires a string.
        runtime = ScriptedRuntime([
            _tool("list_incidents"),
            '{"action":"answer","answer":true,"citations":[]}',
        ])
        result = Investigator(runtime).investigate("Any incidents?")
        assert result["answer"] == "yes"
        assert isinstance(result["answer"], str)

    def test_numeric_answer_coerced_to_string(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            '{"action":"answer","answer":42,"citations":[]}',
        ])
        result = Investigator(runtime).investigate("How many devices?")
        assert result["answer"] == "42"

    def test_object_answer_serialised(self, initialized_db):
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            '{"action":"answer","answer":{"devices":3},"citations":[]}',
        ])
        result = Investigator(runtime).investigate("q")
        assert isinstance(result["answer"], str)
        assert "devices" in result["answer"]

    def test_tool_exception_does_not_crash(self, initialized_db, monkeypatch):
        def boom(params):
            raise RuntimeError("kaboom")
        monkeypatch.setitem(tools.TOOLS, "query_metrics",
                            {"fn": boom, "description": "x"})
        runtime = ScriptedRuntime([
            _tool("query_metrics"),
            _answer("handled", []),
        ])
        result = Investigator(runtime).investigate("q")
        assert result["tool_calls"][0]["result"]["error"] == "kaboom"
        assert result["answer"] == "handled"


# ===================================================================
# Runtime backends
# ===================================================================

class TestRuntimes:

    def test_scripted_runs_out_gracefully(self):
        rt = ScriptedRuntime([])
        out = rt.generate([{"role": "user", "content": "hi"}])
        parsed = json.loads(out)
        assert parsed["action"] == "answer"

    def test_ollama_unavailable_returns_none(self, monkeypatch):
        # Force is_available False → get_runtime returns None (degraded).
        monkeypatch.setattr(OllamaRuntime, "is_available", lambda self: False)
        assert get_runtime() is None

    def test_ollama_available_returns_runtime(self, monkeypatch):
        monkeypatch.setattr(OllamaRuntime, "is_available", lambda self: True)
        rt = get_runtime()
        assert isinstance(rt, OllamaRuntime)


# ===================================================================
# API endpoints (/api/investigate*)
# ===================================================================

class TestInvestigateAPI:

    def test_tools_endpoint(self, client):
        resp = client.get('/api/investigate/tools')
        assert resp.status_code == 200
        names = {t["name"] for t in resp.get_json()["data"]["tools"]}
        assert names == {"query_metrics", "query_graph", "list_incidents"}

    def test_status_reports_unavailable_without_model(self, client, monkeypatch):
        # No local Ollama in CI → status available:false, still 200.
        monkeypatch.setattr(OllamaRuntime, "is_available", lambda self: False)
        resp = client.get('/api/investigate/status')
        assert resp.status_code == 200
        assert resp.get_json()["data"]["available"] is False

    def test_investigate_requires_question(self, client):
        resp = client.post('/api/investigate', json={})
        assert resp.status_code == 400

    def test_investigate_too_long(self, client):
        resp = client.post('/api/investigate', json={"question": "x" * 1001})
        assert resp.status_code == 400

    def test_investigate_degrades_without_model(self, client, monkeypatch):
        monkeypatch.setattr(OllamaRuntime, "is_available", lambda self: False)
        resp = client.post('/api/investigate', json={"question": "How's the network?"})
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["available"] is False
        assert "Ollama" in data["reason"]

    def test_investigate_with_scripted_runtime(self, client, monkeypatch):
        # Inject a scripted runtime so the endpoint runs the real loop end
        # to end without a model.
        from intelligence.investigator import Investigator

        def fake_build(model=None, max_steps=5):
            return Investigator(ScriptedRuntime([
                _tool("query_metrics"),
                _answer("The network looks healthy.", ["query_metrics"]),
            ]), max_steps=max_steps)

        monkeypatch.setattr(
            "backend.blueprints.investigate_bp.build_investigator",
            fake_build, raising=False)
        # investigate_bp imports build_investigator lazily inside the helper,
        # so patch the source module too.
        monkeypatch.setattr(
            "intelligence.investigator.build_investigator", fake_build,
            raising=False)

        resp = client.post('/api/investigate',
                           json={"question": "How's the network?"})
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data["available"] is True
        assert data["answer"] == "The network looks healthy."
        assert data["citations"] == ["query_metrics"]


class TestRuntimeFailureMidLoop:
    """The investigator must degrade, not 500, when the backend dies or the
    model isn't pulled during a call."""

    def test_llm_unavailable_mid_investigation(self, initialized_db):
        from intelligence.investigator import Investigator
        from intelligence.llm_runtime import LLMUnavailable

        class DyingRuntime:
            def is_available(self): return True
            def generate(self, messages):
                raise LLMUnavailable("model not found (404)")

        result = Investigator(DyingRuntime()).investigate("How's the network?")
        assert result["available"] is False
        assert "unavailable" in result["reason"].lower()
        assert result["answer"] == ""

    def test_backend_dies_after_a_tool_call(self, initialized_db):
        from intelligence.investigator import Investigator
        from intelligence.llm_runtime import LLMUnavailable

        class FlakyRuntime:
            def __init__(self):
                self.n = 0
            def is_available(self): return True
            def generate(self, messages):
                self.n += 1
                if self.n == 1:
                    return json.dumps({"action": "tool",
                                       "tool": "query_metrics", "params": {}})
                raise LLMUnavailable("connection reset")

        result = Investigator(FlakyRuntime()).investigate("q")
        assert result["available"] is False
        # The tool result gathered before the failure is preserved.
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["tool"] == "query_metrics"
