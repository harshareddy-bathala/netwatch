"""
test_evaluation.py - Evaluation Harness Tests (Phase 4)
========================================================

Covers the labeled dataset, the detector precision/recall harness, and
the citation-faithfulness metric + ablation — all deterministic and
model-free.
"""

import sys
import os
import json

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation import threat_dataset as ds
from evaluation import detector_eval as de
from evaluation import faithfulness as fa


# ===================================================================
# Dataset
# ===================================================================

class TestDataset:

    def test_builds_scenarios(self):
        data = ds.build_dataset()
        assert len(data) >= 15
        labels = {s.label for s in data}
        assert set(ds.THREAT_LABELS).issubset(labels)
        assert ds.BENIGN in labels

    def test_reproducible(self):
        a = ds.build_dataset()
        b = ds.build_dataset()
        assert [s.id for s in a] == [s.id for s in b]
        # DNS-tunnel labels use a seeded RNG — identical across builds.
        assert [s.events for s in a] == [s.events for s in b]

    def test_every_scenario_well_formed(self):
        for s in ds.build_dataset():
            assert s.id and s.label and s.events
            for e in s.events:
                assert e["kind"] in ("flow", "dns")
                assert e["source_mac"]

    def test_has_benign_near_misses(self):
        benign = [s for s in ds.build_dataset() if s.label == ds.BENIGN]
        assert len(benign) >= 5
        ids = {s.id for s in benign}
        assert "benign-fileshare" in ids   # below lateral threshold
        assert "benign-ptr-burst" in ids   # .arpa long qnames

    def test_export_json(self, tmp_path):
        path = str(tmp_path / "dataset.json")
        ds.export_json(path)
        with open(path) as fh:
            data = json.load(fh)
        assert data["version"] == "1.0"
        assert len(data["scenarios"]) == len(ds.build_dataset())

    def test_stats(self):
        stats = ds.dataset_stats()
        assert stats["port_scan"] >= 2
        assert stats[ds.BENIGN] >= 5


# ===================================================================
# Detector evaluation
# ===================================================================

class TestDetectorEval:

    def test_attacks_detected(self):
        report = de.evaluate()
        for t in ds.THREAT_LABELS:
            m = report.per_detector[t]
            assert m.recall == 1.0, f"{t} recall {m.recall}"

    def test_benign_no_false_positives(self):
        report = de.evaluate()
        assert report.benign_false_positive_rate == 0.0

    def test_high_macro_f1(self):
        report = de.evaluate()
        assert report.macro_f1 >= 0.9
        assert report.accuracy == 1.0

    def test_report_to_dict_shape(self):
        payload = de.report_to_dict(de.evaluate())
        assert "per_detector" in payload
        assert "overall" in payload
        assert payload["overall"]["macro_f1"] >= 0.9
        for t in ds.THREAT_LABELS:
            assert set(payload["per_detector"][t]) == {
                "precision", "recall", "f1", "tp", "fp", "fn"}

    def test_format_table(self):
        table = de.format_table(de.evaluate())
        assert "precision" in table
        assert "macro-F1" in table

    def test_benign_scenarios_stay_silent(self):
        for s in ds.build_dataset():
            if s.label == ds.BENIGN:
                fired = de.run_scenario(s)
                assert fired == set(), f"{s.id} fired {fired}"


# ===================================================================
# Citation faithfulness
# ===================================================================

def _call(tool, result):
    return {"step": 0, "tool": tool, "params": {}, "result": result}


class TestCheckableFacts:

    def test_extracts_ip_mac_numbers(self):
        facts = fa.checkable_facts("Device aa:bb:cc:dd:ee:ff at 10.0.0.5 sent 42 MB")
        assert "aa:bb:cc:dd:ee:ff" in facts
        assert "10.0.0.5" in facts
        assert "42" in facts

    def test_ip_not_double_counted_as_numbers(self):
        facts = fa.checkable_facts("host 10.0.0.5")
        # The IP is one fact, not four bare numbers.
        assert facts == ["10.0.0.5"]

    def test_empty(self):
        assert fa.checkable_facts("") == []


class TestFaithfulness:

    def test_grounded_supported_answer(self):
        result = {
            "answer": "Bandwidth is 12.5 Mbps across 3 devices.",
            "citations": ["query_metrics"],
            "tool_calls": [_call("query_metrics",
                                 {"bandwidth_mbps": 12.5, "active_devices": 3})],
        }
        f = fa.evaluate_faithfulness(result)
        assert f.grounded is True
        assert f.citation_validity == 1.0
        assert f.claim_support == 1.0
        assert f.unsupported_facts == []

    def test_hallucinated_number_flagged(self):
        result = {
            "answer": "Bandwidth is 999 Mbps.",   # tool said 12.5
            "citations": ["query_metrics"],
            "tool_calls": [_call("query_metrics", {"bandwidth_mbps": 12.5})],
        }
        f = fa.evaluate_faithfulness(result)
        assert "999" in f.unsupported_facts
        assert f.claim_support < 1.0

    def test_citation_to_uncalled_tool_is_invalid(self):
        result = {
            "answer": "All quiet.",
            "citations": ["query_graph"],       # never called
            "tool_calls": [_call("query_metrics", {"x": 1})],
        }
        f = fa.evaluate_faithfulness(result)
        assert f.citation_validity == 0.0

    def test_ungrounded_answer_not_grounded(self):
        result = {"answer": "Probably fine.", "citations": [], "tool_calls": []}
        f = fa.evaluate_faithfulness(result)
        assert f.grounded is False
        # No citations and no tools → vacuously valid, but not grounded.
        assert f.citation_validity == 1.0

    def test_no_checkable_facts_full_support(self):
        result = {"answer": "The network looks healthy.", "citations": [],
                  "tool_calls": []}
        f = fa.evaluate_faithfulness(result)
        assert f.checkable_facts == 0
        assert f.claim_support == 1.0


class TestBatchAndAblation:

    def _investigator(self):
        from intelligence.investigator import Investigator
        from intelligence.llm_runtime import ScriptedRuntime
        # Model calls query_metrics, then answers with a supported number.
        runtime = ScriptedRuntime([
            json.dumps({"action": "tool", "tool": "query_metrics", "params": {}}),
            json.dumps({"action": "answer",
                        "answer": "Traffic is nominal.",
                        "citations": ["query_metrics"]}),
        ])
        return Investigator(runtime)

    def test_evaluate_batch(self, initialized_db):
        report = fa.evaluate_batch(self._investigator(), ["How is the network?"])
        assert report.n == 1
        assert report.grounded_rate == 1.0
        assert report.mean_citation_validity == 1.0

    def test_ablation_prefers_grounded(self, initialized_db):
        from intelligence.investigator import Investigator
        from intelligence.llm_runtime import ScriptedRuntime

        # Grounded run: calls a tool that returns a specific device count,
        # then cites a supported number.
        def grounded_factory():
            rt = ScriptedRuntime([
                json.dumps({"action": "tool", "tool": "query_metrics",
                            "params": {}}),
                json.dumps({"action": "answer",
                            "answer": "There are 7 active devices.",
                            "citations": ["query_metrics"]}),
            ])
            return Investigator(rt)

        # We need the tool result to actually contain "7" for the grounded
        # answer to score 1.0; monkeypatch query_metrics for determinism.
        import evaluation.faithfulness as _fa  # noqa: F401
        grounded = grounded_factory()

        # Ungrounded answer invents a different number with no data.
        def ungrounded(_q):
            return "There are 512 active devices."

        # Reference tool calls: what the grounded run retrieved.
        ref = [_call("query_metrics", {"active_devices": 7})]
        out = fa.ablation(grounded, ungrounded, ["How many devices?"],
                          reference_tool_calls_fn=lambda q: ref)
        assert out["ungrounded_mean_claim_support"] < 1.0  # 512 unsupported
        assert out["delta"] >= 0.0
        # Micro-averaged: the ungrounded run hallucinated its only fact.
        assert out["ungrounded_facts"]["hallucination_rate"] == 1.0
        assert out["grounded_facts"]["hallucination_rate"] == 0.0


class TestFactCoverage:
    """mean_claim_support is 1.0 for answers with nothing checkable, so the
    report must expose how much it actually measured."""

    def _inv(self, answer):
        from intelligence.investigator import Investigator
        from intelligence.llm_runtime import ScriptedRuntime
        return Investigator(ScriptedRuntime([
            json.dumps({"action": "tool", "tool": "query_metrics",
                        "params": {}}),
            json.dumps({"action": "answer", "answer": answer,
                        "citations": ["query_metrics"]}),
        ]))

    def test_factless_answer_flagged_as_uncovered(self, initialized_db):
        # A fact-free answer scores claim_support 1.0 by default — the
        # coverage fields must make that visible rather than let it pass
        # as a perfect score.
        report = fa.evaluate_batch(self._inv("The network looks fine."),
                                   ["How is it?"])
        assert report.mean_claim_support == 1.0
        assert report.answers_with_facts == 0
        assert report.total_facts == 0
        assert report.hallucination_rate is None   # nothing measured

    def test_fact_bearing_answer_counted(self, initialized_db):
        report = fa.evaluate_batch(self._inv("There are 99999 devices."),
                                   ["How many?"])
        assert report.answers_with_facts == 1
        assert report.total_facts == 1
        assert report.unsupported_facts == 1       # 99999 not in tool result
        assert report.hallucination_rate == 1.0


class TestFailedInvestigationsExcluded:
    """A run that never completed has an empty answer, hence no checkable
    facts, hence a free claim_support of 1.0. Scoring it would let a
    degraded run report as perfect — it must be excluded and surfaced."""

    class _DeadInvestigator:
        def investigate(self, question):
            return {"available": False, "question": question,
                    "reason": "Ollama request failed: timed out",
                    "answer": "", "citations": [], "tool_calls": [],
                    "steps": 0}

    def test_failed_runs_are_not_scored(self, initialized_db):
        report = fa.evaluate_batch(self._DeadInvestigator(), ["q1", "q2"])
        assert report.n == 0                 # nothing scored
        assert len(report.failed) == 2
        assert "timed out" in report.failed[0]["reason"]
        # The bug this guards: mean_claim_support must NOT be a proud 1.0.
        assert report.mean_claim_support == 0.0

    def test_mixed_batch_scores_only_successes(self, initialized_db):
        from intelligence.investigator import Investigator
        from intelligence.llm_runtime import ScriptedRuntime

        class _Flaky:
            def __init__(self):
                self._n = 0
                self._real = Investigator(ScriptedRuntime([
                    json.dumps({"action": "tool", "tool": "query_metrics",
                                "params": {}}),
                    json.dumps({"action": "answer", "answer": "All good.",
                                "citations": ["query_metrics"]}),
                ]))

            def investigate(self, question):
                self._n += 1
                if self._n == 1:
                    return {"available": False, "question": question,
                            "reason": "timed out", "answer": "",
                            "citations": [], "tool_calls": [], "steps": 0}
                return self._real.investigate(question)

        report = fa.evaluate_batch(_Flaky(), ["dies", "works"])
        assert report.n == 1
        assert len(report.failed) == 1
        assert report.per_question[0]["question"] == "works"

    def test_ablation_skips_failed_grounded_runs(self, initialized_db):
        out = fa.ablation(self._DeadInvestigator(), lambda q: "42 devices.",
                          ["q1"])
        assert out["n"] == 0
        assert len(out["failed"]) == 1
        assert out["questions_asked"] == 1


class TestNetworkSeed:
    """The seeded network is what makes claim_support measurable — an idle
    DB yields answers with no checkable facts in them."""

    def test_seed_is_deterministic(self, initialized_db):
        from evaluation import network_seed as ns
        ns.clear_seed()
        a = ns.seed_network(minutes=5)
        ns.clear_seed()
        b = ns.seed_network(minutes=5)
        assert a["devices"] == b["devices"]
        assert a["traffic_rows"] == b["traffic_rows"]
        assert a["device_ips"] == b["device_ips"]

    def test_seed_populates_metrics(self, initialized_db):
        from evaluation import network_seed as ns
        from intelligence.investigator_tools import run_tool
        ns.clear_seed()
        info = ns.seed_network(minutes=10)
        metrics = run_tool("query_metrics", {})
        # The whole point: the tool now returns facts to be checked.
        assert metrics["current"]["active_devices"] == info["devices"]
        assert metrics["current"]["bandwidth_mbps"] > 0
        assert metrics["top_protocols"]

    def test_seeded_answer_has_checkable_facts(self, initialized_db):
        # An idle DB produced 2 facts across 5 questions; a seeded one must
        # give the metric something to verify.
        from evaluation import network_seed as ns
        from intelligence.investigator_tools import run_tool
        ns.clear_seed()
        ns.seed_network(minutes=10)
        blob = json.dumps(run_tool("query_metrics", {}), default=str)
        assert len(fa.checkable_facts(blob)) > 5

    def test_clear_seed_removes_only_its_own_rows(self, initialized_db):
        from evaluation import network_seed as ns
        from database.connection import get_connection
        ns.clear_seed()
        with get_connection() as c:
            cur = c.cursor()
            cur.execute("INSERT INTO traffic_summary (timestamp, source_ip, "
                        "dest_ip, protocol, bytes_transferred, session_id) "
                        "VALUES (datetime('now'), '10.0.0.1', '10.0.0.2', "
                        "'TCP', 100, 'NOT-EVAL')")
            c.commit()
        ns.seed_network(minutes=3)
        ns.clear_seed()
        with get_connection() as c:
            cur = c.cursor()
            cur.execute("SELECT COUNT(*) AS n FROM traffic_summary "
                        "WHERE session_id = 'NOT-EVAL'")
            assert cur.fetchone()["n"] == 1        # untouched
            cur.execute("SELECT COUNT(*) AS n FROM traffic_summary "
                        "WHERE session_id = ?", (ns.SESSION_TAG,))
            assert cur.fetchone()["n"] == 0        # all seed rows gone
