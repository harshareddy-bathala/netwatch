"""
test_responder.py - AI incident responder: propose, validate, never overreach
==============================================================================

The responder is the one component allowed to *suggest* cutting a device off,
so its failure modes matter more than its successes. These tests pin the three
guarantees that make it safe to run in front of an audience:

1. It works with no model at all (the deterministic path is the floor).
2. A model cannot cite evidence the network never produced.
3. A model cannot talk us out of containing a corroborated attack.

Guarantee 3 is not hypothetical. Measured against this project's own evidence,
llama3.2:3b called a benign Meta-CDN DNS burst "tunneling, quarantine" and —
once given domain context — called a corroborated port scan plus lateral
movement "a legitimate port scan, likely from an authorized device". The model
earns its place by explaining; it does not get the trigger.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.llm_runtime import ScriptedRuntime
from intelligence.responder import (
    VALID_ACTIONS, Responder, gather_evidence, validate_verdict, _rule_verdict,
)


def _dns_fp_incident():
    """The real false positive from the field logs: fbcdn.net."""
    return {
        "id": 3, "severity": "critical", "status": "open",
        "device_mac": "22:5e:3e:1a:d0:f3",
        "alerts": [{
            "message": "Possible DNS tunneling: 63 queries to 'fbcdn.net'.",
            "details": {
                "threat_type": "dns_tunneling", "confidence": 0.91,
                "evidence": [{"signal": "qname_stuffing", "domain": "fbcdn.net",
                              "queries_in_window": 63,
                              "avg_qname_length": 33.0}],
            },
        }],
    }


def _scan_incident():
    return {
        "id": 7, "severity": "critical", "status": "open",
        "device_mac": "de:ad:00:00:06:01",
        "alerts": [
            {"message": "Port scan: 24 ports in 60s.",
             "details": {"threat_type": "port_scan", "confidence": 0.93,
                         "evidence": [{"signal": "vertical_scan",
                                       "ports_touched": 24}]}},
            {"message": "Lateral movement to 3 hosts on 445.",
             "details": {"threat_type": "lateral_movement", "confidence": 0.88,
                         "evidence": [{"signal": "admin_port_fanout",
                                       "hosts": 3}]}},
        ],
    }


class TestEvidence:
    def test_signals_and_domains_extracted(self):
        ev = gather_evidence(_dns_fp_incident())
        assert ev["signals"] == ["qname_stuffing"]
        assert ev["domains"] == ["fbcdn.net"]
        assert ev["threat_types"] == ["dns_tunneling"]
        assert ev["max_detector_confidence"] == 0.91

    def test_details_may_arrive_as_json_text(self):
        """SQLite hands `details` back as a string."""
        import json
        inc = _dns_fp_incident()
        inc["alerts"][0]["details"] = json.dumps(inc["alerts"][0]["details"])
        assert gather_evidence(inc)["signals"] == ["qname_stuffing"]

    def test_empty_incident_is_survivable(self):
        ev = gather_evidence({"id": 1, "alerts": []})
        assert ev["signals"] == [] and ev["alert_count"] == 0


class TestRulesOnly:
    """No model installed — the demo must still work."""

    def test_cdn_dns_burst_is_dismissed(self):
        v = Responder(runtime=None).assess(_dns_fp_incident())
        assert v["recommended_action"] == "dismiss_benign"
        assert v["source"] == "rules"
        assert "fbcdn.net" in v["assessment"]

    def test_corroborated_scan_is_quarantined(self):
        v = Responder(runtime=None).assess(_scan_incident())
        assert v["recommended_action"] == "quarantine"
        assert v["confidence"] == "high"

    def test_lone_new_device_is_only_monitored(self):
        """A phone joining a hotspot is the normal way a guest appears."""
        inc = {"id": 9, "severity": "warning", "device_mac": "aa:bb:cc:dd:ee:01",
               "alerts": [{"message": "Unrecognized device joined.",
                           "details": {"threat_type": "rogue_device",
                                       "confidence": 0.5,
                                       "evidence": [{"signal": "unknown_mac"}]}}]}
        v = Responder(runtime=None).assess(inc)
        assert v["recommended_action"] == "monitor"

    def test_thin_scan_evidence_is_not_quarantined(self):
        inc = {"id": 10, "severity": "warning", "device_mac": "aa:bb:cc:dd:ee:02",
               "alerts": [{"message": "Port scan suspected.",
                           "details": {"threat_type": "port_scan",
                                       "confidence": 0.4,
                                       "evidence": [{"signal": "vertical_scan"}]}}]}
        v = Responder(runtime=None).assess(inc)
        assert v["recommended_action"] == "monitor"
        assert v["confidence"] == "low"

    def test_every_verdict_is_a_valid_action(self):
        for inc in (_dns_fp_incident(), _scan_incident(), {"id": 1, "alerts": []}):
            assert Responder(None).assess(inc)["recommended_action"] in VALID_ACTIONS


class TestValidation:
    def test_indicators_are_grounded_in_real_evidence(self):
        """A model may not cite a symptom the network never showed."""
        ev = gather_evidence(_dns_fp_incident())
        v = validate_verdict({
            "assessment": "Looks like CDN traffic.",
            "confidence": "medium",
            "indicators_matched": ["qname_stuffing", "beacon_jitter",
                                   "totally_made_up"],
            "recommended_action": "dismiss_benign",
        }, ev)
        assert v["indicators_matched"] == ["qname_stuffing"]

    @pytest.mark.parametrize("bad", [
        {"confidence": "high", "recommended_action": "monitor"},          # no assessment
        {"assessment": "x", "recommended_action": "nuke_from_orbit"},     # bad action
        {"assessment": "  ", "recommended_action": "monitor"},            # blank
        "not a dict",
        None,
    ])
    def test_unusable_output_is_rejected_not_repaired(self, bad):
        """Guessing what the model meant is worse than falling back."""
        assert validate_verdict(bad, {"signals": []}) is None

    def test_missing_confidence_becomes_low(self):
        v = validate_verdict({"assessment": "x", "recommended_action": "monitor"},
                             {"signals": []})
        assert v["confidence"] == "low"


class TestModelPath:
    def test_valid_model_output_is_used(self):
        runtime = ScriptedRuntime(['{"assessment": "Meta CDN prefetch, not '
                                  'exfiltration.", "confidence": "high", '
                                  '"indicators_matched": ["qname_stuffing"], '
                                  '"recommended_action": "dismiss_benign"}'])
        v = Responder(runtime).assess(_dns_fp_incident())
        assert v["source"] == "model"
        assert v["recommended_action"] == "dismiss_benign"

    def test_junk_model_output_falls_back_to_rules(self):
        runtime = ScriptedRuntime(["I'm not sure, maybe check the logs?"])
        v = Responder(runtime).assess(_dns_fp_incident())
        assert v["source"] == "rules"
        assert v["recommended_action"] == "dismiss_benign"

    def test_model_exception_falls_back_to_rules(self):
        class Exploding:
            def generate(self, messages):
                raise RuntimeError("ollama died")
        v = Responder(Exploding()).assess(_scan_incident())
        assert v["source"] == "rules"
        assert v["recommended_action"] == "quarantine"

    def test_model_sees_domain_context_it_cannot_be_expected_to_recall(self):
        """Asked cold, a 3B model does not know fbcdn.net is Meta's CDN — and
        without that it recommends quarantining a phone for using Instagram."""
        runtime = ScriptedRuntime(['{"assessment": "ok", "confidence": "low", '
                                  '"indicators_matched": [], '
                                  '"recommended_action": "monitor"}'])
        Responder(runtime).assess(_dns_fp_incident())
        prompt = runtime.calls[0][0]["content"]
        assert "domain_context" in prompt
        assert "is_known_app_infrastructure" in prompt
        assert "Facebook" in prompt or "Meta" in prompt


class TestContainmentFloor:
    """The model may raise containment. It may never lower it."""

    def test_model_cannot_downgrade_a_real_threat(self):
        runtime = ScriptedRuntime(['{"assessment": "Probably an authorised '
                                  'admin scan.", "confidence": "low", '
                                  '"indicators_matched": ["vertical_scan"], '
                                  '"recommended_action": "dismiss_benign"}'])
        v = Responder(runtime).assess(_scan_incident())
        assert v["recommended_action"] == "quarantine"
        assert v["overruled"]["model_recommended"] == "dismiss_benign"

    def test_overruled_text_matches_the_action_taken(self):
        """A 'this is benign' paragraph beside a Quarantine button reads as a
        bug — the assessment that decided must be the one displayed."""
        runtime = ScriptedRuntime(['{"assessment": "Totally benign.", '
                                  '"confidence": "low", '
                                  '"indicators_matched": [], '
                                  '"recommended_action": "monitor"}'])
        v = Responder(runtime).assess(_scan_incident())
        assert "Totally benign" not in v["assessment"]
        assert v["overruled"]["model_assessment"] == "Totally benign."

    def test_model_may_escalate_freely(self):
        runtime = ScriptedRuntime(['{"assessment": "This is worse than it '
                                  'looks.", "confidence": "high", '
                                  '"indicators_matched": ["qname_stuffing"], '
                                  '"recommended_action": "quarantine"}'])
        v = Responder(runtime).assess(_dns_fp_incident())
        assert v["recommended_action"] == "quarantine"
        assert "overruled" not in v

    def test_agreement_is_left_alone(self):
        runtime = ScriptedRuntime(['{"assessment": "CDN.", "confidence": '
                                  '"medium", "indicators_matched": [], '
                                  '"recommended_action": "dismiss_benign"}'])
        v = Responder(runtime).assess(_dns_fp_incident())
        assert v["recommended_action"] == "dismiss_benign"
        assert "overruled" not in v
        assert v["assessment"] == "CDN."
