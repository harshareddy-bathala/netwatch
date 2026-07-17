"""
test_redteam_demo.py - Red-Team Demo Smoke Tests (Phase 2)
===========================================================

The demo script doubles as a CI smoke check for the detector pack: every
scenario must fire its named threat through the real ThreatDetector code
path.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.redteam_demo import run, SCENARIOS, main


def test_every_scenario_fires_named_threat():
    results = run()
    assert set(results) == set(SCENARIOS)
    for name, res in results.items():
        assert res["fired"], f"{name} did not fire {res['expect']}"


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scenario_isolation(name):
    """Non-rogue scenarios must not leak a rogue_device alert (attacker is
    pre-registered as known)."""
    res = run(only=[name])[name]
    assert res["fired"]
    threat_types = {a["threat_type"] for a in res["alerts"]}
    if name != "rogue_device":
        assert "rogue_device" not in threat_types


def test_alerts_carry_evidence_and_confidence():
    for res in run().values():
        for alert in res["alerts"]:
            assert alert["evidence"], "alert missing evidence[]"
            assert 0.0 <= alert["confidence"] <= 1.0


def test_unknown_scenario_rejected():
    with pytest.raises(SystemExit):
        run(only=["does_not_exist"])


def test_main_exit_zero_when_all_fire():
    assert main([]) == 0
