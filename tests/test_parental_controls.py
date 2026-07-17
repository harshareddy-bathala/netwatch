"""
test_parental_controls.py - Parental controls / quotas (W5)
============================================================

The enforcement *decision* is pure (no DB, injected clock), so the "should
this device be blocked right now?" logic — pause, daily cap, bedtime window
(incl. past-midnight wrap) — is unit-tested directly. Plus the DNS blocker's
whole-device sinkhole and the CRUD round-trip.
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.queries.policy_queries import (
    is_blocked_now, evaluate_blocked_macs, _in_window,
)

MB = 1024 * 1024


class TestBlockDecision:

    def test_paused_blocks(self):
        assert is_blocked_now({"paused": True}, 0) == "paused"

    def test_quota_exceeded_blocks(self):
        p = {"daily_quota_mb": 100}
        assert is_blocked_now(p, 99 * MB) is None
        assert is_blocked_now(p, 100 * MB) == "quota_exceeded"

    def test_no_quota_means_no_cap(self):
        assert is_blocked_now({"daily_quota_mb": None}, 999 * MB) is None

    def test_bedtime_window_blocks(self):
        p = {"blocked_windows": [{"start": "22:00", "end": "07:00"}]}
        assert is_blocked_now(p, 0, now=datetime(2026, 7, 20, 23, 30)) == "schedule"
        assert is_blocked_now(p, 0, now=datetime(2026, 7, 20, 6, 0)) == "schedule"
        assert is_blocked_now(p, 0, now=datetime(2026, 7, 20, 12, 0)) is None

    def test_daytime_window_no_wrap(self):
        p = {"blocked_windows": [{"start": "09:00", "end": "17:00"}]}
        assert is_blocked_now(p, 0, now=datetime(2026, 7, 20, 10, 0)) == "schedule"
        assert is_blocked_now(p, 0, now=datetime(2026, 7, 20, 20, 0)) is None

    def test_windows_as_json_string(self):
        p = {"blocked_windows": '[{"start": "22:00", "end": "07:00"}]'}
        assert is_blocked_now(p, 0, now=datetime(2026, 7, 20, 23, 0)) == "schedule"

    def test_pause_precedence_over_quota(self):
        assert is_blocked_now({"paused": True, "daily_quota_mb": 100}, 0) == "paused"


class TestInWindow:

    def test_wrap_midnight(self):
        assert _in_window(datetime(2026, 1, 1, 23, 0).time(), "22:00", "07:00")
        assert _in_window(datetime(2026, 1, 1, 3, 0).time(), "22:00", "07:00")
        assert not _in_window(datetime(2026, 1, 1, 12, 0).time(), "22:00", "07:00")


class TestEvaluateBlockedMacs:

    def test_maps_reasons_per_device(self):
        policies = [
            {"device_mac": "AA:BB:CC:00:00:01", "paused": True},
            {"device_mac": "AA:BB:CC:00:00:02", "daily_quota_mb": 50},
            {"device_mac": "AA:BB:CC:00:00:03"},
        ]
        usage = {"aa:bb:cc:00:00:02": 60 * MB}
        blocked = evaluate_blocked_macs(policies, usage)
        assert blocked == {
            "aa:bb:cc:00:00:01": "paused",
            "aa:bb:cc:00:00:02": "quota_exceeded",
        }


class TestDnsBlockerDeviceBlock:

    def test_set_blocked_macs_activates_and_matches(self):
        from packet_capture.dns_blocker import DNSBlocker
        b = DNSBlocker(iface=None, sender=lambda *a, **k: None)
        assert b._active is False
        b.set_blocked_macs({"AA:BB:CC:00:00:01"})
        assert b._active is True
        # normalized + stored
        assert "aa:bb:cc:00:00:01" in b._blocked_macs
        b.set_blocked_macs(set())
        assert b._active is False


class TestPolicyCrud:

    def test_upsert_get_delete(self, initialized_db):
        from database.queries.policy_queries import (
            upsert_policy, get_policy, get_policies, delete_policy,
        )
        upsert_policy("AA:BB:CC:00:00:09", paused=True, daily_quota_mb=200,
                      blocked_windows=[{"start": "22:00", "end": "07:00"}])
        p = get_policy("aa:bb:cc:00:00:09")
        assert p is not None
        assert p["paused"] is True
        assert p["daily_quota_mb"] == 200
        assert p["blocked_windows"] == [{"start": "22:00", "end": "07:00"}]
        # partial update keeps other fields
        upsert_policy("AA:BB:CC:00:00:09", paused=False)
        p2 = get_policy("aa:bb:cc:00:00:09")
        assert p2["paused"] is False
        assert p2["daily_quota_mb"] == 200
        assert any(x["device_mac"] == "aa:bb:cc:00:00:09" for x in get_policies())
        assert delete_policy("aa:bb:cc:00:00:09") is True
        assert get_policy("aa:bb:cc:00:00:09") is None
