"""
test_traffic_blocker.py - Real per-client enforcement (P1.8)
=============================================================
Pure logic only (no WinDivert driver in CI): filter construction + blocked-set
state management + graceful degradation when pydivert is absent.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.traffic_blocker import TrafficBlocker, build_windivert_filter


class TestFilter:
    def test_empty_is_none(self):
        assert build_windivert_filter(set()) is None

    def test_ipv4_only_terms(self):
        f = build_windivert_filter({"192.168.137.142", "192.168.137.178", "fe80::1"})
        assert f.startswith("ip and (")
        assert "ip.SrcAddr == 192.168.137.142" in f
        assert "ip.DstAddr == 192.168.137.178" in f
        assert "fe80" not in f          # IPv6 excluded from the v4 filter

    def test_only_ipv6_is_none(self):
        assert build_windivert_filter({"fe80::1", "2001:db8::1"}) is None


class TestState:
    def test_set_and_clear(self):
        tb = TrafficBlocker()
        tb.set_blocked_ips({"192.168.137.142"})
        st = tb.get_status()
        assert st["blocked_ips"] == ["192.168.137.142"]
        # No driver in CI → not 'windivert'; must degrade, not crash.
        assert st["mode"] in ("unavailable", "arp", "windivert")
        tb.set_blocked_ips(set())
        assert tb.get_status()["mode"] == "off"
        tb.stop()

    def test_arp_fallback_invoked_without_driver(self, monkeypatch):
        import packet_capture.traffic_blocker as m
        monkeypatch.setattr(m, "_PYDIVERT_OK", False)
        called = {}
        tb = TrafficBlocker(arp_blackhole=lambda ips: called.setdefault("ips", set(ips)))
        tb.set_blocked_ips({"192.168.137.142"})
        assert called.get("ips") == {"192.168.137.142"}
        assert tb.get_status()["mode"] == "arp"
        tb.stop()

    def test_idempotent_no_rearm_on_same_set(self, monkeypatch):
        import packet_capture.traffic_blocker as m
        monkeypatch.setattr(m, "_PYDIVERT_OK", False)
        calls = []
        tb = TrafficBlocker(arp_blackhole=lambda ips: calls.append(set(ips)))
        tb.set_blocked_ips({"10.0.0.5"})
        tb.set_blocked_ips({"10.0.0.5"})   # same set → no re-arm
        assert len(calls) == 1
        tb.stop()
