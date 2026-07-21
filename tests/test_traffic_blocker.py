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


class FakeClock:
    """Monotonic clock we can advance by hand."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class TestRearmDebounce:
    """The SNI learner grows the blocked set continuously while an app retries.

    Re-arming per change meant tearing the kernel filter down and back up every
    policy sweep on the live NAT path. Widening is batched; anything that could
    leave a device wrongly blocked is not.
    """

    def _blocker(self, monkeypatch, clock):
        import packet_capture.traffic_blocker as m
        monkeypatch.setattr(m, "_PYDIVERT_OK", False)
        calls = []
        tb = TrafficBlocker(
            arp_blackhole=lambda ips: calls.append(set(ips)),
            rearm_interval=30.0,
            clock=clock,
        )
        return tb, calls

    def test_first_block_arms_immediately(self, monkeypatch):
        clock = FakeClock()
        tb, calls = self._blocker(monkeypatch, clock)
        tb.set_blocked_ips({"57.144.56.196"})
        assert len(calls) == 1        # blocking must feel instant
        tb.stop()

    def test_widening_is_deferred(self, monkeypatch):
        clock = FakeClock()
        tb, calls = self._blocker(monkeypatch, clock)
        tb.set_blocked_ips({"57.144.56.196"})
        tb.set_blocked_ips({"57.144.56.196", "57.144.56.197"})
        tb.set_blocked_ips({"57.144.56.196", "57.144.56.197", "31.13.79.35"})
        assert len(calls) == 1        # still one handle, not three
        # ...but the wider set is remembered and applied once due.
        assert len(tb.get_status()["blocked_ips"]) == 3
        assert tb.flush_pending() is False      # too soon
        clock.advance(31)
        assert tb.flush_pending() is True
        assert calls[-1] == {"57.144.56.196", "57.144.56.197", "31.13.79.35"}
        tb.stop()

    def test_unblocking_is_never_deferred(self, monkeypatch):
        clock = FakeClock()
        tb, calls = self._blocker(monkeypatch, clock)
        tb.set_blocked_ips({"10.0.0.5", "10.0.0.6"})
        tb.set_blocked_ips({"10.0.0.5"})        # a device was released
        assert len(calls) == 2                   # applied at once
        assert calls[-1] == {"10.0.0.5"}
        tb.stop()

    def test_full_release_is_never_deferred(self, monkeypatch):
        clock = FakeClock()
        tb, calls = self._blocker(monkeypatch, clock)
        tb.set_blocked_ips({"10.0.0.5"})
        tb.set_blocked_ips(set())
        assert tb.get_status()["mode"] == "off"
        tb.stop()

    def test_flush_is_noop_when_nothing_pending(self, monkeypatch):
        clock = FakeClock()
        tb, calls = self._blocker(monkeypatch, clock)
        tb.set_blocked_ips({"10.0.0.5"})
        clock.advance(120)
        assert tb.flush_pending() is False       # set already matches what's armed
        assert len(calls) == 1
        tb.stop()
