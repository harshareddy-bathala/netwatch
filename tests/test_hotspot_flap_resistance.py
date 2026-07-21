"""
test_hotspot_flap_resistance.py - Don't leave hotspot mode on a blink
=====================================================================

Field logs (2026-07-20) show hotspot <-> public_network oscillating roughly
every 30 seconds while a hotspot was up. Windows drops the ICS virtual adapter
whenever the Mobile Hotspot has no client attached, and each flap restarts
capture, clears the dashboard, resets the digital twin and re-scopes every
device row — on stage it reads as the app crashing.

Two changes are covered here:

* leaving hotspot now needs a full minute of agreement (entering stays instant,
  because entering is cheap and leaving is not), and
* an "interface lost" notification no longer short-circuits that, but does set
  a restart flag so capture rebuilds the moment the adapter reappears with the
  same name and IP — which is the normal ICS case and previously left capture
  dead until something else changed.
"""

import os
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.interface_manager import InterfaceManager
from packet_capture.modes.base_mode import InterfaceInfo, ModeName


class _FakeMode:
    def __init__(self, mode_name, ip, iface, iface_type, gateway=None):
        self._mode_name = mode_name
        self.interface = InterfaceInfo(
            name=iface,
            friendly_name=iface,
            ip_address=ip,
            mac_address="AA:BB:CC:DD:EE:FF",
            netmask="255.255.255.0",
            gateway=gateway,
            ssid=None,
            interface_type=iface_type,
            is_active=True,
        )

    def get_mode_name(self):
        return self._mode_name


def _hotspot():
    return _FakeMode(ModeName.HOTSPOT, "192.168.137.1",
                     "Local Area Connection* 10", "hotspot_virtual")


def _public():
    return _FakeMode(ModeName.PUBLIC_NETWORK, "192.168.40.160", "Wi-Fi",
                     "wifi", gateway="192.168.40.1")


def _manager(current):
    mgr = InterfaceManager(refresh_interval=30, auto_detect=False,
                           force_safe=False)
    mgr._current_mode = current
    mgr._last_transition_time = 0.0
    return mgr


class TestExitHysteresis:
    def test_single_blink_does_not_leave_hotspot(self):
        mgr = _manager(_hotspot())
        with patch.object(mgr._detector, "detect", return_value=_public()):
            mgr._do_detect()
        assert mgr._current_mode.get_mode_name() == ModeName.HOTSPOT

    def test_leaving_needs_sustained_agreement(self):
        mgr = _manager(_hotspot())
        pub = _public()
        with patch.object(mgr._detector, "detect", return_value=pub):
            for _ in range(mgr._hotspot_exit_threshold - 1):
                mgr._do_detect()
            assert mgr._current_mode.get_mode_name() == ModeName.HOTSPOT
            mgr._do_detect()
        assert mgr._current_mode.get_mode_name() == ModeName.PUBLIC_NETWORK

    def test_exit_threshold_covers_at_least_a_minute(self):
        """The observed flap period was ~30s, so the guard must exceed it."""
        mgr = _manager(_hotspot())
        # Pending detections poll at 3s; the threshold must span > 30s.
        assert mgr._hotspot_exit_threshold * 3 >= 30
        assert mgr._hotspot_exit_cooldown >= 60

    def test_entering_hotspot_is_still_immediate(self):
        mgr = _manager(_public())
        hs = _hotspot()
        with patch.object(mgr._detector, "detect", return_value=hs):
            mgr._do_detect()
        assert mgr._current_mode.get_mode_name() == ModeName.HOTSPOT


class TestInterfaceLossRecovery:
    def test_loss_in_hotspot_does_not_instantly_switch(self):
        mgr = _manager(_hotspot())
        with patch.object(mgr._detector, "detect", return_value=_public()):
            mgr.notify_interface_lost()
        assert mgr._current_mode.get_mode_name() == ModeName.HOTSPOT
        assert mgr._restart_requested is True

    def test_capture_restarts_when_same_interface_returns(self):
        """ICS brings the adapter back with an identical name and IP, so
        nothing "changed" — but capture is dead and must be rebuilt."""
        mgr = _manager(_hotspot())
        fired = []
        mgr.on_mode_change(lambda old, new: fired.append((old, new)))

        with patch.object(mgr._detector, "detect", return_value=_public()):
            mgr.notify_interface_lost()
        assert fired == []                       # nothing to restart onto yet

        with patch.object(mgr._detector, "detect", return_value=_hotspot()):
            mgr._do_detect()

        assert len(fired) == 1                   # callbacks fired -> engine restarts
        assert fired[0][1].get_mode_name() == ModeName.HOTSPOT
        assert mgr._restart_requested is False   # consumed, not sticky

    def test_loss_outside_hotspot_still_switches_fast(self):
        """Only hotspot-sensitive modes need the slow path."""
        eth = _FakeMode(ModeName.ETHERNET, "10.0.0.5", "Ethernet", "ethernet",
                        gateway="10.0.0.1")
        mgr = _manager(eth)
        with patch.object(mgr._detector, "detect", return_value=_public()):
            mgr.notify_interface_lost()
        assert mgr._current_mode.get_mode_name() == ModeName.PUBLIC_NETWORK


class TestPinnedModeHold:
    def test_absent_pinned_interface_holds_current_mode(self):
        mgr = _manager(_hotspot())
        # detect() returns *something*, but the detector reports that the
        # pinned interface is missing — we must not adopt the substitute.
        mgr._detector.forced_mode_unavailable = True
        try:
            with patch.object(mgr._detector, "detect", return_value=_public()):
                mgr._do_detect()
            assert mgr._current_mode.get_mode_name() == ModeName.HOTSPOT
        finally:
            mgr._detector.forced_mode_unavailable = False
