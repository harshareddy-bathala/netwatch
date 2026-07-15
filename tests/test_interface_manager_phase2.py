"""
test_interface_manager_phase2.py - Phase 2 Mode Transition Tests
=================================================================

Covers hotspot responsiveness and cooldown behavior in InterfaceManager.
"""

import os
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.interface_manager import InterfaceManager
from packet_capture.modes.base_mode import InterfaceInfo, ModeName


class _FakeMode:
    def __init__(
        self,
        mode_name: ModeName,
        ip: str,
        iface: str,
        iface_type: str,
        gateway: str | None,
        ssid: str | None = None,
    ):
        self._mode_name = mode_name
        self.interface = InterfaceInfo(
            name=iface,
            friendly_name=iface,
            ip_address=ip,
            mac_address="AA:BB:CC:DD:EE:FF",
            netmask="255.255.255.0",
            gateway=gateway,
            ssid=ssid,
            interface_type=iface_type,
            is_active=True,
        )

    def get_mode_name(self):
        return self._mode_name


def _make_mode(mode_name: ModeName, ip: str, iface: str, iface_type: str, gateway: str | None):
    return _FakeMode(mode_name, ip=ip, iface=iface, iface_type=iface_type, gateway=gateway)


class TestInterfaceManagerPhase2:
    def test_hotspot_transition_bypasses_cooldown(self):
        mgr = InterfaceManager(refresh_interval=30, auto_detect=False, force_safe=False)

        old_mode = _make_mode(
            ModeName.PUBLIC_NETWORK,
            ip="10.0.0.50",
            iface="Wi-Fi",
            iface_type="wifi",
            gateway="10.0.0.1",
        )
        hotspot_mode = _make_mode(
            ModeName.HOTSPOT,
            ip="192.168.137.1",
            iface="Local Area Connection* 10",
            iface_type="hotspot_virtual",
            gateway=None,
        )

        mgr._current_mode = old_mode
        mgr._last_transition_time = time.time()
        mgr._transition_cooldown = 60

        with patch.object(mgr._detector, "detect", return_value=hotspot_mode):
            mgr._do_detect()

        assert mgr._current_mode is hotspot_mode

    def test_public_mode_keeps_fast_poll_interval(self):
        mgr = InterfaceManager(refresh_interval=30, auto_detect=False, force_safe=False)

        public_mode = _make_mode(
            ModeName.PUBLIC_NETWORK,
            ip="10.0.0.50",
            iface="Wi-Fi",
            iface_type="wifi",
            gateway="10.0.0.1",
        )

        mgr._current_mode = public_mode
        mgr._refresh_interval = 120
        mgr._is_stable = True
        mgr._stable_index = 2
        mgr._consecutive_stable = 20

        with patch.object(mgr._detector, "detect", return_value=public_mode):
            mgr._do_detect()

        assert mgr._refresh_interval == mgr._hotspot_fast_interval

    def test_non_hotspot_transition_still_respects_cooldown(self):
        mgr = InterfaceManager(refresh_interval=30, auto_detect=False, force_safe=False)

        old_mode = _make_mode(
            ModeName.ETHERNET,
            ip="192.168.1.10",
            iface="Ethernet",
            iface_type="ethernet",
            gateway="192.168.1.1",
        )
        new_mode = _make_mode(
            ModeName.PUBLIC_NETWORK,
            ip="192.168.1.20",
            iface="Wi-Fi",
            iface_type="wifi",
            gateway="192.168.1.1",
        )

        mgr._current_mode = old_mode
        mgr._stability_threshold = 1
        mgr._last_transition_time = time.time()
        mgr._transition_cooldown = 60

        with patch.object(mgr._detector, "detect", return_value=new_mode):
            mgr._do_detect()

        assert mgr._current_mode is old_mode

    def test_hotspot_exit_requires_extra_stability(self):
        mgr = InterfaceManager(refresh_interval=30, auto_detect=False, force_safe=False)

        hotspot_mode = _make_mode(
            ModeName.HOTSPOT,
            ip="192.168.137.1",
            iface="Local Area Connection* 10",
            iface_type="hotspot_virtual",
            gateway=None,
        )
        public_mode = _make_mode(
            ModeName.PUBLIC_NETWORK,
            ip="10.0.0.50",
            iface="Wi-Fi",
            iface_type="wifi",
            gateway="10.0.0.1",
        )

        mgr._current_mode = hotspot_mode
        mgr._stability_threshold = 1
        mgr._hotspot_exit_threshold = 3
        mgr._last_transition_time = 0

        with patch.object(mgr._detector, "detect", return_value=public_mode):
            mgr._do_detect()

        assert mgr._current_mode is hotspot_mode
        assert mgr._pending_count == 1

    def test_hotspot_exit_respects_exit_cooldown(self):
        mgr = InterfaceManager(refresh_interval=30, auto_detect=False, force_safe=False)

        hotspot_mode = _make_mode(
            ModeName.HOTSPOT,
            ip="192.168.137.1",
            iface="Local Area Connection* 10",
            iface_type="hotspot_virtual",
            gateway=None,
        )
        public_mode = _make_mode(
            ModeName.PUBLIC_NETWORK,
            ip="10.0.0.50",
            iface="Wi-Fi",
            iface_type="wifi",
            gateway="10.0.0.1",
        )

        mgr._current_mode = hotspot_mode
        mgr._stability_threshold = 1
        mgr._hotspot_exit_threshold = 2
        mgr._hotspot_exit_cooldown = 30
        mgr._last_transition_time = time.time()

        with patch.object(mgr._detector, "detect", return_value=public_mode):
            mgr._do_detect()
            mgr._do_detect()

        assert mgr._current_mode is hotspot_mode
