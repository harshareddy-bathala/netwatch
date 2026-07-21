"""
test_forced_mode.py - Operator-pinned capture mode (--mode / NETWATCH_FORCE_MODE)
================================================================================

Auto-detection reads live OS state, and that state is not stable: Windows tears
down the ICS virtual adapter whenever the Mobile Hotspot has no client, so the
detector legitimately sees "not a hotspot", switches to public_network, and
switches back seconds later. Field logs show that cycle repeating every ~30s,
and each pass restarts capture, resets the digital twin and re-scopes every
device row.

Pinning the mode removes the question. These tests cover the three properties
that make the pin trustworthy:

* it wins over whatever detection would have concluded,
* it skips the liveness probes that exist only to help detection guess, and
* when its interface is genuinely absent it *holds*, rather than quietly
  falling back to a different mode (which would reintroduce the flap).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from packet_capture.mode_detector import ModeDetector
from packet_capture.modes.base_mode import InterfaceInfo, ModeName


def _iface(name, ip, iface_type, gateway=None, mac="AA:BB:CC:DD:EE:01"):
    return InterfaceInfo(
        name=name,
        friendly_name=name,
        ip_address=ip,
        mac_address=mac,
        netmask="255.255.255.0",
        gateway=gateway,
        ssid=None,
        interface_type=iface_type,
        is_active=True,
    )


HOTSPOT_IFACE = _iface("Local Area Connection* 10", "192.168.137.1",
                       "hotspot_virtual")
WIFI_IFACE = _iface("Wi-Fi", "192.168.40.160", "wifi", gateway="192.168.40.1",
                    mac="28:D0:43:A5:22:70")
ETH_IFACE = _iface("Ethernet", "10.0.0.5", "ethernet", gateway="10.0.0.1")
SPAN_IFACE = _iface("Ethernet 2", "", "ethernet")


@pytest.fixture
def pinned(monkeypatch):
    """Pin a mode for the duration of a test."""
    def _pin(name):
        monkeypatch.setattr(config, "FORCE_MODE", name)
    return _pin


@pytest.fixture
def detector(monkeypatch):
    d = ModeDetector()

    def _no_ssid(_cache=None):
        return None

    # get_hotspot_ssid shells out to netsh; irrelevant here.
    import packet_capture.mode_detector as md
    monkeypatch.setattr(md.ph, "get_hotspot_ssid", _no_ssid)
    return d


class TestPinnedHotspot:
    def test_pin_wins_over_detection(self, detector, pinned, monkeypatch):
        pinned("hotspot")
        detector._all_interfaces = [WIFI_IFACE, HOTSPOT_IFACE]
        mode = detector._forced_mode()
        assert mode is not None
        assert mode.get_mode_name() == ModeName.HOTSPOT
        assert mode.interface.name == HOTSPOT_IFACE.name
        assert detector.forced_mode_unavailable is False

    def test_pin_skips_the_adapter_liveness_probe(self, detector, pinned):
        """The probe is what a slow PowerShell call turns into a mode switch.

        A pinned mode must not consult it at all.
        """
        pinned("hotspot")
        detector._all_interfaces = [HOTSPOT_IFACE]

        def _boom(_name):
            raise AssertionError("pinned mode must not probe adapter liveness")

        detector._is_hotspot_adapter_active = _boom
        assert detector._forced_mode() is not None

    def test_ics_adapter_without_type_hint_still_matches(self, detector, pinned):
        """ICS always gives the host 192.168.137.1 and no gateway there."""
        pinned("hotspot")
        detector._all_interfaces = [
            WIFI_IFACE,
            _iface("Some Virtual Adapter", "192.168.137.1", "virtual"),
        ]
        mode = detector._forced_mode()
        assert mode is not None
        assert mode.get_mode_name() == ModeName.HOTSPOT

    def test_absent_interface_holds_instead_of_switching(self, detector, pinned):
        """The whole point: never silently become a different mode."""
        pinned("hotspot")
        detector._all_interfaces = [WIFI_IFACE]      # hotspot adapter gone
        assert detector._forced_mode() is None
        assert detector.forced_mode_unavailable is True


class TestPinnedOtherModes:
    def test_port_mirror_prefers_the_ip_less_ethernet(self, detector, pinned):
        """A SPAN port carries traffic *about* others, so it commonly has no
        IP and no gateway — the opposite of every other mode's preference."""
        pinned("port_mirror")
        detector._all_interfaces = [ETH_IFACE, SPAN_IFACE]
        mode = detector._forced_mode()
        assert mode is not None
        assert mode.get_mode_name() == ModeName.PORT_MIRROR
        assert mode.interface.name == SPAN_IFACE.name

    def test_port_mirror_without_ethernet_holds(self, detector, pinned):
        pinned("port_mirror")
        detector._all_interfaces = [WIFI_IFACE]
        assert detector._forced_mode() is None
        assert detector.forced_mode_unavailable is True

    def test_no_pin_returns_none_and_clears_flag(self, detector, pinned):
        pinned(None)
        detector._all_interfaces = [WIFI_IFACE]
        assert detector._forced_mode() is None
        assert detector.forced_mode_unavailable is False


class TestConfigParsing:
    def test_only_known_modes_are_accepted(self):
        assert "hotspot" in config.VALID_FORCE_MODES
        assert "port_mirror" in config.VALID_FORCE_MODES
        # "auto" is the CLI's way of saying "no pin", not a mode.
        assert "auto" not in config.VALID_FORCE_MODES
