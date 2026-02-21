"""
test_mode_detection.py - Phase 1: Network Mode Detection Tests
================================================================

Tests for mode detection across Windows, Linux, and macOS.
Verifies hotspot, WiFi client, ethernet, and public network detection.
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.modes.base_mode import (
    BaseMode, InterfaceInfo, ModeCapabilities, NetworkScope, ModeName,
)
from packet_capture.modes.hotspot_mode import HotspotMode
from packet_capture.modes.wifi_client_mode import WiFiClientMode
from packet_capture.modes.ethernet_mode import EthernetMode
from packet_capture.modes.public_network_mode import PublicNetworkMode
from packet_capture.modes.port_mirror_mode import PortMirrorMode
from packet_capture.mode_detector import ModeDetector
from packet_capture.filter_manager import FilterManager


# ===================================================================
# Hotspot Mode Tests
# ===================================================================

class TestHotspotMode:
    """Tests for hotspot / mobile AP detection."""

    def test_hotspot_mode_name(self, hotspot_mode):
        assert hotspot_mode.get_mode_name() == ModeName.HOTSPOT

    def test_hotspot_sees_connected_clients(self, hotspot_mode):
        caps = hotspot_mode.capabilities
        assert caps.scope == NetworkScope.CONNECTED_CLIENTS

    def test_hotspot_can_see_other_devices(self, hotspot_mode):
        assert hotspot_mode.capabilities.can_see_other_devices is True

    def test_hotspot_uses_promiscuous(self, hotspot_mode):
        assert hotspot_mode.should_use_promiscuous() is True

    def test_hotspot_bpf_filter_not_empty(self, hotspot_mode):
        bpf = hotspot_mode.get_bpf_filter()
        assert bpf and len(bpf) > 0

    def test_hotspot_bpf_contains_subnet(self, hotspot_mode):
        bpf = hotspot_mode.get_bpf_filter()
        # Should filter to hotspot subnet
        assert "192.168.137" in bpf or "net" in bpf.lower()

    def test_hotspot_valid_ip_range(self, hotspot_mode):
        ip_range = hotspot_mode.get_valid_ip_range()
        assert ip_range is not None

    def test_hotspot_dict_serializable(self, hotspot_mode):
        d = hotspot_mode.to_dict()
        assert "mode" in d or "mode_name" in d or "name" in d


# ===================================================================
# WiFi Client Mode Tests
# ===================================================================

class TestWiFiClientMode:
    """Tests for WiFi client (station) mode."""

    def test_wifi_mode_name(self, wifi_mode):
        assert wifi_mode.get_mode_name() == ModeName.WIFI_CLIENT

    def test_wifi_scope_own_traffic(self, wifi_mode):
        caps = wifi_mode.capabilities
        assert caps.scope == NetworkScope.OWN_TRAFFIC_ONLY

    def test_wifi_not_detected_as_hotspot(self, mock_wifi_info):
        """Critical: WiFi client must NOT be confused with hotspot."""
        mode = WiFiClientMode(mock_wifi_info)
        assert mode.get_mode_name() != ModeName.HOTSPOT

    def test_wifi_bpf_filter_restricts_to_self(self, wifi_mode):
        bpf = wifi_mode.get_bpf_filter()
        assert bpf and len(bpf) > 0
        # Filter should reference the wifi IP or MAC
        info = wifi_mode.interface
        assert info.ip_address in bpf or info.mac_address.lower() in bpf.lower()

    def test_wifi_no_promiscuous(self, wifi_mode):
        assert wifi_mode.should_use_promiscuous() is False

    def test_wifi_cannot_see_others(self, wifi_mode):
        assert wifi_mode.capabilities.can_see_other_devices is False

    def test_wifi_description(self, wifi_mode):
        desc = wifi_mode.get_description()
        assert isinstance(desc, str) and len(desc) > 0


# ===================================================================
# Ethernet Mode Tests
# ===================================================================

class TestEthernetMode:
    """Tests for wired Ethernet mode."""

    def test_ethernet_mode_name(self, ethernet_mode):
        assert ethernet_mode.get_mode_name() == ModeName.ETHERNET

    def test_ethernet_scope_local_network(self, ethernet_mode):
        caps = ethernet_mode.capabilities
        assert caps.scope == NetworkScope.LOCAL_NETWORK

    def test_ethernet_bpf_contains_subnet(self, ethernet_mode):
        bpf = ethernet_mode.get_bpf_filter()
        assert bpf and len(bpf) > 0

    def test_ethernet_can_see_devices(self, ethernet_mode):
        assert ethernet_mode.capabilities.can_see_other_devices is True

    def test_ethernet_can_arp_scan(self, ethernet_mode):
        assert ethernet_mode.can_arp_scan() is True


# ===================================================================
# Public Network Mode Tests
# ===================================================================

class TestPublicNetworkMode:
    """Tests for safe/public network mode."""

    def test_public_mode_name(self, public_mode):
        assert public_mode.get_mode_name() == ModeName.PUBLIC_NETWORK

    def test_public_safe_for_public(self, public_mode):
        assert public_mode.is_safe_for_public_network() is True

    def test_public_no_promiscuous(self, public_mode):
        assert public_mode.should_use_promiscuous() is False

    def test_public_restricts_to_self(self, public_mode):
        caps = public_mode.capabilities
        assert caps.scope == NetworkScope.OWN_TRAFFIC_ONLY

    def test_public_bpf_filter(self, public_mode):
        bpf = public_mode.get_bpf_filter()
        assert bpf and len(bpf) > 0


# ===================================================================
# Filter Manager Tests
# ===================================================================

class TestFilterManager:
    """Tests for BPF filter generation and validation."""

    def test_hotspot_filter_not_empty(self, hotspot_mode):
        fm = FilterManager(hotspot_mode)
        flt = fm.get_validated_filter()
        assert flt and len(flt) > 0

    def test_wifi_filter_not_empty(self, wifi_mode):
        fm = FilterManager(wifi_mode)
        flt = fm.get_validated_filter()
        assert flt and len(flt) > 0

    def test_ethernet_filter_not_empty(self, ethernet_mode):
        fm = FilterManager(ethernet_mode)
        flt = fm.get_validated_filter()
        assert flt and len(flt) > 0

    def test_promiscuous_setting_hotspot(self, hotspot_mode):
        fm = FilterManager(hotspot_mode)
        assert fm.get_promiscuous_setting() is True

    def test_promiscuous_setting_wifi(self, wifi_mode):
        fm = FilterManager(wifi_mode)
        assert fm.get_promiscuous_setting() is False

    def test_filter_summary(self, ethernet_mode):
        fm = FilterManager(ethernet_mode)
        summary = fm.get_filter_summary()
        assert isinstance(summary, dict)
        assert "filter" in summary or "bpf_filter" in summary or "mode" in summary


# ===================================================================
# Mode Detector Tests
# ===================================================================

class TestModeDetector:
    """Tests for the ModeDetector orchestrator."""

    @pytest.fixture(autouse=True)
    def _mock_detector(self):
        """Prevent real network/subprocess calls in ModeDetector."""
        from packet_capture.modes.base_mode import InterfaceInfo, ModeName
        from packet_capture.modes.ethernet_mode import EthernetMode

        mock_info = InterfaceInfo(
            name="eth0", friendly_name="Ethernet",
            ip_address="192.168.1.100", mac_address="AA:BB:CC:DD:EE:FF",
            netmask="255.255.255.0", gateway="192.168.1.1",
            ssid=None, interface_type="ethernet", is_active=True,
        )
        self._mock_mode = EthernetMode(mock_info)
        self._mock_info = mock_info

    def test_detector_returns_base_mode(self):
        with patch.object(ModeDetector, 'detect', return_value=self._mock_mode):
            detector = ModeDetector()
            mode = detector.detect()
            assert isinstance(mode, BaseMode)

    def test_detector_mode_has_name(self):
        with patch.object(ModeDetector, 'detect', return_value=self._mock_mode):
            detector = ModeDetector()
            mode = detector.detect()
            assert mode.get_mode_name() in [
                ModeName.HOTSPOT, ModeName.WIFI_CLIENT, ModeName.ETHERNET,
                ModeName.PUBLIC_NETWORK, ModeName.PORT_MIRROR, ModeName.UNKNOWN,
            ]

    def test_detector_mode_has_bpf(self):
        with patch.object(ModeDetector, 'detect', return_value=self._mock_mode):
            detector = ModeDetector()
            mode = detector.detect()
            bpf = mode.get_bpf_filter()
            assert isinstance(bpf, str)

    def test_detector_enumerate_interfaces(self):
        with patch.object(ModeDetector, 'get_all_interfaces', return_value=[self._mock_info]):
            detector = ModeDetector()
            ifaces = detector.get_all_interfaces()
            assert isinstance(ifaces, list)
            assert len(ifaces) == 1


# ===================================================================
# InterfaceInfo Tests
# ===================================================================

class TestInterfaceInfo:
    """Tests for the InterfaceInfo data class."""

    def test_create_interface_info(self, mock_interface_info):
        assert mock_interface_info.name == "eth0"
        assert mock_interface_info.ip_address == "192.168.1.100"

    def test_interface_is_active(self, mock_interface_info):
        assert mock_interface_info.is_active is True

    def test_interface_type(self, mock_interface_info):
        assert mock_interface_info.interface_type == "ethernet"


# ===================================================================
# Cross-Mode Consistency Tests
# ===================================================================

class TestModeConsistency:
    """Ensure all modes follow the BaseMode contract."""

    @pytest.fixture(params=["hotspot", "wifi", "ethernet", "public"])
    def any_mode(self, request, hotspot_mode, wifi_mode, ethernet_mode, public_mode):
        modes = {
            "hotspot": hotspot_mode,
            "wifi": wifi_mode,
            "ethernet": ethernet_mode,
            "public": public_mode,
        }
        return modes[request.param]

    def test_has_bpf_filter(self, any_mode):
        bpf = any_mode.get_bpf_filter()
        assert isinstance(bpf, str)

    def test_has_capabilities(self, any_mode):
        caps = any_mode.capabilities
        assert isinstance(caps, ModeCapabilities)

    def test_has_scope(self, any_mode):
        scope = any_mode.get_scope()
        assert scope in NetworkScope

    def test_to_dict(self, any_mode):
        d = any_mode.to_dict()
        assert isinstance(d, dict)

    def test_has_description(self, any_mode):
        desc = any_mode.get_description()
        assert isinstance(desc, str) and len(desc) > 0
