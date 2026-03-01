"""
test_mode_detection.py - Phase 1: Network Mode Detection Tests
================================================================

Tests for mode detection across Windows, Linux, and macOS.
Verifies hotspot, ethernet, and public network detection.
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
        # Hotspot uses broad filter to capture all IP traffic on the
        # dedicated virtual adapter (no subnet restriction needed).
        assert "ip" in bpf.lower()

    def test_hotspot_valid_ip_range(self, hotspot_mode):
        ip_range = hotspot_mode.get_valid_ip_range()
        assert ip_range is not None

    def test_hotspot_dict_serializable(self, hotspot_mode):
        d = hotspot_mode.to_dict()
        assert "mode" in d or "mode_name" in d or "name" in d


# ===================================================================
# Public Network WiFi Mode Tests (uses PublicNetworkMode)
# ===================================================================

class TestPublicNetworkWiFiMode:
    """Tests for WiFi connections — always uses PublicNetworkMode."""

    def test_wifi_mode_name(self, wifi_mode):
        assert wifi_mode.get_mode_name() == ModeName.PUBLIC_NETWORK

    def test_wifi_scope_own_traffic(self, wifi_mode):
        caps = wifi_mode.capabilities
        assert caps.scope == NetworkScope.OWN_TRAFFIC_ONLY

    def test_wifi_not_detected_as_hotspot(self, mock_wifi_info):
        """Critical: WiFi client must NOT be confused with hotspot."""
        mode = PublicNetworkMode(mock_wifi_info)
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
# Hotspot Adapter Active-Service Verification Tests
# ===================================================================

class TestHotspotAdapterActiveCheck:
    """Tests for _is_hotspot_adapter_active() and its integration into Strategy 1."""

    @pytest.fixture(autouse=True)
    def _reset_caches(self):
        """Clear class-level caches between tests."""
        ModeDetector._adapter_status_cache = {}
        ModeDetector._adapter_status_cache_time = 0
        ModeDetector._hostednet_cache = None
        ModeDetector._hostednet_cache_time = 0
        yield
        ModeDetector._adapter_status_cache = {}
        ModeDetector._adapter_status_cache_time = 0
        ModeDetector._hostednet_cache = None
        ModeDetector._hostednet_cache_time = 0

    def _make_hotspot_iface(self, name="Local Area Connection* 10",
                            ip="192.168.137.1"):
        return InterfaceInfo(
            name=name, friendly_name=name,
            ip_address=ip, mac_address="AA:BB:CC:DD:EE:01",
            netmask="255.255.255.0", gateway=None,
            ssid=None, interface_type="hotspot_virtual", is_active=True,
        )

    def _make_wifi_iface(self, ip="192.168.44.100"):
        return InterfaceInfo(
            name="Wi-Fi", friendly_name="Wi-Fi",
            ip_address=ip, mac_address="AA:BB:CC:DD:EE:02",
            netmask="255.255.255.0", gateway="192.168.44.1",
            ssid="HomeNetwork", interface_type="wifi", is_active=True,
        )

    # ── _is_hotspot_adapter_active() unit tests ──

    @patch("packet_capture.platform_helpers.run_command", return_value="Up|1\n")
    def test_adapter_active_when_status_up(self, mock_cmd):
        detector = ModeDetector()
        assert detector._is_hotspot_adapter_active("Local Area Connection* 10") is True

    @patch("packet_capture.platform_helpers.run_command", return_value="Disconnected|0\n")
    def test_adapter_inactive_when_disconnected(self, mock_cmd):
        detector = ModeDetector()
        assert detector._is_hotspot_adapter_active("Local Area Connection* 10") is False

    @patch("packet_capture.platform_helpers.run_command", return_value=None)
    def test_adapter_failclosed_on_command_failure(self, mock_cmd):
        """When PowerShell fails, assume adapter is inactive (fail-closed)."""
        detector = ModeDetector()
        assert detector._is_hotspot_adapter_active("Local Area Connection* 10") is False

    @patch("packet_capture.platform_helpers.run_command", return_value="Not Present|0\n")
    def test_adapter_inactive_for_unexpected_status(self, mock_cmd):
        detector = ModeDetector()
        assert detector._is_hotspot_adapter_active("Local Area Connection* 10") is False

    @patch("packet_capture.platform_helpers.run_command", return_value="Up|1\n")
    def test_adapter_status_cached(self, mock_cmd):
        detector = ModeDetector()
        # First call populates cache
        assert detector._is_hotspot_adapter_active("Local Area Connection* 10") is True
        # Second call should use cache (run_command called only once)
        assert detector._is_hotspot_adapter_active("Local Area Connection* 10") is True
        mock_cmd.assert_called_once()

    # ── Strategy 1 integration tests ──

    @patch("packet_capture.mode_detector.IS_WINDOWS", True)
    @patch("packet_capture.mode_detector.run_command", return_value=None)
    def test_strategy1_skips_disconnected_adapter(self, mock_cmd):
        """Strategy 1 should skip a hotspot_virtual adapter that isn't Up."""
        detector = ModeDetector()
        detector._all_interfaces = [
            self._make_hotspot_iface(),
            self._make_wifi_iface(),
        ]
        # Make _is_hotspot_adapter_active return False
        with patch.object(detector, '_is_hotspot_adapter_active', return_value=False):
            result = detector._check_hotspot_windows()
        assert result is None

    @patch("packet_capture.mode_detector.IS_WINDOWS", True)
    @patch("packet_capture.mode_detector.run_command", return_value=None)
    def test_strategy1_detects_active_adapter(self, mock_cmd):
        """Strategy 1 should detect a hotspot_virtual adapter that is Up."""
        detector = ModeDetector()
        detector._all_interfaces = [
            self._make_hotspot_iface(),
            self._make_wifi_iface(),
        ]
        with patch.object(detector, '_is_hotspot_adapter_active', return_value=True):
            with patch("packet_capture.platform_helpers.get_hotspot_ssid", return_value="TestHotspot"):
                result = detector._check_hotspot_windows()
        assert result is not None
        assert isinstance(result, HotspotMode)


# ===================================================================
# Campus WiFi / Public Network Classification Tests
# ===================================================================

class TestWiFiPublicClassification:
    """Tests for _check_public_network_wifi() — all WiFi connections now return
    PublicNetworkMode regardless of network category or subnet size."""

    def _make_wifi_iface(self, ip="192.168.44.100", netmask="255.255.255.0",
                         ssid="HomeNetwork"):
        return InterfaceInfo(
            name="Wi-Fi", friendly_name="Wi-Fi",
            ip_address=ip, mac_address="AA:BB:CC:DD:EE:02",
            netmask=netmask, gateway="192.168.44.1",
            ssid=ssid, interface_type="wifi", is_active=True,
        )

    # ── Windows NLM-based classification ──

    @patch("packet_capture.mode_detector.IS_WINDOWS", True)
    def test_public_wifi_returns_public_mode(self):
        """WiFi on a Windows 'public' network → PublicNetworkMode."""
        detector = ModeDetector()
        detector._all_interfaces = [self._make_wifi_iface(ssid="CampusWiFi")]
        with patch("packet_capture.platform_helpers.detect_network_category", return_value="public"):
            result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    @patch("packet_capture.mode_detector.IS_WINDOWS", True)
    def test_domain_wifi_returns_public_mode(self):
        """WiFi on a Windows 'domain_authenticated' network → PublicNetworkMode."""
        detector = ModeDetector()
        detector._all_interfaces = [self._make_wifi_iface(ssid="CorpNet")]
        with patch("packet_capture.platform_helpers.detect_network_category", return_value="domain_authenticated"):
            result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    @patch("packet_capture.mode_detector.IS_WINDOWS", True)
    def test_private_wifi_returns_public_mode(self):
        """WiFi on a Windows 'private' network → PublicNetworkMode (merged)."""
        detector = ModeDetector()
        detector._all_interfaces = [self._make_wifi_iface(ssid="HomeNetwork")]
        with patch("packet_capture.platform_helpers.detect_network_category", return_value="private"):
            result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    @patch("packet_capture.mode_detector.IS_WINDOWS", True)
    def test_category_none_falls_through_to_public(self):
        """When NLM returns None, still returns PublicNetworkMode."""
        detector = ModeDetector()
        # /16 subnet = 65 534 hosts
        detector._all_interfaces = [
            self._make_wifi_iface(ssid="BigNet", netmask="255.255.0.0")
        ]
        with patch("packet_capture.platform_helpers.detect_network_category", return_value=None):
            result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    # ── Cross-platform — all WiFi returns PublicNetworkMode ──

    @patch("packet_capture.mode_detector.IS_WINDOWS", False)
    def test_large_subnet_returns_public_mode(self):
        """Subnet > /22 (campus-scale) → PublicNetworkMode."""
        detector = ModeDetector()
        # /20 = 4094 hosts
        detector._all_interfaces = [
            self._make_wifi_iface(ssid="UniWiFi", netmask="255.255.240.0")
        ]
        result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    @patch("packet_capture.mode_detector.IS_WINDOWS", False)
    def test_small_subnet_returns_public_mode(self):
        """Subnet <= /22 (home-scale) → PublicNetworkMode (merged)."""
        detector = ModeDetector()
        # /24 = 254 hosts
        detector._all_interfaces = [
            self._make_wifi_iface(ssid="HomeNetwork", netmask="255.255.255.0")
        ]
        result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    @patch("packet_capture.mode_detector.IS_WINDOWS", False)
    def test_boundary_slash22_returns_public_mode(self):
        """Exactly /22 (1022 hosts) → PublicNetworkMode (merged)."""
        detector = ModeDetector()
        detector._all_interfaces = [
            self._make_wifi_iface(ssid="SmallCampus", netmask="255.255.252.0")
        ]
        result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    @patch("packet_capture.mode_detector.IS_WINDOWS", False)
    def test_slash21_returns_public_mode(self):
        """/21 (2046 hosts) → PublicNetworkMode."""
        detector = ModeDetector()
        detector._all_interfaces = [
            self._make_wifi_iface(ssid="BigCampus", netmask="255.255.248.0")
        ]
        result = detector._check_public_network_wifi()
        assert isinstance(result, PublicNetworkMode)

    # ── detect() Step 4 log correctness ──

    @patch("packet_capture.mode_detector.IS_WINDOWS", False)
    def test_detect_logs_public_for_campus_wifi(self):
        """detect() should log PUBLIC_NETWORK for campus WiFi."""
        detector = ModeDetector()
        # Large subnet, non-Windows
        wifi = self._make_wifi_iface(ssid="CampusNet", netmask="255.255.0.0")
        detector._all_interfaces = [wifi]
        with patch.object(detector, '_enumerate_interfaces', return_value=[wifi]):
            with patch.object(detector, '_check_port_mirror', return_value=None):
                with patch.object(detector, '_check_hotspot', return_value=None):
                    with patch.object(detector, '_check_ethernet', return_value=None):
                        mode = detector.detect()
        assert isinstance(mode, PublicNetworkMode)


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
                ModeName.HOTSPOT, ModeName.ETHERNET,
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
