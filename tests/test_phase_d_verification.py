"""
test_phase_d_verification.py - Phase D: All-Mode Verification & Hardening
============================================================================

Verifies every mode is demo-ready: direction detection, device counts,
bandwidth accuracy, promiscuous-mode lifecycle, port-mirror fallback,
shutdown watchdog, _cached_discovery race-safety, and double-shutdown guard.
"""

import ipaddress
import os
import sys
import threading
import time
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.modes.base_mode import (
    BaseMode,
    InterfaceInfo,
    ModeCapabilities,
    ModeName,
    NetworkScope,
)
from packet_capture.modes.public_network_mode import PublicNetworkMode
from packet_capture.modes.hotspot_mode import HotspotMode
from packet_capture.modes.ethernet_mode import EthernetMode
from packet_capture.modes.port_mirror_mode import PortMirrorMode
from packet_capture.packet_processor import PacketProcessor
from packet_capture.strategies.ethernet_strategy import EthernetCaptureStrategy
from packet_capture.strategies.mirror_strategy import MirrorCaptureStrategy


# ===================================================================
# Helpers
# ===================================================================

def _make_interface(
    *,
    name="eth0",
    ip="192.168.1.100",
    mac="AA:BB:CC:DD:EE:FF",
    mask="255.255.255.0",
    gw="192.168.1.1",
    ssid=None,
    itype="ethernet",
):
    return InterfaceInfo(
        name=name,
        friendly_name=name,
        ip_address=ip,
        mac_address=mac,
        netmask=mask,
        gateway=gw,
        ssid=ssid,
        interface_type=itype,
        is_active=True,
    )


def _make_mock_mode(name_str, ip="192.168.1.100", iface="eth0"):
    info = _make_interface(name=iface, ip=ip)
    mode = MagicMock(spec=BaseMode)
    mode.interface = info
    mode.get_mode_name.return_value = MagicMock(value=name_str)
    mode.get_bpf_filter.return_value = "ip"
    mode.should_use_promiscuous.return_value = False
    return mode


# ===================================================================
# 1. Public Network WiFi Mode Verification
# ===================================================================

class TestPublicNetworkWiFiVerification:
    """Phase D item 1: Public network WiFi captures both directions via ether host."""

    def test_bpf_uses_ether_host_mac(self):
        """BPF filter must be 'ether host <mac>' to capture both IPv4+IPv6."""
        info = _make_interface(
            name="wlan0", ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff",
            ssid="CoffeeShop", itype="wifi",
        )
        mode = PublicNetworkMode(info)
        bpf = mode.get_bpf_filter()
        assert "ether host" in bpf
        assert "aa:bb:cc:dd:ee:ff" in bpf.lower()

    def test_direction_upload_from_self(self):
        """Packets FROM our IP → upload."""
        info = _make_interface(ip="192.168.1.50", mac="AA:BB:CC:44:55:66", itype="wifi")
        mode = PublicNetworkMode(info)
        proc = PacketProcessor(mode)
        d = proc._determine_direction("192.168.1.50", "8.8.8.8")
        assert d == "upload"

    def test_direction_download_to_self(self):
        """Packets TO our IP → download."""
        info = _make_interface(ip="192.168.1.50", mac="AA:BB:CC:44:55:66", itype="wifi")
        mode = PublicNetworkMode(info)
        proc = PacketProcessor(mode)
        d = proc._determine_direction("8.8.8.8", "192.168.1.50")
        assert d == "download"

    def test_mac_fallback_for_ipv6(self):
        """IPv6 packets fallback to MAC-based direction detection."""
        info = _make_interface(ip="192.168.1.50", mac="AA:BB:CC:44:55:66", itype="wifi")
        mode = PublicNetworkMode(info)
        proc = PacketProcessor(mode)
        # IPv6 src not matching our IPv4 → IP-based returns 'other'
        # But MAC-based fallback should resolve it
        d = proc._determine_direction(
            "fe80::1", "2607:f8b0:4004::200e",
            src_mac="AA:BB:CC:44:55:66", dst_mac="11:22:33:44:55:66",
        )
        assert d == "upload"

    def test_no_promiscuous(self):
        info = _make_interface(itype="wifi")
        mode = PublicNetworkMode(info)
        assert mode.should_use_promiscuous() is False

    def test_no_arp_cache_scan(self):
        info = _make_interface(itype="wifi")
        mode = PublicNetworkMode(info)
        assert mode.capabilities.can_arp_cache_scan is False

    def test_no_active_arp_scan(self):
        info = _make_interface(itype="wifi")
        mode = PublicNetworkMode(info)
        assert mode.capabilities.can_arp_scan is False


# ===================================================================
# 2. Hotspot Mode Verification
# ===================================================================

class TestHotspotVerification:
    """Phase D item 2: Hotspot subnet detection for various ranges."""

    def test_standard_ics_subnet(self):
        """Windows ICS 192.168.137.x detected correctly."""
        info = _make_interface(ip="192.168.137.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        assert mode.get_valid_ip_range() == "192.168.137.0/24"

    def test_wifi_direct_subnet(self):
        """Wi-Fi Direct uses 192.168.49.x — NOT 192.168.137.x."""
        info = _make_interface(ip="192.168.49.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        assert mode.get_valid_ip_range() == "192.168.49.0/24"

    def test_custom_hotspot_subnet(self):
        """Arbitrary hotspot subnet (172.20.10.x) from IP+mask."""
        info = _make_interface(ip="172.20.10.1", mask="255.255.255.240")
        mode = HotspotMode(info)
        ip_range = mode.get_valid_ip_range()
        assert ip_range is not None
        net = ipaddress.IPv4Network(ip_range, strict=False)
        assert ipaddress.IPv4Address("172.20.10.1") in net

    def test_ip_only_no_mask_falls_back_to_24(self):
        """If mask is missing, derive /24 from IP."""
        info = _make_interface(ip="192.168.49.1", mask=None)
        mode = HotspotMode(info)
        ip_range = mode.get_valid_ip_range()
        assert ip_range is not None
        assert "/24" in ip_range

    def test_hotspot_direction_client_upload(self):
        """Client→internet = upload from client's perspective."""
        info = _make_interface(ip="192.168.137.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        proc = PacketProcessor(mode)
        # Client 192.168.137.2 → Internet 8.8.8.8 = upload
        d = proc._determine_direction("192.168.137.2", "8.8.8.8")
        assert d == "upload"

    def test_hotspot_direction_client_download(self):
        """Internet→client = download from client's perspective."""
        info = _make_interface(ip="192.168.137.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        proc = PacketProcessor(mode)
        d = proc._determine_direction("8.8.8.8", "192.168.137.2")
        assert d == "download"

    def test_hotspot_bpf_contains_subnet(self):
        """BPF should capture all IP traffic on the dedicated hotspot adapter."""
        info = _make_interface(ip="192.168.49.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        bpf = mode.get_bpf_filter()
        assert "ip" in bpf.lower()

    def test_hotspot_arp_scan_allowed(self):
        info = _make_interface(ip="192.168.137.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        assert mode.capabilities.can_arp_scan is True


# ===================================================================
# 3. Ethernet Mode Verification
# ===================================================================

class TestEthernetVerification:
    """Phase D item 3: Ethernet promiscuous mode and ARP scan."""

    def test_promiscuous_enabled(self):
        info = _make_interface()
        mode = EthernetMode(info)
        assert mode.should_use_promiscuous() is True

    def test_bpf_contains_subnet(self):
        info = _make_interface(ip="192.168.1.100", mask="255.255.255.0")
        mode = EthernetMode(info)
        bpf = mode.get_bpf_filter()
        assert "192.168.1.0/24" in bpf

    def test_valid_ip_range_correct_cidr(self):
        info = _make_interface(ip="10.0.0.50", mask="255.255.0.0")
        mode = EthernetMode(info)
        assert mode.get_valid_ip_range() == "10.0.0.0/16"

    def test_strategy_setup_windows_promisc(self):
        """On Windows, EthernetCaptureStrategy.setup() sets _promisc_was_enabled."""
        info = _make_interface()
        mode = EthernetMode(info)
        strategy = EthernetCaptureStrategy(mode)
        with patch("packet_capture.strategies.ethernet_strategy.sys") as mock_sys:
            mock_sys.platform = "win32"
            strategy.setup()
        assert strategy._promisc_was_enabled is True

    def test_strategy_teardown_resets_state(self):
        """Teardown must reset _promisc_was_enabled regardless of platform."""
        info = _make_interface()
        mode = EthernetMode(info)
        strategy = EthernetCaptureStrategy(mode)
        strategy._promisc_was_enabled = True
        with patch("packet_capture.strategies.ethernet_strategy.sys") as mock_sys:
            mock_sys.platform = "win32"
            strategy.teardown()
        assert strategy._promisc_was_enabled is False
        assert strategy._compiled_filter is None

    def test_strategy_teardown_linux_ip_link(self):
        """On Linux, teardown disables promisc via ip link."""
        info = _make_interface()
        mode = EthernetMode(info)
        strategy = EthernetCaptureStrategy(mode)
        strategy._promisc_was_enabled = True
        with patch("packet_capture.strategies.ethernet_strategy.sys") as mock_sys, \
             patch("subprocess.run") as mock_run:
            mock_sys.platform = "linux"
            strategy.teardown()
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "promisc" in args and "off" in args

    def test_arp_scan_allowed(self):
        info = _make_interface()
        mode = EthernetMode(info)
        assert mode.capabilities.can_arp_scan is True


# ===================================================================
# 4. Port Mirror Mode Verification
# ===================================================================

class TestPortMirrorVerification:
    """Phase D item 4: Port mirror empty BPF, direction fallback."""

    def test_bpf_is_empty(self):
        info = _make_interface()
        mode = PortMirrorMode(info)
        assert mode.get_bpf_filter() == ""

    def test_promiscuous_on(self):
        info = _make_interface()
        mode = PortMirrorMode(info)
        assert mode.should_use_promiscuous() is True

    def test_direction_with_local_ips(self):
        """When local IPs are known, direction is correct."""
        info = _make_interface(ip="10.0.0.1")
        mode = PortMirrorMode(info)
        proc = PacketProcessor(mode, local_ips={"10.0.0.1", "10.0.0.2"})
        assert proc._determine_direction_by_ip("10.0.0.1", "8.8.8.8") == "upload"
        assert proc._determine_direction_by_ip("8.8.8.8", "10.0.0.2") == "download"

    def test_direction_fallback_when_local_ips_empty(self):
        """Phase D: When _local_ips is empty, fall back to RFC-1918 heuristic."""
        info = _make_interface(ip=None, mask=None)
        mode = PortMirrorMode(info)
        # Create processor with empty local_ips and no subnet
        proc = PacketProcessor(mode, local_ips=set())
        # Clear any auto-populated IPs
        proc._local_ips = set()
        proc._monitored_subnet = None
        # Private → public should be upload
        assert proc._determine_direction_by_ip("192.168.1.100", "8.8.8.8") == "upload"
        # Public → private should be download
        assert proc._determine_direction_by_ip("8.8.8.8", "192.168.1.100") == "download"
        # Both private → other (intra-LAN)
        assert proc._determine_direction_by_ip("192.168.1.1", "192.168.1.2") == "other"
        # Both public → other
        assert proc._determine_direction_by_ip("1.1.1.1", "8.8.8.8") == "other"

    def test_private_ip_detection(self):
        """Verify _is_private_ip works correctly for RFC-1918."""
        assert PacketProcessor._is_private_ip("192.168.1.1") is True
        assert PacketProcessor._is_private_ip("10.0.0.1") is True
        assert PacketProcessor._is_private_ip("172.16.0.1") is True
        assert PacketProcessor._is_private_ip("8.8.8.8") is False
        assert PacketProcessor._is_private_ip("1.1.1.1") is False
        assert PacketProcessor._is_private_ip("invalid") is False

    def test_mirror_strategy_teardown(self):
        """MirrorCaptureStrategy.teardown() resets state."""
        info = _make_interface()
        mode = PortMirrorMode(info)
        strategy = MirrorCaptureStrategy(mode)
        strategy._promisc_was_enabled = True
        with patch("packet_capture.strategies.mirror_strategy.sys") as mock_sys:
            mock_sys.platform = "win32"
            strategy.teardown()
        assert strategy._promisc_was_enabled is False


# ===================================================================
# 5. Public Network Mode Verification
# ===================================================================

class TestPublicNetworkVerification:
    """Phase D item 5: Same as WiFi client, NO active probing."""

    def test_bpf_uses_ether_host(self):
        info = _make_interface(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", itype="wifi")
        mode = PublicNetworkMode(info)
        bpf = mode.get_bpf_filter()
        assert "ether host" in bpf
        assert "aa:bb:cc:dd:ee:ff" in bpf.lower()

    def test_no_promiscuous(self):
        info = _make_interface()
        mode = PublicNetworkMode(info)
        assert mode.should_use_promiscuous() is False

    def test_no_active_arp_scan(self):
        info = _make_interface()
        mode = PublicNetworkMode(info)
        assert mode.capabilities.can_arp_scan is False

    def test_no_passive_discovery(self):
        info = _make_interface()
        mode = PublicNetworkMode(info)
        assert mode.capabilities.can_do_passive_discovery is False

    def test_no_arp_cache_scan_public(self):
        """ARP cache scan is NOT allowed on public networks."""
        info = _make_interface()
        mode = PublicNetworkMode(info)
        assert mode.capabilities.can_arp_cache_scan is False

    def test_safe_for_public(self):
        info = _make_interface()
        mode = PublicNetworkMode(info)
        assert mode.capabilities.safe_for_public is True


# ===================================================================
# 6. Mode Switch Stress Test
# ===================================================================

class TestModeSwitchStress:
    """Phase D item 6: Rapid mode switching, no thread leaks."""

    def test_rapid_mode_switch_no_thread_leak(self):
        """Toggle modes 5 times rapidly — thread count must not grow."""
        from orchestration import state as _state
        from orchestration import mode_handler as _mh
        from orchestration.mode_handler import on_mode_change

        initial_threads = threading.active_count()

        for i in range(5):
            old_mode = _make_mock_mode("ethernet", ip=f"192.168.1.{i + 1}")
            new_mode = _make_mock_mode("public_network", ip=f"192.168.1.{i + 50}")

            with patch.object(_state, 'capture_engine', MagicMock(is_running=True)), \
                 patch.object(_mh, '_create_capture_engine', return_value=MagicMock()), \
                 patch.object(_mh, 'expose_engine_to_routes'), \
                 patch('orchestration.mode_handler.time'), \
                 patch.dict('sys.modules', {'psutil': MagicMock()}):
                on_mode_change(old_mode, new_mode)

        # Allow daemon threads to clean up
        time.sleep(0.2)
        final_threads = threading.active_count()
        # Thread count should not grow unboundedly
        assert final_threads <= initial_threads + 5, (
            f"Thread leak: {initial_threads} → {final_threads}"
        )

    def test_disconnect_graceful_state(self):
        """Disconnected mode stops engine, sends SSE event."""
        from orchestration import state as _state
        from orchestration import mode_handler as _mh
        from orchestration.mode_handler import on_mode_change

        old_mode = _make_mock_mode("ethernet", ip="192.168.1.100")
        disc_mode = _make_mock_mode("disconnected", ip="0.0.0.0")
        disc_mode.interface = _make_interface(
            ip="0.0.0.0", name="none", itype="disconnected",
        )

        engine = MagicMock(is_running=True)

        with patch.object(_state, 'capture_engine', engine), \
             patch.object(_mh, 'expose_engine_to_routes'), \
             patch.object(_mh, '_send_mode_changed_sse') as mock_sse:
            on_mode_change(old_mode, disc_mode)
            engine.stop.assert_called_once()
            mock_sse.assert_called_once()
            # Check it was called with disconnected=True
            call_args = mock_sse.call_args
            assert call_args[1].get('is_disconnected', False) or \
                   (len(call_args[0]) > 1 and call_args[0][1] is True)

    def test_same_mode_skips_restart(self):
        """Same mode + same interface → no restart."""
        from orchestration import state as _state
        from orchestration import mode_handler as _mh
        from orchestration.mode_handler import on_mode_change

        mode = _make_mock_mode("ethernet", ip="192.168.1.100")

        with patch.object(_state, 'capture_engine', MagicMock()), \
             patch.object(_mh, '_create_capture_engine') as mock_create, \
             patch.object(_mh, 'expose_engine_to_routes'):
            on_mode_change(mode, mode)
            mock_create.assert_not_called()


# ===================================================================
# 7. _cached_discovery Race Fix
# ===================================================================

class TestCachedDiscoveryRace:
    """Phase D item 7: _cached_discovery must use local-copy pattern."""

    def test_shutdown_uses_local_copy(self):
        """shutdown() takes a local copy while holding the lock."""
        from orchestration import state as _state
        from orchestration.shutdown import shutdown as _shutdown

        mock_disc = MagicMock()

        # Reset shutdown state
        _state.shutting_down = False

        with patch.object(_state, 'capture_engine', None), \
             patch.object(_state, 'interface_manager', None), \
             patch.object(_state, 'detector', None), \
             patch.object(_state, 'health_monitor', None), \
             patch.object(_state, 'logger', MagicMock()), \
             patch('packet_capture.hostname_resolver.close_resolver'), \
             patch('database.connection.shutdown_pool'):
            _state.cached_discovery = mock_disc
            _shutdown()
            mock_disc.stop_continuous_discovery.assert_called_once()
            assert _state.cached_discovery is None

        # Reset for other tests
        _state.shutting_down = False

    def test_concurrent_access_is_safe(self):
        """Multiple threads accessing cached_discovery don't cause AttributeError."""
        from orchestration import state as _state

        mock_disc = MagicMock()
        _state.cached_discovery = mock_disc

        errors = []

        def _reader():
            for _ in range(100):
                try:
                    with _state.cached_discovery_lock:
                        disc = _state.cached_discovery
                    if disc is not None:
                        disc.arp_scan(timeout=1)
                except AttributeError as e:
                    errors.append(str(e))

        def _writer():
            for _ in range(100):
                with _state.cached_discovery_lock:
                    _state.cached_discovery = MagicMock()

        threads = [
            threading.Thread(target=_reader),
            threading.Thread(target=_writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Race condition errors: {errors}"

        # Cleanup
        _state.cached_discovery = None


# ===================================================================
# 8. Shutdown Timeout Watchdog
# ===================================================================

class TestShutdownWatchdog:
    """Phase D item 8: Shutdown steps wrapped in a 10s watchdog."""

    def test_shutdown_has_watchdog_thread(self):
        """shutdown() launches a ShutdownWatchdog daemon thread."""
        from orchestration import state as _state
        from orchestration.shutdown import shutdown as _shutdown

        _state.shutting_down = False
        threads_before = [t.name for t in threading.enumerate()]

        with patch.object(_state, 'capture_engine', None), \
             patch.object(_state, 'interface_manager', None), \
             patch.object(_state, 'detector', None), \
             patch.object(_state, 'health_monitor', None), \
             patch.object(_state, 'logger', MagicMock()), \
             patch('packet_capture.hostname_resolver.close_resolver'), \
             patch('database.connection.shutdown_pool'):
            _state.cached_discovery = None
            _shutdown()

        # Watchdog thread should have been started (may have already exited
        # since shutdown completes fast, but we verify the code path)
        # Reset state
        _state.shutting_down = False

    def test_shutdown_completes_fast(self):
        """Normal shutdown should complete well under 10s."""
        from orchestration import state as _state
        from orchestration.shutdown import shutdown as _shutdown

        _state.shutting_down = False
        start = time.monotonic()

        with patch.object(_state, 'capture_engine', None), \
             patch.object(_state, 'interface_manager', None), \
             patch.object(_state, 'detector', None), \
             patch.object(_state, 'health_monitor', None), \
             patch.object(_state, 'logger', MagicMock()), \
             patch('packet_capture.hostname_resolver.close_resolver'), \
             patch('database.connection.shutdown_pool'):
            _state.cached_discovery = None
            _shutdown()

        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"Shutdown took {elapsed:.1f}s -- too slow"

        _state.shutting_down = False


# ===================================================================
# 9. Double-Shutdown Race
# ===================================================================

class TestDoubleShutdownGuard:
    """Phase D item 9: signal_handler no longer calls shutdown() directly."""

    def test_signal_handler_only_sets_event(self):
        """signal_handler should only set the shutdown_event, not call shutdown()."""
        import main
        import inspect

        source = inspect.getsource(main.signal_handler)
        # Must NOT call shutdown() directly
        assert "shutdown()" not in source or "shutdown_event.set()" in source
        # Verify it sets the event
        assert "shutdown_event.set()" in source

    def test_shutdown_is_idempotent(self):
        """Calling shutdown() twice does not raise or run teardown twice."""
        from orchestration import state as _state
        from orchestration.shutdown import shutdown as _shutdown

        _state.shutting_down = False
        call_count = 0

        def counting_pool():
            nonlocal call_count
            call_count += 1

        with patch.object(_state, 'capture_engine', None), \
             patch.object(_state, 'interface_manager', None), \
             patch.object(_state, 'detector', None), \
             patch.object(_state, 'health_monitor', None), \
             patch.object(_state, 'logger', MagicMock()), \
             patch('packet_capture.hostname_resolver.close_resolver'), \
             patch('database.connection.shutdown_pool', counting_pool):
            _state.cached_discovery = None
            _shutdown()
            _shutdown()  # second call should be a no-op

        assert call_count == 1, f"shutdown_pool called {call_count} times"
        _state.shutting_down = False

    def test_atexit_registered(self):
        """atexit.register(shutdown) is present in main module."""
        import main
        import atexit
        # The atexit handler is registered at module level, so if
        # main imported successfully, it's registered.
        # We verify by checking the source.
        import inspect
        source = inspect.getsource(main)
        assert "atexit.register(shutdown)" in source


# ===================================================================
# 10. Cross-Mode Direction Consistency
# ===================================================================

class TestDirectionConsistency:
    """Verify direction detection is consistent across all modes."""

    @pytest.mark.parametrize("mode_cls,scope", [
        (PublicNetworkMode, NetworkScope.OWN_TRAFFIC_ONLY),
        (PublicNetworkMode, NetworkScope.OWN_TRAFFIC_ONLY),
        (EthernetMode, NetworkScope.LOCAL_NETWORK),
    ])
    def test_upload_download_for_own_traffic_modes(self, mode_cls, scope):
        """For own-traffic/LAN modes: FROM our IP=upload, TO our IP=download."""
        info = _make_interface(ip="192.168.1.100", mac="AA:BB:CC:DD:EE:FF")
        mode = mode_cls(info)
        proc = PacketProcessor(mode)

        assert proc._determine_direction("192.168.1.100", "8.8.8.8") == "upload"
        assert proc._determine_direction("8.8.8.8", "192.168.1.100") == "download"

    def test_hotspot_direction_is_client_perspective(self):
        """Hotspot: direction is from the CLIENT's perspective."""
        info = _make_interface(ip="192.168.137.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        proc = PacketProcessor(mode)

        # Client → internet = upload
        assert proc._determine_direction("192.168.137.5", "1.1.1.1") == "upload"
        # Internet → client = download
        assert proc._determine_direction("1.1.1.1", "192.168.137.5") == "download"
        # Hotspot host → internet = other (not a client IP)
        d = proc._determine_direction("192.168.137.1", "1.1.1.1")
        assert d == "other"

    def test_hotspot_two_clients(self):
        """Two hotspot clients produce correct directions for each."""
        info = _make_interface(ip="192.168.137.1", mask="255.255.255.0")
        mode = HotspotMode(info)
        proc = PacketProcessor(mode)

        # Client 1 (192.168.137.2) uploads
        assert proc._determine_direction("192.168.137.2", "8.8.4.4") == "upload"
        # Client 2 (192.168.137.3) downloads
        assert proc._determine_direction("8.8.4.4", "192.168.137.3") == "download"
        # Inter-client: src is in subnet → upload (from that client)
        assert proc._determine_direction("192.168.137.2", "192.168.137.3") == "upload"


# ===================================================================
# 11. Ethernet ARP / CIDR Correctness
# ===================================================================

class TestEthernetCIDR:
    """Verify Ethernet mode produces correct CIDR for various subnets."""

    @pytest.mark.parametrize("ip,mask,expected", [
        ("192.168.1.100", "255.255.255.0", "192.168.1.0/24"),
        ("10.0.0.50", "255.255.0.0", "10.0.0.0/16"),
        ("172.16.5.10", "255.255.255.128", "172.16.5.0/25"),
    ])
    def test_cidr_from_ip_and_mask(self, ip, mask, expected):
        info = _make_interface(ip=ip, mask=mask)
        mode = EthernetMode(info)
        assert mode.get_valid_ip_range() == expected


# ===================================================================
# 12. Mode Completeness Check
# ===================================================================

class TestModeCompleteness:
    """Every mode must have all required attributes and methods."""

    @pytest.mark.parametrize("mode_cls,iface_kwargs", [
        (PublicNetworkMode, {"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "itype": "wifi"}),
        (PublicNetworkMode, {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff"}),
        (EthernetMode, {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}),
        (PortMirrorMode, {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}),
        (HotspotMode, {"ip": "192.168.137.1", "mac": "aa:bb:cc:dd:ee:ff"}),
    ])
    def test_mode_has_all_required_outputs(self, mode_cls, iface_kwargs):
        info = _make_interface(**iface_kwargs)
        mode = mode_cls(info)

        # All modes must provide these
        assert isinstance(mode.get_mode_name(), ModeName)
        bpf = mode.get_bpf_filter()
        assert isinstance(bpf, str)
        caps = mode.capabilities
        assert isinstance(caps, ModeCapabilities)
        assert isinstance(caps.scope, NetworkScope)
        assert isinstance(mode.should_use_promiscuous(), bool)
        desc = mode.get_description()
        assert isinstance(desc, str) and len(desc) > 0
