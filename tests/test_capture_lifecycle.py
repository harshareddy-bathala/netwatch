"""
test_capture_lifecycle.py - CaptureEngine Lifecycle Tests (#58)
================================================================

Tests for CaptureEngine init, start/stop, stats, and filter summary.
All Scapy/network calls are mocked.
"""

import sys
import os
import time
import threading
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.modes.base_mode import InterfaceInfo
from packet_capture.modes.ethernet_mode import EthernetMode


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def eth_mode():
    info = InterfaceInfo(
        name="eth0", friendly_name="Ethernet",
        ip_address="192.168.1.100", mac_address="AA:BB:CC:DD:EE:FF",
        netmask="255.255.255.0", gateway="192.168.1.1",
        ssid=None, interface_type="ethernet", is_active=True,
    )
    return EthernetMode(info)


@pytest.fixture
def engine(eth_mode):
    from packet_capture.capture_engine import CaptureEngine
    return CaptureEngine(
        mode=eth_mode,
        interface="eth0",
        queue_size=100,
        batch_size=10,
    )


# ===================================================================
# Initialisation
# ===================================================================

class TestEngineInit:

    def test_engine_created(self, engine):
        assert engine is not None

    def test_engine_not_running_initially(self, engine):
        assert engine.is_running is False

    def test_engine_stats_dict(self, engine):
        stats = engine.get_stats()
        assert isinstance(stats, dict)

    def test_engine_filter_summary(self, engine):
        summary = engine.get_filter_summary()
        assert isinstance(summary, dict)


# ===================================================================
# Start / Stop lifecycle
# ===================================================================

class TestLifecycle:

    @patch("packet_capture.capture_engine.scapy_sniff")
    @patch("packet_capture.capture_engine.SCAPY_AVAILABLE", True)
    def test_start_and_stop(self, mock_sniff, engine):
        """Engine should start capture/process threads and stop cleanly."""
        # Make sniff block briefly then exit
        mock_sniff.side_effect = lambda **kw: time.sleep(0.1)

        engine.start()
        # Give threads time to start
        time.sleep(0.2)
        assert engine.is_running is True

        engine.stop(timeout=3)
        assert engine.is_running is False

    @patch("packet_capture.capture_engine.SCAPY_AVAILABLE", False)
    def test_start_without_scapy_raises(self, engine):
        with pytest.raises(RuntimeError, match="Scapy"):
            engine.start()

    @patch("packet_capture.capture_engine.scapy_sniff")
    @patch("packet_capture.capture_engine.SCAPY_AVAILABLE", True)
    def test_double_start_is_safe(self, mock_sniff, engine):
        """Calling start() twice should not spawn extra threads."""
        mock_sniff.side_effect = lambda **kw: time.sleep(0.1)

        engine.start()
        time.sleep(0.15)
        engine.start()  # Should log warning, not crash
        engine.stop(timeout=3)


# ===================================================================
# Callback registration
# ===================================================================

class TestCallbacks:

    def test_register_callback(self, engine):
        calls = []
        engine.on_packet(lambda pkt: calls.append(pkt))
        assert len(engine._callbacks) == 1


# ===================================================================
# Stats after activity
# ===================================================================

class TestStatsTracking:

    def test_initial_stats_zeros(self, engine):
        stats = engine.get_stats()
        assert stats.get("packets_captured", 0) == 0
        assert stats.get("packets_dropped", 0) == 0
