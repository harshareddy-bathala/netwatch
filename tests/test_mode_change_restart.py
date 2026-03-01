"""
test_mode_change_restart.py - Mode Change & Capture Restart Tests
===================================================================

Verifies that:
- ``on_mode_change()`` properly stops the old engine and starts a new one
- The ``engine_lock`` prevents race conditions
- Disconnected networks pause capture gracefully
- Subnet cache is reset on mode change
"""

import sys
import os
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestration import state
from orchestration import mode_handler
from orchestration.mode_handler import on_mode_change


def _make_mode(name, ip="192.168.1.100", iface="eth0", iface_type="ethernet"):
    """Create a mock NetworkMode."""
    from packet_capture.modes.base_mode import InterfaceInfo
    info = InterfaceInfo(
        name=iface, friendly_name=iface,
        ip_address=ip, mac_address="AA:BB:CC:DD:EE:FF",
        netmask="255.255.255.0", gateway="192.168.1.1",
        ssid=None, interface_type=iface_type, is_active=True,
    )
    mode = MagicMock()
    mode.interface = info
    mode.get_mode_name.return_value = MagicMock(value=name)
    mode.get_bpf_filter.return_value = "ip"
    mode.should_use_promiscuous.return_value = False
    return mode


class TestModeChangeRestart:
    """Integration tests for on_mode_change."""

    def test_engine_stopped_on_mode_change(self):
        """Old engine should be stopped when mode changes."""
        old_engine = MagicMock()
        old_engine.is_running = True

        old_mode = _make_mode("ethernet", ip="192.168.1.100")
        new_mode = _make_mode("public_network", ip="192.168.1.50", iface="wlan0")

        with patch.object(state, 'capture_engine', old_engine), \
             patch.object(mode_handler, '_create_capture_engine') as mock_create, \
             patch.object(mode_handler, 'expose_engine_to_routes'), \
             patch('orchestration.mode_handler.time'), \
             patch.dict('sys.modules', {'psutil': MagicMock()}):
            mock_new_engine = MagicMock()
            mock_create.return_value = mock_new_engine

            on_mode_change(old_mode, new_mode)

            old_engine.stop.assert_called_once()

    def test_new_engine_started_on_mode_change(self):
        """New engine should be created and started."""
        old_engine = MagicMock()
        old_engine.is_running = True

        old_mode = _make_mode("ethernet", ip="192.168.1.100")
        new_mode = _make_mode("public_network", ip="192.168.1.50", iface="wlan0")

        with patch.object(state, 'capture_engine', old_engine), \
             patch.object(mode_handler, '_create_capture_engine') as mock_create, \
             patch.object(mode_handler, 'expose_engine_to_routes'), \
             patch('orchestration.mode_handler.time'), \
             patch.dict('sys.modules', {'psutil': MagicMock()}):
            mock_new_engine = MagicMock()
            mock_create.return_value = mock_new_engine

            on_mode_change(old_mode, new_mode)

            mock_create.assert_called_once_with(new_mode)
            mock_new_engine.start.assert_called_once()

    def test_no_restart_when_mode_unchanged(self):
        """If the mode hasn't actually changed, skip restart."""
        mode = _make_mode("ethernet", ip="192.168.1.100")

        with patch.object(state, 'capture_engine', MagicMock()), \
             patch.object(mode_handler, '_create_capture_engine') as mock_create, \
             patch.object(mode_handler, 'expose_engine_to_routes'):
            # Same old_mode and new_mode
            on_mode_change(mode, mode)

            # Should NOT create a new engine
            mock_create.assert_not_called()

    def test_disconnect_stops_engine(self):
        """Disconnected network (0.0.0.0) should stop engine and set to None."""
        old_engine = MagicMock()
        old_engine.is_running = True

        old_mode = _make_mode("ethernet", ip="192.168.1.100")
        disconnected_mode = _make_mode("disconnected", ip="0.0.0.0", iface="none", iface_type="disconnected")

        with patch.object(state, 'capture_engine', old_engine), \
             patch.object(mode_handler, 'expose_engine_to_routes'):
            on_mode_change(old_mode, disconnected_mode)

            old_engine.stop.assert_called_once()

    def test_engine_lock_prevents_concurrent_mutation(self):
        """Concurrent mode changes should not interleave."""
        call_order = []

        def slow_locked(old, new):
            call_order.append('enter')
            time.sleep(0.1)
            call_order.append('exit')

        old_mode = _make_mode("ethernet")
        new_mode1 = _make_mode("public_network", ip="192.168.1.50")
        new_mode2 = _make_mode("hotspot", ip="192.168.137.1")

        with patch.object(mode_handler, '_on_mode_change_locked', side_effect=slow_locked):
            t1 = threading.Thread(target=on_mode_change, args=(old_mode, new_mode1))
            t2 = threading.Thread(target=on_mode_change, args=(old_mode, new_mode2))
            t1.start()
            time.sleep(0.01)  # give t1 a head start
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        # The lock should ensure enter/exit pairs are contiguous
        assert call_order == ['enter', 'exit', 'enter', 'exit'], \
            f"Calls interleaved: {call_order}"

    def test_expose_engine_called_after_restart(self):
        """Flask routes should see the new engine via expose_engine_to_routes."""
        old_engine = MagicMock()
        old_engine.is_running = True

        old_mode = _make_mode("ethernet", ip="192.168.1.100")
        new_mode = _make_mode("public_network", ip="192.168.1.50", iface="wlan0")

        with patch.object(state, 'capture_engine', old_engine), \
             patch.object(mode_handler, '_create_capture_engine') as mock_create, \
             patch.object(mode_handler, 'expose_engine_to_routes') as mock_expose, \
             patch('orchestration.mode_handler.time'), \
             patch.dict('sys.modules', {'psutil': MagicMock()}):
            mock_create.return_value = MagicMock()

            on_mode_change(old_mode, new_mode)

            mock_expose.assert_called()

    def test_subnet_reset_on_mode_change(self):
        """Subnet cache should be reset when mode changes."""
        old_engine = MagicMock()
        old_engine.is_running = True

        old_mode = _make_mode("ethernet", ip="192.168.1.100")
        new_mode = _make_mode("public_network", ip="10.0.0.50", iface="wlan0")

        with patch.object(state, 'capture_engine', old_engine), \
             patch.object(mode_handler, '_create_capture_engine') as mock_create, \
             patch.object(mode_handler, 'expose_engine_to_routes'), \
             patch('orchestration.mode_handler.time'), \
             patch.dict('sys.modules', {'psutil': MagicMock()}), \
             patch('database.queries.device_queries.reset_subnet_cache') as mock_reset:
            mock_create.return_value = MagicMock()

            on_mode_change(old_mode, new_mode)

            mock_reset.assert_called_once()
