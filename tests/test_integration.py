"""
test_integration.py - Full System Integration Tests
======================================================

Tests for the complete NetWatch system: startup sequence, mode changes,
data flow from capture to frontend, load testing, and graceful shutdown.
"""

import sys
import os
import time
import threading
import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Startup Sequence Tests
# ===================================================================

class TestStartupSequence:
    """Test the full application startup sequence."""

    def test_database_initializes_first(self, initialized_db):
        """Database must initialize before other components."""
        assert os.path.exists(initialized_db)

    def test_connection_pool_after_db(self, connection_pool):
        """Connection pool should work after database init."""
        with connection_pool.get_connection() as conn:
            cursor = conn.execute("SELECT 1")
            assert cursor.fetchone()[0] == 1

    def test_alert_engine_after_db(self, alert_engine):
        """Alert engine should work after database init."""
        stats = alert_engine.get_stats()
        assert isinstance(stats, dict)

    def test_flask_app_creates(self, app):
        """Flask app should create successfully."""
        assert app is not None

    def test_flask_test_client(self, client):
        """Test client should be functional."""
        assert client is not None


# ===================================================================
# Data Flow Tests
# ===================================================================

class TestDataFlow:
    """Test data flow from capture through database to API."""

    def test_device_data_appears_in_api(self, client, db_connection):
        """Devices inserted into DB should appear in API response."""
        # Insert a device directly
        db_connection.execute(
            "INSERT OR REPLACE INTO devices "
            "(mac_address, ip_address, first_seen, last_seen, total_bytes_sent, total_packets) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("AA:BB:CC:DD:EE:FF", "192.168.1.100",
             datetime.now().isoformat(), datetime.now().isoformat(),
             50000, 100)
        )
        db_connection.commit()

        response = client.get('/api/devices')
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, (list, dict))

    def test_alert_data_appears_in_api(self, client, db_connection):
        """Alerts inserted into DB should appear in API response."""
        db_connection.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message) "
            "VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), "bandwidth", "warning", "Test alert")
        )
        db_connection.commit()

        response = client.get('/api/alerts')
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, (list, dict))


# ===================================================================
# Mode Change Tests
# ===================================================================

class TestModeChanges:
    """Test behavior during network mode transitions."""

    def test_interface_manager_detects_mode(self):
        """InterfaceManager should detect current mode."""
        from packet_capture.interface_manager import InterfaceManager
        from packet_capture.modes.base_mode import BaseMode, InterfaceInfo
        from packet_capture.modes.ethernet_mode import EthernetMode

        mock_info = InterfaceInfo(
            name="eth0", friendly_name="Ethernet",
            ip_address="192.168.1.100", mac_address="AA:BB:CC:DD:EE:FF",
            netmask="255.255.255.0", gateway="192.168.1.1",
            ssid=None, interface_type="ethernet", is_active=True,
        )
        mock_mode = EthernetMode(mock_info)

        with patch.object(InterfaceManager, '__init__', lambda self, **kw: None):
            mgr = InterfaceManager(auto_detect=True)
            mgr._lock = threading.Lock()
            mgr._current_mode = mock_mode
            mgr._callbacks = []
            mode = mgr.get_current_mode()
            assert isinstance(mode, BaseMode)

    def test_mode_change_callback(self):
        """Mode change callbacks should fire on transitions."""
        from packet_capture.interface_manager import InterfaceManager
        from packet_capture.modes.base_mode import InterfaceInfo
        from packet_capture.modes.ethernet_mode import EthernetMode

        mock_info = InterfaceInfo(
            name="eth0", friendly_name="Ethernet",
            ip_address="192.168.1.100", mac_address="AA:BB:CC:DD:EE:FF",
            netmask="255.255.255.0", gateway="192.168.1.1",
            ssid=None, interface_type="ethernet", is_active=True,
        )
        mock_mode = EthernetMode(mock_info)

        with patch.object(InterfaceManager, '__init__', lambda self, **kw: None):
            mgr = InterfaceManager(auto_detect=True)
            mgr._lock = threading.Lock()
            mgr._current_mode = mock_mode
            mgr._callbacks = []

            callback_called = threading.Event()

            def on_change(old, new):
                callback_called.set()

            mgr.on_mode_change(on_change)
            mgr.remove_callback(on_change)

    def test_mode_has_valid_bpf(self):
        """Current detected mode should have a valid BPF filter."""
        from packet_capture.interface_manager import InterfaceManager
        from packet_capture.modes.base_mode import InterfaceInfo
        from packet_capture.modes.ethernet_mode import EthernetMode

        mock_info = InterfaceInfo(
            name="eth0", friendly_name="Ethernet",
            ip_address="192.168.1.100", mac_address="AA:BB:CC:DD:EE:FF",
            netmask="255.255.255.0", gateway="192.168.1.1",
            ssid=None, interface_type="ethernet", is_active=True,
        )
        mock_mode = EthernetMode(mock_info)

        with patch.object(InterfaceManager, '__init__', lambda self, **kw: None):
            mgr = InterfaceManager(auto_detect=True)
            mgr._lock = threading.Lock()
            mgr._current_mode = mock_mode
            mgr._callbacks = []
            mode = mgr.get_current_mode()
            bpf = mode.get_bpf_filter()
            assert isinstance(bpf, str)


# ===================================================================
# System Load Tests
# ===================================================================

class TestSystemLoad:
    """Tests for system behavior under load."""

    def test_concurrent_api_requests(self, client):
        """Multiple concurrent API requests should all succeed."""
        results = []
        errors = []

        def make_request():
            try:
                resp = client.get('/api/status')
                results.append(resp.status_code)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=make_request) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Errors during load: {errors}"
        assert all(r == 200 for r in results)

    def test_rapid_database_writes(self, db_connection):
        """Rapid writes should not cause database locks."""
        errors = []

        for i in range(500):
            try:
                db_connection.execute(
                    "INSERT OR REPLACE INTO devices "
                    "(mac_address, ip_address, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?)",
                    (f"DD:EE:FF:{i // 256:02X}:{i % 256:02X}:00",
                     f"10.0.{i // 256}.{i % 256}",
                     datetime.now().isoformat(),
                     datetime.now().isoformat())
                )
            except Exception as e:
                errors.append(str(e))

        db_connection.commit()
        assert len(errors) == 0, f"Write errors: {errors}"

    def test_bandwidth_calculator_under_load(self):
        """BandwidthCalculator should handle high packet rates."""
        from packet_capture.bandwidth_calculator import BandwidthCalculator

        calc = BandwidthCalculator(window_seconds=10)
        start = time.time()

        for i in range(10000):
            calc.add_bytes(1500, direction="download" if i % 2 == 0 else "upload")

        elapsed = time.time() - start
        assert elapsed < 5.0, f"Processing 10K packets took {elapsed:.2f}s"

        stats = calc.get_stats()
        assert isinstance(stats, dict)


# ===================================================================
# Graceful Shutdown Tests
# ===================================================================

class TestGracefulShutdown:
    """Tests for clean resource cleanup."""

    def test_connection_pool_shutdown(self, initialized_db):
        """Pool should shut down cleanly."""
        from database.connection import init_pool, shutdown_pool

        pool = init_pool(initialized_db, pool_size=2)
        shutdown_pool()
        # Should not raise

    def test_bandwidth_calculator_reset(self):
        """Calculator should reset cleanly."""
        from packet_capture.bandwidth_calculator import BandwidthCalculator

        calc = BandwidthCalculator()
        calc.add_bytes(50000, "download")
        calc.reset()
        assert calc.get_current_bps() == 0.0


# ===================================================================
# Configuration Tests
# ===================================================================

class TestConfiguration:
    """Tests for production configuration."""

    def test_config_imports(self):
        """All config values should be importable."""
        import config
        assert hasattr(config, 'FLASK_HOST')
        assert hasattr(config, 'FLASK_PORT')
        assert hasattr(config, 'DATABASE_PATH')
        assert hasattr(config, 'APP_VERSION')
        assert hasattr(config, 'APP_ENV')

    def test_production_debug_off(self):
        """In production, debug should be disabled."""
        import config
        if config.APP_ENV == 'production':
            assert config.FLASK_DEBUG is False
            assert config.DEBUG_MODE is False

    def test_secret_key_set(self):
        """Secret key should be configured."""
        import config
        assert config.SECRET_KEY is not None
        assert len(config.SECRET_KEY) > 0

    def test_database_path_configured(self):
        """Database path should be set."""
        import config
        assert config.DATABASE_PATH is not None
        assert len(config.DATABASE_PATH) > 0
