"""
conftest.py - Shared Pytest Fixtures for NetWatch Tests
=========================================================

Provides test database, Flask test client, mock modes, and other
reusable fixtures used across the entire test suite.
"""

import os
import sys
import tempfile
import threading
import sqlite3
import json
import time
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Force testing environment
os.environ['NETWATCH_ENV'] = 'testing'


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

# Path to the real schema file
_SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "database", "schema.sql",
)


@pytest.fixture
def db_path(tmp_path):
    """Return a temporary database file path."""
    return str(tmp_path / "test_netwatch.db")


@pytest.fixture
def initialized_db(db_path):
    """
    Create and initialize a temporary test database.

    Bypasses ``init_db.initialize_database`` (which binds DATABASE_PATH
    at import time) by reading schema.sql directly, then re-points the
    global connection pool at the temp file so every ``get_connection()``
    call in production code uses the test DB.
    """
    import config
    original = config.DATABASE_PATH
    config.DATABASE_PATH = db_path

    # Create schema directly — avoids stale module-level import of DATABASE_PATH
    conn = sqlite3.connect(db_path)
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.close()

    # Point the global connection pool at the temp database
    from database.connection import init_pool, shutdown_pool
    init_pool(db_path, pool_size=2)

    yield db_path

    shutdown_pool()
    config.DATABASE_PATH = original

    # Cleanup
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


@pytest.fixture
def db_connection(initialized_db):
    """Provide a raw sqlite3 connection to the test database."""
    conn = sqlite3.connect(initialized_db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    yield conn
    conn.close()


@pytest.fixture
def connection_pool(initialized_db):
    """Initialize and return a connection pool for the test database."""
    from database.connection import init_pool, shutdown_pool
    pool = init_pool(initialized_db, pool_size=2)
    yield pool
    shutdown_pool()


# ---------------------------------------------------------------------------
# Flask app fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app(initialized_db):
    """Create a Flask test application."""
    import config
    config.DATABASE_PATH = initialized_db

    from backend.app import create_app
    application = create_app()
    application.config['TESTING'] = True
    return application


@pytest.fixture
def client(app):
    """Provide a Flask test client."""
    return app.test_client()


# ---------------------------------------------------------------------------
# Mode / Interface mocks
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_interface_info():
    """Create a mock InterfaceInfo."""
    from packet_capture.modes.base_mode import InterfaceInfo
    return InterfaceInfo(
        name="eth0",
        friendly_name="Ethernet",
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        netmask="255.255.255.0",
        gateway="192.168.1.1",
        ssid=None,
        interface_type="ethernet",
        is_active=True,
    )


@pytest.fixture
def mock_hotspot_info():
    """Create a mock hotspot InterfaceInfo."""
    from packet_capture.modes.base_mode import InterfaceInfo
    return InterfaceInfo(
        name="wlan0",
        friendly_name="Wi-Fi",
        ip_address="192.168.137.1",
        mac_address="AA:BB:CC:11:22:33",
        netmask="255.255.255.0",
        gateway=None,
        ssid="MyHotspot",
        interface_type="wifi",
        is_active=True,
    )


@pytest.fixture
def mock_wifi_info():
    """Create a mock WiFi client InterfaceInfo."""
    from packet_capture.modes.base_mode import InterfaceInfo
    return InterfaceInfo(
        name="wlan0",
        friendly_name="Wi-Fi",
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:44:55:66",
        netmask="255.255.255.0",
        gateway="192.168.1.1",
        ssid="HomeNetwork",
        interface_type="wifi",
        is_active=True,
    )


@pytest.fixture
def ethernet_mode(mock_interface_info):
    """Create an EthernetMode instance."""
    from packet_capture.modes.ethernet_mode import EthernetMode
    return EthernetMode(mock_interface_info)


@pytest.fixture
def hotspot_mode(mock_hotspot_info):
    """Create a HotspotMode instance."""
    from packet_capture.modes.hotspot_mode import HotspotMode
    return HotspotMode(mock_hotspot_info)


@pytest.fixture
def wifi_mode(mock_wifi_info):
    """Create a PublicNetworkMode instance for WiFi client scenarios."""
    from packet_capture.modes.public_network_mode import PublicNetworkMode
    return PublicNetworkMode(mock_wifi_info)


@pytest.fixture
def public_mode(mock_wifi_info):
    """Create a PublicNetworkMode instance."""
    from packet_capture.modes.public_network_mode import PublicNetworkMode
    return PublicNetworkMode(mock_wifi_info)


# ---------------------------------------------------------------------------
# Alert fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def alert_engine(initialized_db):
    """Create an AlertEngine connected to the test database."""
    from alerts.alert_engine import AlertEngine
    return AlertEngine()


@pytest.fixture
def anomaly_detector(alert_engine):
    """Create an AnomalyDetector with a test alert engine."""
    from alerts.anomaly_detector import AnomalyDetector
    return AnomalyDetector(alert_engine=alert_engine)


# ---------------------------------------------------------------------------
# Packet fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_packet_data():
    """Return a sample PacketData dict."""
    return {
        "timestamp": datetime.now().isoformat(),
        "source_ip": "192.168.1.100",
        "dest_ip": "8.8.8.8",
        "source_port": 54321,
        "dest_port": 443,
        "protocol": "HTTPS",
        "raw_protocol": "TCP",
        "bytes_transferred": 1500,
        "direction": "upload",
        "source_mac": "AA:BB:CC:DD:EE:FF",
        "dest_mac": "11:22:33:44:55:66",
    }


@pytest.fixture
def sample_packets_batch():
    """Return a batch of sample packet dicts."""
    packets = []
    for i in range(100):
        packets.append({
            "timestamp": datetime.now().isoformat(),
            "source_ip": f"192.168.1.{(i % 254) + 1}",
            "dest_ip": "8.8.8.8",
            "source_port": 50000 + i,
            "dest_port": 443,
            "protocol": "HTTPS",
            "raw_protocol": "TCP",
            "bytes_transferred": 1000 + i * 10,
            "direction": "upload" if i % 2 == 0 else "download",
            "source_mac": f"AA:BB:CC:DD:{i % 256:02X}:FF",
            "dest_mac": "11:22:33:44:55:66",
        })
    return packets


# ---------------------------------------------------------------------------
# Timing / performance helpers
# ---------------------------------------------------------------------------

class Timer:
    """Simple context-managed timer for performance tests."""

    def __init__(self):
        self.elapsed = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed = (time.perf_counter() - self._start) * 1000  # ms


@pytest.fixture
def timer():
    """Provide a Timer helper."""
    return Timer
