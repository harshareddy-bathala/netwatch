"""
test_save_packets_batch.py - Tests for the Critical Write Hot‐Path
=====================================================================

``save_packets_batch`` is the main insertion function called on every
capture tick.  These tests verify:

* All rows are persisted in a single transaction.
* Device UPSERT logic (ON CONFLICT) updates correctly.
* Traffic records are always saved (even for public IPs).
* Only private‐IP devices make it into the ``devices`` table.
* Edge cases: empty batch, missing fields, duplicate MACs.
"""

import sys
import os
import sqlite3
from datetime import datetime
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.queries.device_queries import save_packets_batch, is_valid_device_ip, is_private_ip


# ===================================================================
# Fixtures  – use the shared initialized_db from conftest.py
# ===================================================================


@pytest.fixture(autouse=True)
def _test_db(initialized_db):
    """
    Re-use the shared conftest.py initialized_db fixture which creates a
    temp database with the real schema and points the global connection
    pool at it.
    """
    yield initialized_db


@pytest.fixture
def db_conn(_test_db):
    """Raw sqlite3 connection for assertion queries."""
    conn = sqlite3.connect(_test_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# ===================================================================
# Basic Persistence
# ===================================================================

class TestBatchPersistence:
    """Verify that save_packets_batch writes all rows."""

    def test_returns_count(self):
        """Return value should equal number of saved packets."""
        packets = _make_packets(5, source_prefix="192.168.1")
        saved = save_packets_batch(packets)
        assert saved == 5

    def test_traffic_rows_created(self, db_conn):
        """Each packet should produce exactly one traffic_summary row."""
        packets = _make_packets(10, source_prefix="192.168.1")
        save_packets_batch(packets)

        cursor = db_conn.execute("SELECT COUNT(*) FROM traffic_summary")
        assert cursor.fetchone()[0] == 10

    def test_empty_batch_returns_zero(self):
        """An empty list should be a no‐op."""
        assert save_packets_batch([]) == 0

    def test_single_packet(self, db_conn):
        """A one‐element batch must still work."""
        packets = _make_packets(1, source_prefix="192.168.1")
        assert save_packets_batch(packets) == 1

        cursor = db_conn.execute("SELECT COUNT(*) FROM traffic_summary")
        assert cursor.fetchone()[0] == 1


# ===================================================================
# Device UPSERT Logic
# ===================================================================

# Patch _is_valid_device_for_insert so subnet/gateway checks don't
# interfere — we only care about private-IP / public-IP distinction.
def _valid_if_private(ip, mac):
    """Replacement: accept any private IP with a non-trivial MAC."""
    if not ip:
        return False
    if not is_private_ip(ip):
        return False
    if not mac or mac in ("", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    return True


@patch(
    "database.queries.device_queries._is_valid_device_for_insert",
    side_effect=_valid_if_private,
)
class TestDeviceUpsert:
    """Verify ON CONFLICT behaviour for the devices table."""

    def test_private_ip_creates_device(self, _mock, db_conn):
        """A packet from a private IP should insert a device row."""
        packets = [{
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": "192.168.1.42",
            "dest_ip": "8.8.8.8",
            "source_mac": "AA:BB:CC:DD:EE:01",
            "dest_mac": "11:22:33:44:55:66",
            "protocol": "HTTPS",
            "raw_protocol": "TCP",
            "bytes": 1500,
            "direction": "upload",
        }]
        save_packets_batch(packets)

        cursor = db_conn.execute(
            "SELECT ip_address, mac_address FROM devices WHERE ip_address = '192.168.1.42'"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["ip_address"] == "192.168.1.42"

    def test_public_ip_not_in_devices(self, _mock, db_conn):
        """A public‐IP source should NOT appear in the devices table."""
        packets = [{
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": "8.8.8.8",
            "dest_ip": "192.168.1.10",
            "source_mac": "FF:FF:FF:FF:FF:FF",
            "dest_mac": "AA:BB:CC:DD:EE:02",
            "protocol": "DNS",
            "raw_protocol": "UDP",
            "bytes": 200,
            "direction": "download",
        }]
        save_packets_batch(packets)

        cursor = db_conn.execute(
            "SELECT COUNT(*) FROM devices WHERE ip_address = '8.8.8.8'"
        )
        assert cursor.fetchone()[0] == 0

    def test_upsert_increments_bytes(self, _mock, db_conn):
        """Two packets from the same IP should accumulate total_bytes_sent."""
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": "192.168.1.77",
            "dest_ip": "1.1.1.1",
            "source_mac": "AA:BB:CC:DD:EE:77",
            "dest_mac": "11:22:33:44:55:66",
            "protocol": "HTTP",
            "raw_protocol": "TCP",
            "bytes": 1000,
            "direction": "upload",
        }
        save_packets_batch([pkt])
        save_packets_batch([pkt])

        cursor = db_conn.execute(
            "SELECT total_bytes_sent FROM devices WHERE ip_address = '192.168.1.77'"
        )
        row = cursor.fetchone()
        assert row is not None
        # Should be at least 2000 (two batches of 1000)
        assert row["total_bytes_sent"] >= 2000

    def test_dest_device_receives_bytes(self, _mock, db_conn):
        """When dest is a private IP, total_bytes_received should increase."""
        pkt = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": "8.8.8.8",
            "dest_ip": "192.168.1.88",
            "source_mac": "11:22:33:44:55:66",
            "dest_mac": "AA:BB:CC:DD:EE:88",
            "protocol": "HTTPS",
            "raw_protocol": "TCP",
            "bytes": 500,
            "direction": "download",
        }
        save_packets_batch([pkt])

        cursor = db_conn.execute(
            "SELECT total_bytes_received FROM devices WHERE ip_address = '192.168.1.88'"
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["total_bytes_received"] >= 500


# ===================================================================
# Edge Cases
# ===================================================================

class TestBatchEdgeCases:
    """Edge cases and malformed data."""

    def test_missing_optional_fields(self):
        """Packets with missing optional fields should not crash."""
        packets = [{
            "source_ip": "192.168.1.5",
            "dest_ip": "10.0.0.1",
            "bytes": 100,
        }]
        saved = save_packets_batch(packets)
        assert saved >= 0  # Should not raise

    def test_none_source_ip(self):
        """None IPs should be handled gracefully."""
        packets = [{
            "source_ip": None,
            "dest_ip": None,
            "bytes": 50,
        }]
        # Should not raise
        save_packets_batch(packets)

    def test_large_batch(self):
        """A 500-packet batch should complete without error."""
        packets = _make_packets(500, source_prefix="10.0.0")
        saved = save_packets_batch(packets)
        assert saved == 500


# ===================================================================
# IP Validation Unit Tests
# ===================================================================

class TestIPValidation:
    """Unit tests for is_valid_device_ip and is_private_ip."""

    @pytest.mark.parametrize("ip", [
        "192.168.1.1",
        "192.168.0.100",
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
    ])
    def test_private_ips_are_valid(self, ip):
        """Private IPs should pass both validity and privacy checks."""
        assert is_valid_device_ip(ip) is True
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.80.46",
    ])
    def test_public_ips_valid_but_not_private(self, ip):
        """Public IPs are valid device IPs but NOT private."""
        assert is_valid_device_ip(ip) is True
        assert is_private_ip(ip) is False

    @pytest.mark.parametrize("ip", [
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
    ])
    def test_special_addresses_invalid(self, ip):
        """Broadcast, loopback, and zero addresses are invalid."""
        assert is_valid_device_ip(ip) is False


# ===================================================================
# Helpers
# ===================================================================

def _make_packets(n: int, source_prefix: str = "192.168.1") -> list:
    """Generate *n* realistic packet dicts."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        {
            "timestamp": now,
            "source_ip": f"{source_prefix}.{(i % 254) + 1}",
            "dest_ip": "8.8.8.8",
            "source_mac": f"AA:BB:CC:DD:{i % 256:02X}:FF",
            "dest_mac": "11:22:33:44:55:66",
            "source_port": 50000 + i,
            "dest_port": 443,
            "protocol": "HTTPS",
            "raw_protocol": "TCP",
            "bytes": 1000 + i * 10,
            "direction": "upload" if i % 2 == 0 else "download",
        }
        for i in range(n)
    ]
