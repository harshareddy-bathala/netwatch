"""
test_control_protocol_filtering.py - Phase 1 control-traffic filtering tests
=========================================================================
"""

import ipaddress
import os
import sqlite3
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.queries.device_queries import save_packets_batch
from packet_capture.bandwidth_calculator import BandwidthCalculator
from packet_capture.protocols import is_control_protocol, is_essential_control


@pytest.fixture(autouse=True)
def _test_db(initialized_db):
    """Use shared initialized DB fixture from conftest."""
    yield initialized_db


@pytest.fixture
def db_conn(_test_db):
    conn = sqlite3.connect(_test_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def _accept_private_devices(ip: str, mac: str) -> bool:
    if not ip or not mac:
        return False
    if mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class TestControlProtocolHelpers:
    def test_control_protocol_detection(self):
        assert is_control_protocol("ARP")
        assert is_control_protocol("mDNS")
        assert is_control_protocol("DHCPv6")
        assert is_control_protocol("ICMPv6-NS")

        assert not is_control_protocol("HTTP")
        assert not is_control_protocol("HTTPS")
        assert not is_control_protocol("DNS")

    def test_essential_control_subset(self):
        assert is_essential_control("ARP")
        assert is_essential_control("DHCP")
        assert is_essential_control("DHCPv6")
        assert not is_essential_control("mDNS")


class TestBandwidthSplit:
    def test_bandwidth_calculator_separates_control_bytes(self):
        calc = BandwidthCalculator(window_seconds=30)

        calc.add_bytes(1_000, direction="download", is_control_traffic=False)
        calc.add_bytes(250, direction="download", is_control_traffic=True)

        stats = calc.get_stats()
        assert stats["total_bps"] > 0
        assert stats["control_total_bps"] > 0
        assert stats["combined_total_bps"] >= stats["total_bps"]

        history = calc.get_recent_history(bucket_seconds=30, max_points=5)
        assert history
        latest = history[-1]
        assert latest["total_bytes"] == 1_000
        assert latest["control_total_bytes"] == 250
        assert latest["combined_total_bytes"] == 1_250

    def test_recent_history_normalizes_in_progress_bucket(self, monkeypatch):
        calc = BandwidthCalculator(window_seconds=30)

        base_monotonic = 1000.0
        base_wall = 2000.0

        monkeypatch.setattr(
            "packet_capture.bandwidth_calculator.time.monotonic",
            lambda: base_monotonic,
        )
        monkeypatch.setattr(
            "packet_capture.bandwidth_calculator.time.time",
            lambda: base_wall,
        )

        # 1,250,000 bytes in 1 second => 10 Mbps equivalent.
        calc.add_bytes(1_250_000, direction="download", is_control_traffic=False)

        monkeypatch.setattr(
            "packet_capture.bandwidth_calculator.time.monotonic",
            lambda: base_monotonic + 0.5,
        )
        monkeypatch.setattr(
            "packet_capture.bandwidth_calculator.time.time",
            lambda: base_wall + 1.0,
        )

        history = calc.get_recent_history(bucket_seconds=10, max_points=5)
        assert history

        latest = history[-1]
        assert latest["total_bytes"] == 1_250_000
        assert latest["download_mbps"] == pytest.approx(10.0, rel=0.05)


class TestDeviceCounterFiltering:
    def test_control_packets_not_added_to_app_device_totals(self, monkeypatch, db_conn):
        monkeypatch.setattr(
            "database.queries.packet_store._is_valid_device_for_insert",
            _accept_private_devices,
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packets = [
            {
                "timestamp": now,
                "source_ip": "192.168.137.50",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:50",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "ARP",
                "raw_protocol": "ARP",
                "bytes": 300,
                "direction": "upload",
                "is_control_traffic": True,
            },
            {
                "timestamp": now,
                "source_ip": "192.168.137.50",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:50",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "HTTPS",
                "raw_protocol": "TCP",
                "bytes": 700,
                "direction": "upload",
                "is_control_traffic": False,
            },
        ]

        saved = save_packets_batch(packets)
        assert saved == 2

        traffic = db_conn.execute(
            "SELECT COUNT(*) AS cnt, "
            "SUM(CASE WHEN is_control = 1 THEN bytes_transferred ELSE 0 END) AS control_bytes, "
            "SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END) AS app_bytes "
            "FROM traffic_summary"
        ).fetchone()
        assert traffic["cnt"] == 2
        assert traffic["control_bytes"] == 300
        assert traffic["app_bytes"] == 700

        device = db_conn.execute(
            "SELECT total_bytes_sent, control_bytes_sent FROM devices WHERE mac_address = ?",
            ("AA:BB:CC:DD:EE:50",),
        ).fetchone()
        assert device is not None
        assert device["total_bytes_sent"] == 700
        assert device["control_bytes_sent"] == 300

        daily = db_conn.execute(
            "SELECT bytes_sent, total_bytes FROM daily_usage WHERE mac_address = ?",
            ("AA:BB:CC:DD:EE:50",),
        ).fetchone()
        assert daily is not None
        assert daily["bytes_sent"] == 700
        assert daily["total_bytes"] == 700
