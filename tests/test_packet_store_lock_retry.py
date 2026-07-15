"""
test_packet_store_lock_retry.py - Packet batch lock retry regressions
====================================================================
"""

import ipaddress
import os
import sqlite3
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_connection
from database.queries import device_queries as dq
from database.queries import network_filters as nf
from database.queries import packet_store as ps


def _accept_private(ip: str, mac: str) -> bool:
    if not ip or not mac:
        return False
    if mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


@pytest.fixture(autouse=True)
def _lock_retry_setup(initialized_db):
    nf.reset_subnet_cache()
    nf.set_current_mode("hotspot")
    dq._device_cache.clear()
    yield
    dq._device_cache.clear()
    nf.set_current_mode("")
    nf.reset_subnet_cache()


class TestPacketStoreLockRetry:
    def test_locked_retry_replays_full_transaction(self, monkeypatch):
        monkeypatch.setattr("database.queries.device_queries._is_valid_device_for_insert", _accept_private)
        monkeypatch.setattr(ps, "_is_valid_device_for_insert", _accept_private)
        monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)

        real_get_connection = ps.get_connection
        attempts = {"count": 0}

        def _flaky_get_connection():
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise sqlite3.OperationalError("database is locked")
            return real_get_connection()

        monkeypatch.setattr(ps, "get_connection", _flaky_get_connection)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packets = [
            {
                "timestamp": now,
                "source_ip": "192.168.137.99",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:99",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "HTTPS",
                "raw_protocol": "TCP",
                "bytes": 512,
                "direction": "upload",
                "is_control_traffic": False,
            }
        ]

        saved = dq.save_packets_batch(packets)

        assert saved == 1
        assert attempts["count"] >= 2

        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM traffic_summary")
            assert cursor.fetchone()[0] == 1

            cursor.execute(
                """
                SELECT total_bytes_sent, control_bytes_sent, total_packets
                FROM devices
                WHERE mac_address = ?
                """,
                ("AA:BB:CC:DD:EE:99",),
            )
            device_row = cursor.fetchone()
            assert device_row is not None
            assert device_row[0] == 512
            assert device_row[1] == 0
            assert device_row[2] == 1

            cursor.execute(
                """
                SELECT total_bytes, packet_count
                FROM daily_usage
                WHERE mac_address = ?
                """,
                ("AA:BB:CC:DD:EE:99",),
            )
            daily_row = cursor.fetchone()
            assert daily_row is not None
            assert daily_row[0] == 512
            assert daily_row[1] == 1

    def test_exhausted_lock_retries_return_failure_sentinel(self, monkeypatch):
        monkeypatch.setattr("database.queries.device_queries._is_valid_device_for_insert", _accept_private)
        monkeypatch.setattr(ps, "_is_valid_device_for_insert", _accept_private)
        monkeypatch.setattr("time.sleep", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(
            ps,
            "get_connection",
            lambda: (_ for _ in ()).throw(sqlite3.OperationalError("database is locked")),
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packets = [
            {
                "timestamp": now,
                "source_ip": "192.168.137.99",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:98",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "HTTPS",
                "raw_protocol": "TCP",
                "bytes": 512,
                "direction": "upload",
                "is_control_traffic": False,
            }
        ]

        saved = dq.save_packets_batch(packets)
        assert saved == -1
