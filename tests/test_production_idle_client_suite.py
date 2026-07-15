"""
test_production_idle_client_suite.py - Phase 5 Regression Suite
================================================================

Covers:
- 24h idle-client baseline regression thresholds
- simulated 10-20 hotspot client connect/disconnect bursts
"""

import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.idle_baseline import collect_idle_baseline_metrics
from utils.realtime_state import InMemoryDashboardState


@pytest.fixture
def db_conn(initialized_db):
    conn = sqlite3.connect(initialized_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def _insert_idle_24h(conn, app_bytes_per_hour: int, control_bytes_per_hour: int) -> None:
    rows = []
    now = datetime.now()
    for hour_idx in range(24):
        ts = (now - timedelta(hours=24 - hour_idx - 1)).strftime("%Y-%m-%d %H:%M:%S")

        rows.append((
            ts,
            "192.168.137.51",
            "8.8.4.4",
            "AA:BB:CC:DD:EE:51",
            "11:22:33:44:55:66",
            50001,
            443,
            "HTTPS",
            "TCP",
            app_bytes_per_hour,
            "upload",
            0,
        ))
        rows.append((
            ts,
            "192.168.137.51",
            "255.255.255.255",
            "AA:BB:CC:DD:EE:51",
            "ff:ff:ff:ff:ff:ff",
            68,
            67,
            "DHCP",
            "UDP",
            control_bytes_per_hour,
            "other",
            1,
        ))

    conn.executemany(
        """
        INSERT INTO traffic_summary (
            timestamp, source_ip, dest_ip, source_mac, dest_mac,
            source_port, dest_port, protocol, raw_protocol,
            bytes_transferred, direction, is_control
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


class TestProductionIdleClientSuite:
    def test_24h_idle_regression_threshold_pass(self, db_conn):
        _insert_idle_24h(
            db_conn,
            app_bytes_per_hour=48 * 1024,
            control_bytes_per_hour=2 * 1024 * 1024,
        )

        metrics = collect_idle_baseline_metrics(hours=24)

        assert metrics["checks"]["app_bytes_within_limit"] is True
        assert metrics["checks"]["app_pps_within_limit"] is True

    def test_24h_idle_regression_threshold_fail(self, db_conn):
        _insert_idle_24h(
            db_conn,
            app_bytes_per_hour=256 * 1024,
            control_bytes_per_hour=2 * 1024 * 1024,
        )

        metrics = collect_idle_baseline_metrics(hours=24)

        assert metrics["checks"]["app_bytes_within_limit"] is False
        assert metrics["status"] == "warning"

    def test_hotspot_burst_connect_disconnect_realtime_visibility(self):
        state = InMemoryDashboardState()
        state.set_mode_context(own_traffic_only=False)
        state.set_device_active_window(60)

        # Simulate 20 clients connecting quickly.
        for idx in range(20):
            mac = f"aa:bb:cc:dd:ee:{idx:02x}"
            ip = f"192.168.137.{idx + 10}"
            state.upsert_discovered_device(mac_address=mac, ip_address=ip, hostname=f"client-{idx}")

        assert state.get_active_device_count(minutes=1) == 20

        # Simulate sudden disconnection of 8 clients.
        stale_cutoff = time.time() - 120
        with state._lock:
            for idx in range(8):
                mac = f"aa:bb:cc:dd:ee:{idx:02x}"
                state._devices[mac].last_seen = stale_cutoff

        evicted = state.remove_stale_devices(max_age_seconds=60)
        assert evicted == 8
        assert state.get_active_device_count(minutes=1) == 12

        # Simulate 5 clients reconnecting immediately.
        for idx in range(5):
            mac = f"aa:bb:cc:dd:ee:{idx:02x}"
            ip = f"192.168.137.{idx + 10}"
            state.upsert_discovered_device(mac_address=mac, ip_address=ip, hostname=f"client-{idx}")

        assert state.get_active_device_count(minutes=1) == 17

        top = state.get_top_devices_memory(limit=25)
        assert len(top) == 17
