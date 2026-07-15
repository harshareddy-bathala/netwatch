"""
test_idle_client_baseline.py - Phase 5 Idle Baseline Validation
=================================================================

Validates baseline metrics and the Phase 5 idle-client health endpoint.
"""

import os
import sqlite3
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.idle_baseline import collect_idle_baseline_metrics


@pytest.fixture
def db_conn(initialized_db):
    conn = sqlite3.connect(initialized_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def _insert_hourly_baseline_rows(conn, hours: int, app_bytes_per_hour: int, control_bytes_per_hour: int) -> None:
    rows = []
    now = datetime.now()
    for hour_idx in range(hours):
        ts = (now - timedelta(hours=hours - hour_idx - 1)).strftime("%Y-%m-%d %H:%M:%S")

        rows.append((
            ts,
            "192.168.137.20",
            "8.8.8.8",
            "AA:BB:CC:DD:EE:20",
            "11:22:33:44:55:66",
            51000,
            443,
            "HTTPS",
            "TCP",
            app_bytes_per_hour,
            "upload",
            0,
        ))
        rows.append((
            ts,
            "192.168.137.20",
            "224.0.0.251",
            "AA:BB:CC:DD:EE:20",
            "01:00:5e:00:00:fb",
            5353,
            5353,
            "mDNS",
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


class TestIdleBaselineMetrics:
    def test_collect_idle_baseline_metrics_meets_expected_idle_profile(self, db_conn):
        _insert_hourly_baseline_rows(
            db_conn,
            hours=24,
            app_bytes_per_hour=64 * 1024,
            control_bytes_per_hour=2 * 1024 * 1024,
        )

        metrics = collect_idle_baseline_metrics(hours=24)

        assert metrics["app_bytes_per_hour"] <= 100 * 1024
        assert metrics["control_bytes_per_hour"] >= 1 * 1024 * 1024
        assert metrics["control_bytes_per_hour"] <= 5 * 1024 * 1024
        assert metrics["app_pps"] < 5
        assert metrics["checks"]["app_bytes_within_limit"] is True
        assert metrics["checks"]["app_pps_within_limit"] is True

    def test_idle_client_baseline_endpoint_returns_phase5_fields(self, client):
        resp = client.get('/api/health/idle-client-baseline?hours=24')
        assert resp.status_code == 200

        body = resp.get_json()
        assert "data" in body
        data = body["data"]

        for key in (
            "app_pps",
            "control_overhead_ratio",
            "mode_transition_count",
            "app_bytes_per_hour",
            "control_bytes_per_hour",
            "active_devices_realtime",
            "checks",
            "status",
        ):
            assert key in data, f"Missing key: {key}"

    def test_collect_idle_baseline_metrics_flags_excess_idle_app_usage(self, db_conn):
        _insert_hourly_baseline_rows(
            db_conn,
            hours=24,
            app_bytes_per_hour=512 * 1024,
            control_bytes_per_hour=2 * 1024 * 1024,
        )

        metrics = collect_idle_baseline_metrics(hours=24)

        assert metrics["app_bytes_per_hour"] > 100 * 1024
        assert metrics["checks"]["app_bytes_within_limit"] is False
        assert metrics["status"] == "warning"
