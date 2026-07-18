"""
test_device_queries_phase3.py - Phase 3 CIDR Query Regression Tests
====================================================================

Validates that device query filtering is CIDR-aware and no longer assumes /24.
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_connection
from database.queries import device_queries as dq
from database.queries import network_filters as nf


def _insert_device(mac: str, ip: str, active_mode: str = "hotspot") -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO devices (
                mac_address, ip_address, ipv4_address, hostname,
                detected_mode, active_mode, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            """,
            (mac, ip, ip, ip, active_mode, active_mode),
        )
        conn.commit()


@pytest.fixture(autouse=True)
def _phase3_setup(initialized_db):
    nf.reset_subnet_cache()
    nf.set_current_mode("hotspot")
    nf.set_subnet_from_ip("10.42.0.1", "255.255.0.0")
    dq._device_cache.clear()
    yield
    dq._device_cache.clear()
    nf.reset_subnet_cache()


class TestPhase3CidrFiltering:
    def test_active_device_count_respects_16bit_subnet(self):
        _insert_device("AA:BB:CC:DD:EE:10", "10.42.99.9")
        _insert_device("AA:BB:CC:DD:EE:11", "10.43.1.5")

        # Keep exclusion behavior deterministic across host environments.
        with patch("database.queries.device_queries._detect_all_local_ips", return_value={"10.42.0.1"}), \
             patch("database.queries.device_queries._get_gateway_ip", return_value=""):
            count = dq.get_active_device_count(minutes=5)

        assert count == 1

    def test_active_count_excludes_host_by_mac_when_ip_evades_detection(self):
        """The hotspot ICS virtual adapter is invisible to psutil, so
        _detect_all_local_ips() misses the host IP and it slipped into the
        count (1 with nothing connected, 2 with one phone). The count must
        also exclude the host by its MAC, from get_host_identity() — the same
        source the device *list* uses — so count == list."""
        host_mac = "2E:D0:43:A5:22:70"
        _insert_device(host_mac, "10.42.0.1")            # the host / gateway
        _insert_device("AA:BB:CC:DD:EE:31", "10.42.99.9")  # one real client

        class _FakeState:
            def get_host_identity(self):
                # IP intentionally absent (psutil can't see the ICS adapter);
                # only the MAC is known — the exclusion must still fire.
                return {"macs": {host_mac.lower()}, "ips": set()}

        import utils.realtime_state as rs
        with patch("database.queries.device_queries._detect_all_local_ips", return_value=set()), \
             patch("database.queries.device_queries._get_gateway_ip", return_value=""), \
             patch.object(rs, "dashboard_state", _FakeState()):
            count = dq.get_active_device_count(minutes=5)

        assert count == 1

    def test_get_all_devices_respects_16bit_subnet(self):
        _insert_device("AA:BB:CC:DD:EE:20", "10.42.99.9")
        _insert_device("AA:BB:CC:DD:EE:21", "10.43.1.5")

        devices = dq.get_all_devices(limit=20, offset=0, hours=24)
        ips = {d.get("ip_address") for d in devices}

        assert "10.42.99.9" in ips
        assert "10.43.1.5" not in ips

    def test_scope_devices_to_mode_accepts_cidr(self):
        _insert_device("AA:BB:CC:DD:EE:30", "10.42.99.9", active_mode="")
        _insert_device("AA:BB:CC:DD:EE:31", "10.43.1.5", active_mode="")

        nf.scope_devices_to_mode("hotspot", "10.42.0.0/16")

        with get_connection() as conn:
            in_subnet_mode = conn.execute(
                "SELECT active_mode FROM devices WHERE mac_address = ?",
                ("AA:BB:CC:DD:EE:30",),
            ).fetchone()["active_mode"]
            out_subnet_mode = conn.execute(
                "SELECT active_mode FROM devices WHERE mac_address = ?",
                ("AA:BB:CC:DD:EE:31",),
            ).fetchone()["active_mode"]

        assert in_subnet_mode == "hotspot"
        assert out_subnet_mode in (None, "")

    def test_hotspot_get_all_devices_ignores_traffic_history_only_rows(self):
        _insert_device("AA:BB:CC:DD:EE:40", "10.42.99.40", active_mode="hotspot")

        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO traffic_summary (
                    timestamp, source_ip, dest_ip, source_mac, dest_mac,
                    protocol, bytes_transferred, direction, is_control
                ) VALUES (datetime('now'), ?, ?, ?, ?, 'TCP', ?, 'outbound', 0)
                """,
                (
                    "10.42.99.50",
                    "8.8.8.8",
                    "AA:BB:CC:DD:EE:50",
                    "11:22:33:44:55:66",
                    12345,
                ),
            )
            conn.commit()

        devices = dq.get_all_devices(limit=20, offset=0, hours=24)
        macs = {d.get("mac_address") for d in devices}

        assert "AA:BB:CC:DD:EE:40" in macs
        assert "AA:BB:CC:DD:EE:50" not in macs

    def test_hotspot_top_devices_bypasses_cache_for_realtime_updates(self):
        _insert_device("AA:BB:CC:DD:EE:60", "10.42.99.60", active_mode="hotspot")

        with get_connection() as conn:
            conn.execute(
                """
                UPDATE devices
                SET total_bytes_sent = 1200,
                    total_bytes_received = 0,
                    last_seen = datetime('now')
                WHERE mac_address = ?
                """,
                ("AA:BB:CC:DD:EE:60",),
            )
            conn.commit()

        with patch("database.queries.device_queries._detect_all_local_ips", return_value={"10.42.0.1"}), \
             patch("database.queries.device_queries._detect_all_local_macs", return_value=set()), \
             patch("database.queries.device_queries._strip_host_devices", side_effect=lambda rows: rows):
            first = dq.get_top_devices(limit=5, hours=24)
            first_bytes = next(
                (
                    d.get("total_bytes", 0)
                    for d in first
                    if (d.get("mac_address") or "").lower() == "aa:bb:cc:dd:ee:60"
                ),
                0,
            )

        with get_connection() as conn:
            conn.execute(
                """
                UPDATE devices
                SET total_bytes_sent = 6200,
                    last_seen = datetime('now')
                WHERE mac_address = ?
                """,
                ("AA:BB:CC:DD:EE:60",),
            )
            conn.commit()

        with patch("database.queries.device_queries._detect_all_local_ips", return_value={"10.42.0.1"}), \
             patch("database.queries.device_queries._detect_all_local_macs", return_value=set()), \
             patch("database.queries.device_queries._strip_host_devices", side_effect=lambda rows: rows):
            second = dq.get_top_devices(limit=5, hours=24)
            second_bytes = next(
                (
                    d.get("total_bytes", 0)
                    for d in second
                    if (d.get("mac_address") or "").lower() == "aa:bb:cc:dd:ee:60"
                ),
                0,
            )

        assert first_bytes == 1200
        assert second_bytes == 6200

    def test_hotspot_get_all_devices_keeps_mac_only_clients_visible(self):
        # Connected hotspot clients can be discovered by MAC before IP
        # assignment resolves. Keep them visible on list endpoints.
        _insert_device("AA:BB:CC:DD:EE:70", "", active_mode="hotspot")

        devices = dq.get_all_devices(limit=20, offset=0, hours=24)
        target = next(
            (
                d
                for d in devices
                if (d.get("mac_address") or "").lower() == "aa:bb:cc:dd:ee:70"
            ),
            None,
        )

        assert target is not None
        assert target.get("ip_address") in ("", None)
