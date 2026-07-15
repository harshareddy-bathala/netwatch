"""
test_device_metric_separation.py - Phase 2 app/control metric split tests
=======================================================================
"""

import ipaddress
import os
import sys
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.queries import device_queries as dq
from database.queries import network_filters as nf
from database.connection import get_connection
from utils.realtime_state import InMemoryDashboardState


@pytest.fixture(autouse=True)
def _phase2_setup(initialized_db):
    nf.reset_subnet_cache()
    nf.set_current_mode("port_mirror")
    dq._device_cache.clear()
    yield
    dq._device_cache.clear()
    nf.set_current_mode("")
    nf.reset_subnet_cache()


def _accept_private(ip: str, mac: str) -> bool:
    if not ip or not mac:
        return False
    if mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class TestDeviceQueryMetricSeparation:
    def test_get_all_devices_supports_app_and_control_views(self, monkeypatch):
        monkeypatch.setattr(
            "database.queries.device_queries._is_valid_device_for_insert",
            _accept_private,
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

        saved = dq.save_packets_batch(packets)
        assert saved == 2

        app_devices = dq.get_all_devices(limit=20, offset=0, hours=24, include_control=False)
        app_row = next((d for d in app_devices if d.get("mac_address") == "AA:BB:CC:DD:EE:50"), None)
        assert app_row is not None
        assert app_row["bytes_sent_app"] == 700
        assert app_row["bytes_sent_control"] == 300
        assert app_row["total_bytes_app"] == 700
        assert app_row["total_bytes_control"] == 300
        assert app_row["total_bytes"] == 700

        combined_devices = dq.get_all_devices(limit=20, offset=0, hours=24, include_control=True)
        combined_row = next((d for d in combined_devices if d.get("mac_address") == "AA:BB:CC:DD:EE:50"), None)
        assert combined_row is not None
        assert combined_row["bytes_sent"] == 1000
        assert combined_row["total_bytes"] == 1000
        assert combined_row["total_bytes_total"] == 1000
        assert combined_row["control_overhead_ratio"] == 0.3

    def test_control_overhead_query_returns_ratio(self, monkeypatch):
        monkeypatch.setattr(
            "database.queries.device_queries._is_valid_device_for_insert",
            _accept_private,
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dq.save_packets_batch([
            {
                "timestamp": now,
                "source_ip": "192.168.137.60",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:60",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "MDNS",
                "raw_protocol": "UDP",
                "bytes": 200,
                "direction": "upload",
                "is_control_traffic": True,
            },
            {
                "timestamp": now,
                "source_ip": "192.168.137.60",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:60",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "HTTPS",
                "raw_protocol": "TCP",
                "bytes": 800,
                "direction": "upload",
                "is_control_traffic": False,
            },
        ])

        rows = dq.get_device_control_overhead(hours=24, limit=20)
        row = next((d for d in rows if d.get("mac_address") == "AA:BB:CC:DD:EE:60"), None)
        assert row is not None
        assert row["app_bytes"] == 800
        assert row["control_bytes"] == 200
        assert row["total_bytes"] == 1000
        assert row["control_overhead_ratio"] == 0.2


class TestDeviceApiIncludeControl:
    def test_devices_endpoint_include_control_switches_display_totals(self, client, monkeypatch):
        monkeypatch.setattr(
            "database.queries.device_queries._is_valid_device_for_insert",
            _accept_private,
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dq.save_packets_batch([
            {
                "timestamp": now,
                "source_ip": "192.168.137.70",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:70",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "LLMNR",
                "raw_protocol": "UDP",
                "bytes": 120,
                "direction": "upload",
                "is_control_traffic": True,
            },
            {
                "timestamp": now,
                "source_ip": "192.168.137.70",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:70",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "HTTPS",
                "raw_protocol": "TCP",
                "bytes": 480,
                "direction": "upload",
                "is_control_traffic": False,
            },
        ])

        resp_app = client.get('/api/devices?limit=50&offset=0&include_control=false')
        assert resp_app.status_code == 200
        body_app = resp_app.get_json()
        assert body_app["meta"]["include_control"] is False
        row_app = next((d for d in body_app["data"] if d.get("mac_address") == "AA:BB:CC:DD:EE:70"), None)
        assert row_app is not None
        assert row_app["total_bytes"] == 480

        resp_total = client.get('/api/devices?limit=50&offset=0&include_control=true')
        assert resp_total.status_code == 200
        body_total = resp_total.get_json()
        assert body_total["meta"]["include_control"] is True
        row_total = next((d for d in body_total["data"] if d.get("mac_address") == "AA:BB:CC:DD:EE:70"), None)
        assert row_total is not None
        assert row_total["total_bytes"] == 600
        assert row_total["total_bytes_control"] == 120

    def test_devices_endpoint_hotspot_merges_realtime_rows(self, client, monkeypatch):
        monkeypatch.setattr(
            "database.queries.device_queries._is_valid_device_for_insert",
            _accept_private,
        )

        nf.set_current_mode("hotspot")
        nf.set_subnet_from_ip("192.168.137.1", "255.255.255.0")
        dq._device_cache.clear()

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dq.save_packets_batch([
            {
                "timestamp": now,
                "source_ip": "192.168.137.71",
                "dest_ip": "8.8.8.8",
                "source_mac": "AA:BB:CC:DD:EE:71",
                "dest_mac": "11:22:33:44:55:66",
                "protocol": "HTTPS",
                "raw_protocol": "TCP",
                "bytes": 300,
                "direction": "upload",
                "is_control_traffic": False,
            },
        ])

        realtime_rows = [
            {
                "mac_address": "AA:BB:CC:DD:EE:71",
                "ip_address": "192.168.137.71",
                "hostname": "phone-1",
                "total_bytes": 900,
                "last_seen": "2099-01-01 00:00:00",
            },
            {
                "mac_address": "AA:BB:CC:DD:EE:72",
                "ip_address": "",
                "hostname": "phone-2",
                "total_bytes": 0,
                "last_seen": "2099-01-01 00:00:00",
            },
        ]

        monkeypatch.setattr(
            "utils.realtime_state.dashboard_state.get_top_devices_memory",
            lambda limit=5, include_control=False: realtime_rows,
        )

        resp = client.get('/api/devices?limit=50&offset=0&include_control=false')
        assert resp.status_code == 200
        body = resp.get_json()

        row_existing = next((d for d in body["data"] if d.get("mac_address") == "AA:BB:CC:DD:EE:71"), None)
        row_memory_only = next((d for d in body["data"] if d.get("mac_address") == "AA:BB:CC:DD:EE:72"), None)

        assert row_existing is not None
        assert row_existing["total_bytes"] == 900
        assert row_memory_only is not None

    def test_devices_endpoint_hotspot_filters_stale_active_rows(self, client):
        nf.set_current_mode("hotspot")
        nf.set_subnet_from_ip("192.168.137.1", "255.255.255.0")
        dq._device_cache.clear()

        now = datetime.utcnow()
        stale_ts = (now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        fresh_ts = now.strftime("%Y-%m-%d %H:%M:%S")

        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    mac_address, ip_address, ipv4_address,
                    detected_mode, active_mode,
                    first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "AA:BB:CC:DD:EE:81",
                    "192.168.137.81",
                    "192.168.137.81",
                    "hotspot",
                    "hotspot",
                    stale_ts,
                    stale_ts,
                ),
            )
            conn.execute(
                """
                INSERT INTO devices (
                    mac_address, ip_address, ipv4_address,
                    detected_mode, active_mode,
                    first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "AA:BB:CC:DD:EE:82",
                    "192.168.137.82",
                    "192.168.137.82",
                    "hotspot",
                    "hotspot",
                    fresh_ts,
                    fresh_ts,
                ),
            )
            conn.commit()

        resp = client.get('/api/devices?limit=50&offset=0&include_control=false')
        assert resp.status_code == 200

        body = resp.get_json()
        stale = next((d for d in body["data"] if d.get("mac_address") == "AA:BB:CC:DD:EE:81"), None)
        fresh = next((d for d in body["data"] if d.get("mac_address") == "AA:BB:CC:DD:EE:82"), None)

        assert stale is None
        assert fresh is not None


class TestRealtimeStateMetricSeparation:
    def test_memory_state_exposes_split_fields(self):
        state = InMemoryDashboardState()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packets = [
            {
                "source_mac": "aa:bb:cc:dd:ee:90",
                "dest_mac": "ff:ff:ff:ff:ff:ff",
                "source_ip": "192.168.1.90",
                "dest_ip": "8.8.8.8",
                "bytes": 500,
                "protocol": "HTTPS",
                "direction": "upload",
                "is_control_traffic": False,
                "timestamp": now,
            },
            {
                "source_mac": "aa:bb:cc:dd:ee:90",
                "dest_mac": "ff:ff:ff:ff:ff:ff",
                "source_ip": "192.168.1.90",
                "dest_ip": "8.8.8.8",
                "bytes": 200,
                "protocol": "ARP",
                "direction": "upload",
                "is_control_traffic": True,
                "timestamp": now,
            },
        ]

        state.update_from_batch(packets)

        app_view = state.get_top_devices_memory(limit=5, include_control=False)
        assert app_view
        app_dev = app_view[0]
        assert app_dev["total_bytes"] == 500
        assert app_dev["total_bytes_control"] == 200
        assert app_dev["total_bytes_app"] == 500

        total_view = state.get_top_devices_memory(limit=5, include_control=True)
        assert total_view
        total_dev = total_view[0]
        assert total_dev["total_bytes"] == 700
        assert total_dev["total_bytes_total"] == 700

        snap = state.snapshot()
        assert snap["today_bytes_app"] == 500
        assert snap["today_bytes_control"] == 200
        assert snap["today_bytes_total"] == 700
