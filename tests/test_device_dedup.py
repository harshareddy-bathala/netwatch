"""
test_device_dedup.py - Devices list: dedup + host exclusion (P1.1/P1.2)
========================================================================
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.blueprints.devices_bp import _dedupe_by_hostname


class TestDedupeByHostname:

    def test_two_macs_one_phone_collapse(self):
        devs = [
            {"mac_address": "22:5e:3e:1a:d0:f3", "ip_address": "192.168.137.142",
             "hostname": "Nothing-Phone-2a-Plus", "last_seen": "2026-07-17 18:00:00"},
            {"mac_address": "de:ad:00:00:00:01", "ip_address": "192.168.137.199",
             "hostname": "Nothing-Phone-2a-Plus", "last_seen": "2026-07-17 18:05:00"},
        ]
        out = _dedupe_by_hostname(devs)
        assert len(out) == 1
        # keeps the most-recently-seen row
        assert out[0]["mac_address"] == "de:ad:00:00:00:01"

    def test_distinct_devices_kept(self):
        devs = [
            {"mac_address": "aa:11", "ip_address": "192.168.137.10",
             "hostname": "Galaxy-Tab-A9", "last_seen": "t1"},
            {"mac_address": "bb:22", "ip_address": "192.168.137.11",
             "hostname": "Nothing-Phone-2a-Plus", "last_seen": "t2"},
        ]
        assert len(_dedupe_by_hostname(devs)) == 2

    def test_no_hostname_passthrough_by_mac(self):
        # Rows without a real hostname are kept (unique by MAC), not merged.
        devs = [
            {"mac_address": "aa:11", "ip_address": "192.168.137.10",
             "hostname": "", "last_seen": "t1"},
            {"mac_address": "bb:22", "ip_address": "192.168.137.11",
             "hostname": "", "last_seen": "t2"},
        ]
        assert len(_dedupe_by_hostname(devs)) == 2

    def test_hostname_equal_ip_not_merged(self):
        devs = [
            {"mac_address": "aa:11", "ip_address": "192.168.137.10",
             "hostname": "192.168.137.10", "last_seen": "t1"},
            {"mac_address": "bb:22", "ip_address": "192.168.137.11",
             "hostname": "192.168.137.11", "last_seen": "t2"},
        ]
        assert len(_dedupe_by_hostname(devs)) == 2


class TestDropHostRows:

    def test_host_dropped_by_ip_and_mac(self, monkeypatch):
        from backend.blueprints.devices_bp import _drop_host_rows

        class FakeState:
            def get_host_identity(self):
                return {"macs": {"2e:d0:43:a5:22:70"}, "ips": {"192.168.137.1"}}
        import utils.realtime_state as rs
        monkeypatch.setattr(rs, "dashboard_state", FakeState())

        rows = [
            {"mac_address": "2e:d0:43:a5:22:70", "ip_address": "192.168.137.1",
             "hostname": "HarshaReddy"},                       # host by MAC+IP
            {"mac_address": "AA:BB:CC:00:00:01", "ip_address": "192.168.137.1",
             "hostname": "spoofed"},                            # host by IP only
            {"mac_address": "22:5e:3e:1a:d0:f3", "ip_address": "192.168.137.142",
             "hostname": "Nothing-Phone"},                      # real client
        ]
        out = _drop_host_rows(rows)
        names = [d["hostname"] for d in out]
        assert names == ["Nothing-Phone"]


class TestHostExclusionSql:

    def test_hotspot_clause_excludes_host(self, monkeypatch):
        import database.queries.device_queries as dq

        class FakeState:
            def get_host_identity(self):
                return {"macs": {"2e:d0:43:a5:22:70"},
                        "ips": {"192.168.137.1", "fe80::1"}}
        import utils.realtime_state as rs
        monkeypatch.setattr(rs, "dashboard_state", FakeState())

        clause = dq._devices_table_ip_filter_clause("hotspot")
        assert "192.168.137.1" in clause
        assert "2e:d0:43:a5:22:70" in clause
        assert "NOT IN" in clause

    def test_non_hotspot_no_host_exclusion(self):
        import database.queries.device_queries as dq
        clause = dq._devices_table_ip_filter_clause("public_network")
        assert "NOT IN" not in clause
