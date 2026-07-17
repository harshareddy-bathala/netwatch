"""
test_activity_attribution.py - Hotspot host/gateway exclusion (W1)
===================================================================

Regressions for "1 client shows as 2 topology nodes / 4 activity cards
+ this-host card". The three views (dashboard, twin, activity) must apply
the SAME host/gateway exclusion.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus
from intelligence.twin import TwinBuilder


HOTSPOT_MAC = "2e:d0:43:a5:22:70"   # host's hotspot adapter (= gateway)
WIFI_MAC = "aa:bb:cc:11:22:33"      # host's leftover Wi-Fi adapter
CLIENT_MAC = "16:c9:99:2b:3a:27"    # the one real client


def _twin_hotspot():
    twin = TwinBuilder(bus=EventBus(), seed_from_db=False)
    twin.set_context(
        our_mac=HOTSPOT_MAC, our_ip="192.168.137.1",
        gateway_mac=HOTSPOT_MAC, gateway_ip="192.168.137.1",
        mode="hotspot",
        host_macs={HOTSPOT_MAC, WIFI_MAC},
        host_ips={"192.168.137.1", "192.168.1.68"},
        subnet="192.168.137",
    )
    return twin


def _pkt(src_mac, src_ip, dst_ip="93.184.216.34", direction="upload", **extra):
    d = {"source_mac": src_mac, "dest_mac": HOTSPOT_MAC,
         "source_ip": src_ip, "dest_ip": dst_ip,
         "protocol": "HTTPS", "bytes": 1000, "direction": direction}
    d.update(extra)
    return d


class TestTwinHostExclusion:

    def test_leftover_wifi_adapter_not_counted_as_device(self):
        twin = _twin_hotspot()
        # One real client uploading, plus the host's own Wi-Fi adapter
        # emitting a packet (the "phantom second device").
        twin.ingest_packets([
            _pkt(CLIENT_MAC, "192.168.137.178"),
            _pkt(WIFI_MAC, "192.168.1.68"),
        ])
        snap = twin.snapshot()
        assert snap["stats"]["device_count"] == 1
        device_nodes = [n for n in snap["nodes"] if n["type"] == "device"]
        assert len(device_nodes) == 1
        assert device_nodes[0]["mac"] == CLIENT_MAC
        # The Wi-Fi adapter, if present at all, is typed "self".
        wifi = [n for n in snap["nodes"] if n["mac"] == WIFI_MAC]
        assert all(n["type"] == "self" for n in wifi)

    def test_out_of_subnet_device_dropped(self):
        twin = _twin_hotspot()
        # A stale node from the previous 192.168.1.x network (not a host
        # adapter — a random leftover) must not count as a live device.
        twin.ingest_packets([
            _pkt(CLIENT_MAC, "192.168.137.178"),
            _pkt("de:ad:be:ef:00:01", "192.168.1.50"),
        ])
        snap = twin.snapshot()
        assert snap["stats"]["device_count"] == 1
        macs = {n["mac"] for n in snap["nodes"] if n["type"] == "device"}
        assert macs == {CLIENT_MAC}

    def test_client_in_subnet_still_shown(self):
        twin = _twin_hotspot()
        twin.ingest_packets([_pkt(CLIENT_MAC, "192.168.137.142")])
        snap = twin.snapshot()
        assert snap["stats"]["device_count"] == 1


class TestActivityHostExclusion:

    def test_query_filters_host_macs_and_ips(self, monkeypatch):
        # Verify get_recent_activity threads the exclusion sets into the SQL
        # (no DB needed — we intercept the cursor).
        import database.queries.flow_queries as fq

        captured = {}

        class FakeCursor:
            description = [("timestamp",), ("source_ip",), ("source_mac",),
                          ("qname",), ("qtype",), ("protocol",), ("device_name",)]

            def execute(self, sql, params):
                captured["sql"] = sql
                captured["params"] = params

            def fetchall(self):
                return []

        class FakeConn:
            def cursor(self):
                return FakeCursor()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(fq, "get_connection", lambda: FakeConn())

        fq.get_recent_activity(
            minutes=15, limit=100,
            exclude_macs={"2e:d0:43:a5:22:70"},
            exclude_ips={"192.168.137.1", "192.168.1.68"},
        )
        sql = captured["sql"]
        params = captured["params"]
        assert "q.source_mac IS NULL OR LOWER(q.source_mac) != LOWER(?)" in sql
        assert "q.source_ip IS NULL OR q.source_ip != ?" in sql
        assert "2e:d0:43:a5:22:70" in params
        assert "192.168.137.1" in params
        assert "192.168.1.68" in params
        # Still coalesces MAC by IP for stable grouping.
        assert "COALESCE(q.source_mac, dip.mac_address)" in sql
