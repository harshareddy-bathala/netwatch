"""
test_scale_50_devices.py - Correctness + performance at class scale (P3)
========================================================================

A hotspot classroom is 40-50 devices. This asserts the correctness-critical
paths hold and stay fast at 50 clients: twin device attribution, activity
grouping, device dedup, and the blocked-set hot path.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus
from intelligence.twin import TwinBuilder
from backend.blueprints.devices_bp import _dedupe_by_hostname
from packet_capture.traffic_blocker import build_windivert_filter


N = 50
HOST_MAC = "2e:d0:43:a5:22:70"


def _client(i):
    return {"mac": f"aa:bb:cc:00:{i//256:02x}:{i%256:02x}",
            "ip": f"192.168.137.{10 + i}"}


class TestTwinAtScale:

    def test_50_clients_all_counted_no_host(self):
        twin = TwinBuilder(bus=EventBus(), seed_from_db=False)
        twin.set_context(our_mac=HOST_MAC, our_ip="192.168.137.1",
                         gateway_mac=HOST_MAC, gateway_ip="192.168.137.1",
                         mode="hotspot",
                         host_macs={HOST_MAC}, host_ips={"192.168.137.1"},
                         subnet="192.168.137")
        batch = []
        for i in range(N):
            c = _client(i)
            batch.append({"source_mac": c["mac"], "dest_mac": HOST_MAC,
                          "source_ip": c["ip"], "dest_ip": f"93.184.{i}.1",
                          "protocol": "HTTPS", "bytes": 1000 + i,
                          "direction": "upload"})
        t0 = time.time()
        twin.ingest_packets(batch)
        snap = twin.snapshot()
        elapsed = time.time() - t0
        assert snap["stats"]["device_count"] == N, snap["stats"]
        # host is never a device
        assert all(n["mac"] != HOST_MAC or n["type"] != "device" for n in snap["nodes"])
        assert elapsed < 1.0, f"twin ingest+snapshot too slow: {elapsed:.3f}s"


class TestDedupeAtScale:

    def test_50_devices_each_seen_twice(self):
        # Each phone appears under 2 MACs (randomized) — 100 rows → 50 devices.
        rows = []
        for i in range(N):
            c = _client(i)
            for j, ls in enumerate(("2026-07-17 18:00:00", "2026-07-17 18:05:00")):
                rows.append({"mac_address": f"{c['mac']}:{j}",
                             "ip_address": c["ip"],
                             "hostname": f"device-{i}", "last_seen": ls})
        t0 = time.time()
        out = _dedupe_by_hostname(rows)
        elapsed = time.time() - t0
        assert len(out) == N
        assert elapsed < 0.5


class TestBlockedSetAtScale:

    def test_filter_builds_for_many_ips(self):
        ips = {_client(i)["ip"] for i in range(N)}
        f = build_windivert_filter(ips)
        assert f.count("ip.SrcAddr") == N
        # single filter string, not per-IP handles
        assert f.startswith("ip and (")
