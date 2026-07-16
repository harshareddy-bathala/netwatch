"""
test_twin.py - Digital Twin Tests (Phase 1)
============================================

Covers ``intelligence.twin``: node/edge construction from packet batches,
role assignment (self/gateway/external), DNS enrichment, mode timeline,
pruning, and snapshot shape.  DB seeding is disabled; the bus is private.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus
from intelligence.twin import TwinBuilder


LAPTOP = "aa:bb:cc:00:00:01"
PHONE = "aa:bb:cc:00:00:02"
GATEWAY = "aa:bb:cc:00:00:99"


def _twin(**ctx):
    twin = TwinBuilder(bus=EventBus(), seed_from_db=False)
    if ctx:
        twin.set_context(**ctx)
    return twin


def _pkt(src_mac=LAPTOP, dst_mac=GATEWAY, src_ip="192.168.1.10",
         dst_ip="93.184.216.34", proto="HTTPS", nbytes=1000, **extra):
    d = {
        "source_mac": src_mac, "dest_mac": dst_mac,
        "source_ip": src_ip, "dest_ip": dst_ip,
        "protocol": proto, "bytes": nbytes,
    }
    d.update(extra)
    return d


class TestGraphConstruction:

    def test_local_device_and_external_endpoint(self):
        twin = _twin()
        twin.ingest_packets([_pkt()])
        snap = twin.snapshot()
        ids = {n["id"] for n in snap["nodes"]}
        assert f"mac:{LAPTOP}" in ids
        assert "ip:93.184.216.34" in ids
        assert len(snap["edges"]) == 1
        edge = snap["edges"][0]
        assert edge["source"] == f"mac:{LAPTOP}"
        assert edge["target"] == "ip:93.184.216.34"
        assert edge["bytes"] == 1000

    def test_edges_aggregate_across_packets(self):
        twin = _twin()
        twin.ingest_packets([_pkt(nbytes=100), _pkt(nbytes=200)])
        edge = twin.snapshot()["edges"][0]
        assert edge["bytes"] == 300
        assert edge["packets"] == 2

    def test_local_to_local_edge(self):
        twin = _twin()
        twin.ingest_packets([
            _pkt(src_mac=LAPTOP, dst_mac=PHONE,
                 src_ip="192.168.1.10", dst_ip="192.168.1.11"),
        ])
        snap = twin.snapshot()
        ids = {n["id"] for n in snap["nodes"]}
        assert f"mac:{LAPTOP}" in ids and f"mac:{PHONE}" in ids
        assert snap["edges"][0]["target"] == f"mac:{PHONE}"

    def test_broadcast_mac_never_becomes_node(self):
        twin = _twin()
        twin.ingest_packets([
            _pkt(dst_mac="ff:ff:ff:ff:ff:ff", dst_ip="192.168.1.255"),
            _pkt(dst_mac="01:00:5e:00:00:fb", dst_ip="224.0.0.251"),
        ])
        ids = {n["id"] for n in twin.snapshot()["nodes"]}
        assert not any("ff:ff:ff" in i or "01:00:5e" in i for i in ids)
        assert twin.snapshot()["edges"] == []

    def test_byte_counters_directional(self):
        twin = _twin()
        twin.ingest_packets([_pkt(nbytes=500)])
        node = next(n for n in twin.snapshot()["nodes"]
                    if n["id"] == f"mac:{LAPTOP}")
        assert node["bytes_out"] == 500
        assert node["bytes_in"] == 0


class TestRoles:

    def test_self_and_gateway_roles(self):
        twin = _twin(our_mac=LAPTOP, our_ip="192.168.1.10",
                     gateway_mac=GATEWAY, gateway_ip="192.168.1.1")
        twin.ingest_packets([
            _pkt(src_mac=LAPTOP, dst_mac=GATEWAY,
                 src_ip="192.168.1.10", dst_ip="192.168.1.1"),
        ])
        types = {n["id"]: n["type"] for n in twin.snapshot()["nodes"]}
        assert types[f"mac:{LAPTOP}"] == "self"
        assert types[f"mac:{GATEWAY}"] == "gateway"

    def test_context_reroles_existing_nodes(self):
        twin = _twin()
        twin.ingest_packets([_pkt()])
        twin.set_context(our_mac=LAPTOP)
        types = {n["id"]: n["type"] for n in twin.snapshot()["nodes"]}
        assert types[f"mac:{LAPTOP}"] == "self"

    def test_public_ip_is_external(self):
        twin = _twin()
        twin.ingest_packets([_pkt(dst_ip="8.8.8.8")])
        node = next(n for n in twin.snapshot()["nodes"] if n["id"] == "ip:8.8.8.8")
        assert node["type"] == "external"

    def test_global_ipv6_source_stays_local_on_upload(self):
        """Regression (live-run finding): a local device uploading from a
        global IPv6 address must be keyed by MAC, not become 'external'."""
        twin = _twin(our_mac=LAPTOP)
        twin.ingest_packets([_pkt(
            src_mac=LAPTOP, src_ip="2401:4900:c97a:f3b4::1234",
            dst_ip="2606:4700:103::2", direction="upload",
        )])
        snap = twin.snapshot()
        ids = {n["id"] for n in snap["nodes"]}
        assert f"mac:{LAPTOP}" in ids
        assert "ip:2401:4900:c97a:f3b4::1234" not in ids
        assert snap["edges"][0]["source"] == f"mac:{LAPTOP}"


class TestEnrichment:

    def test_dns_annotates_device(self):
        twin = _twin()
        twin.ingest_packets([_pkt()])
        twin.ingest_dns({"source_mac": LAPTOP, "qname": "example.com"})
        node = next(n for n in twin.snapshot()["nodes"]
                    if n["id"] == f"mac:{LAPTOP}")
        assert "example.com" in node["recent_dns"]

    def test_mode_change_updates_timeline(self):
        twin = _twin()
        twin.ingest_mode_change({"timestamp": time.time(),
                                 "old_mode": "hotspot", "new_mode": "ethernet"})
        snap = twin.snapshot()
        assert snap["mode"] == "ethernet"
        assert snap["mode_timeline"][-1]["new_mode"] == "ethernet"

    def test_hostname_learned_from_packet(self):
        twin = _twin()
        twin.ingest_packets([_pkt(device_name="harsha-laptop", vendor="Intel")])
        node = next(n for n in twin.snapshot()["nodes"]
                    if n["id"] == f"mac:{LAPTOP}")
        assert node["hostname"] == "harsha-laptop"
        assert node["vendor"] == "Intel"


class TestMaintenance:

    def test_prune_removes_stale_nodes(self):
        twin = _twin()
        twin.ingest_packets([_pkt()])
        # Negative staleness puts the cutoff in the future — robust
        # against Windows clock granularity.
        removed = twin.prune(stale_hours=-1)
        assert removed >= 1
        assert twin.snapshot()["edges"] == []

    def test_prune_keeps_self_and_gateway(self):
        twin = _twin(our_mac=LAPTOP, gateway_mac=GATEWAY)
        twin.ingest_packets([
            _pkt(src_mac=LAPTOP, dst_mac=GATEWAY,
                 src_ip="192.168.1.10", dst_ip="192.168.1.1"),
        ])
        twin.prune(stale_hours=-1)
        types = {n["type"] for n in twin.snapshot()["nodes"]}
        assert "self" in types and "gateway" in types

    def test_snapshot_caps_edges(self):
        twin = _twin()
        pkts = [_pkt(dst_ip=f"93.184.{i // 250}.{i % 250 + 1}") for i in range(60)]
        twin.ingest_packets(pkts)
        snap = twin.snapshot(max_edges=10)
        assert len(snap["edges"]) == 10
        assert snap["stats"]["edge_count"] == 60


class TestLiveSnapshot:
    """device_count reflects live client devices only — matching the
    dashboard's active-device count (the '2 vs 1' report)."""

    def test_self_not_counted_as_device(self):
        # Host is both self and gateway (hotspot: host IS the gateway) with
        # one real client. Only the client should count as a device.
        twin = _twin(our_mac=LAPTOP, our_ip="192.168.1.1",
                     gateway_mac=LAPTOP, gateway_ip="192.168.1.1")
        twin.ingest_packets([
            _pkt(src_mac=PHONE, dst_mac=LAPTOP,
                 src_ip="192.168.1.11", dst_ip="8.8.8.8", direction="upload"),
        ])
        snap = twin.snapshot()
        types = {n["id"]: n["type"] for n in snap["nodes"]}
        assert types[f"mac:{LAPTOP}"] == "self"
        assert types[f"mac:{PHONE}"] == "device"
        assert snap["stats"]["device_count"] == 1

    def test_stale_device_drops_off_live_snapshot(self):
        import intelligence.twin as twin_mod
        twin = _twin()
        twin.ingest_packets([_pkt(src_mac=PHONE, src_ip="192.168.1.11")])
        assert twin.snapshot()["stats"]["device_count"] == 1
        # Age the client past the active window without deleting the node.
        node = twin._nodes[f"mac:{PHONE}"]
        node.last_seen = time.time() - (twin_mod.TWIN_ACTIVE_SECONDS + 60)
        snap = twin.snapshot()
        assert snap["stats"]["device_count"] == 0
        assert f"mac:{PHONE}" not in {n["id"] for n in snap["nodes"]}
        assert snap["edges"] == []

    def test_self_and_gateway_always_present_even_if_idle(self):
        import intelligence.twin as twin_mod
        twin = _twin(our_mac=LAPTOP, our_ip="192.168.1.10",
                     gateway_mac=GATEWAY, gateway_ip="192.168.1.1")
        twin.ingest_packets([
            _pkt(src_mac=LAPTOP, dst_mac=GATEWAY,
                 src_ip="192.168.1.10", dst_ip="192.168.1.1"),
        ])
        for node in twin._nodes.values():
            node.last_seen = time.time() - (twin_mod.TWIN_ACTIVE_SECONDS + 60)
        types = {n["type"] for n in twin.snapshot()["nodes"]}
        assert "self" in types and "gateway" in types


class TestBusConsumption:

    def test_end_to_end_via_bus(self):
        import threading
        bus = EventBus()
        shutdown = threading.Event()
        twin = TwinBuilder(bus=bus, shutdown_event=shutdown, seed_from_db=False)
        assert twin.start() is True
        try:
            bus.publish("packet.batch", [_pkt()])
            bus.publish("dns.query", {"source_mac": LAPTOP, "qname": "example.com"})
            deadline = time.time() + 3
            while time.time() < deadline and twin.events_consumed < 2:
                time.sleep(0.05)
            snap = twin.snapshot()
            assert snap["stats"]["node_count"] >= 2
            node = next(n for n in snap["nodes"] if n["id"] == f"mac:{LAPTOP}")
            assert "example.com" in node["recent_dns"]
        finally:
            shutdown.set()
            twin.stop()
