"""
test_false_positive_guards.py - Live-network false-positive regressions
========================================================================

Regressions for the false alarms observed on a real hotspot session
(2026-07-16 logs):

* NetWatch's own ping sweep / return traffic read as "port scans" from
  the capture host and gateway MACs.
* Normal browsing (many CDN hosts on 443) read as a "network sweep".
* Instagram/WhatsApp keepalives (~51s cadence, 3-4% jitter on 443/5222)
  read as C2 beaconing.
* The capture host's own adapters alerted as "rogue devices".
* A health alert fused into an unrelated security incident because both
  carried no device MAC.
* The twin: seeded nodes rendered "live now" after restart, mode changes
  kept the previous network's graph, and node IPs flapped to fe80::/
  external addresses.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus
from intelligence.threats import ThreatDetector
from intelligence.twin import TwinBuilder


class FakeClock:
    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt
        return self.t


class RecordingAlertEngine:
    def __init__(self):
        self.alerts = []

    def create_threat_alert(self, **kwargs):
        self.alerts.append(kwargs)
        return len(self.alerts)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def engine():
    return RecordingAlertEngine()


@pytest.fixture
def detector(engine, clock):
    return ThreatDetector(alert_engine=engine, seed_known_macs=False,
                          now_fn=clock)


def _flow(src="aa:bb:cc:dd:ee:01", src_ip="192.168.137.50",
          dst_ip="192.168.137.9", dst_port=80, protocol="TCP", **extra):
    row = {
        "source_mac": src, "source_ip": src_ip,
        "dest_ip": dst_ip, "dest_port": dst_port,
        "protocol": protocol, "bytes_total": 200, "packets_total": 2,
        "is_control": 0,
    }
    row.update(extra)
    return row


HOST_MAC = "2e:d0:43:a5:22:70"      # hotspot adapter (the machine itself)
GW_MAC = "5c:8c:30:4f:3d:2c"        # upstream gateway


class TestSelfAndGatewayExemption:

    def test_own_discovery_sweep_not_a_port_scan(self, detector, engine):
        detector.set_context(local_macs=[HOST_MAC], gateway_mac=GW_MAC)
        # NetWatch's ping sweep / connection handling: host MAC touching
        # many ports on a client — must never alert.
        for port in range(400, 425):
            detector.ingest_flow(_flow(src=HOST_MAC, dst_port=port))
        assert engine.alerts == []

    def test_gateway_return_traffic_not_a_port_scan(self, detector, engine):
        detector.set_context(local_macs=[HOST_MAC], gateway_mac=GW_MAC)
        for port in range(50000, 50025):
            detector.ingest_flow(_flow(src=GW_MAC, dst_port=port))
        assert engine.alerts == []

    def test_own_adapters_never_rogue(self, detector, engine):
        detector.set_context(local_macs=[HOST_MAC], gateway_mac=GW_MAC)
        detector.ingest_flow(_flow(src=HOST_MAC))
        detector.ingest_flow(_flow(src=GW_MAC))
        rogues = [a for a in engine.alerts if a["threat_type"] == "rogue_device"]
        assert rogues == []


class TestEphemeralAndExternalScanGuards:

    def test_return_traffic_to_ephemeral_ports_not_vertical_scan(
            self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        # A busy client's return flows: many distinct ephemeral dest ports.
        for port in range(49152, 49180):
            detector.ingest_flow(_flow(dst_port=port))
        assert [a for a in engine.alerts
                if a["threat_type"] == "port_scan"] == []

    def test_browsing_many_external_hosts_not_horizontal_sweep(
            self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        # Instagram/YouTube: 443 to a dozen CDN edges in two minutes.
        for i in range(1, 15):
            detector.ingest_flow(
                _flow(dst_ip=f"57.144.168.{i}", dst_port=443))
        assert [a for a in engine.alerts
                if a["threat_type"] == "port_scan"] == []

    def test_internal_sweep_still_fires(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for i in range(1, 15):
            detector.ingest_flow(
                _flow(dst_ip=f"192.168.137.{i}", dst_port=80))
        sweeps = [a for a in engine.alerts if a["threat_type"] == "port_scan"]
        assert len(sweeps) == 1
        assert sweeps[0]["evidence"][0]["signal"] == "horizontal_scan"


class TestBeaconKeepaliveGuard:

    def _beacon(self, detector, clock, dst_port, jitter_pattern):
        for dt in jitter_pattern:
            detector.ingest_flow(
                _flow(dst_ip="57.144.168.192", dst_port=dst_port))
            clock.advance(dt)

    def test_messaging_keepalive_on_443_quiet(self, detector, engine, clock):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        # ~51s cadence with ~4% jitter — the observed Instagram heartbeat.
        self._beacon(detector, clock, 443, [49, 53, 51, 49, 53, 51, 49, 53])
        assert [a for a in engine.alerts
                if a["threat_type"] == "beaconing"] == []

    def test_machine_regular_on_443_still_fires(self, detector, engine, clock):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        self._beacon(detector, clock, 443, [60.0] * 8)
        beacons = [a for a in engine.alerts if a["threat_type"] == "beaconing"]
        assert len(beacons) == 1

    def test_uncommon_port_keeps_normal_jitter_budget(
            self, detector, engine, clock):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        # Same 4% jitter, but on a port no messaging app keeps alive.
        self._beacon(detector, clock, 4444, [49, 53, 51, 49, 53, 51, 49, 53])
        beacons = [a for a in engine.alerts if a["threat_type"] == "beaconing"]
        assert len(beacons) == 1


class TestTwinLivenessAndReset:

    def _twin(self, **ctx):
        twin = TwinBuilder(bus=EventBus(), seed_from_db=False)
        if ctx:
            twin.set_context(**ctx)
        return twin

    def _pkt(self, src_mac="aa:bb:cc:00:00:01", dst_mac="aa:bb:cc:00:00:99",
             src_ip="192.168.1.10", dst_ip="93.184.216.34", **extra):
        d = {"source_mac": src_mac, "dest_mac": dst_mac,
             "source_ip": src_ip, "dest_ip": dst_ip,
             "protocol": "HTTPS", "bytes": 1000}
        d.update(extra)
        return d

    def test_mode_change_resets_graph(self):
        twin = self._twin()
        twin.ingest_mode_change({"old_mode": None, "new_mode": "public_network"})
        twin.ingest_packets([self._pkt()])
        assert twin.snapshot()["nodes"]
        twin.ingest_mode_change({"old_mode": "public_network",
                                 "new_mode": "hotspot"})
        snap = twin.snapshot()
        assert snap["nodes"] == []
        assert snap["edges"] == []
        assert snap["mode"] == "hotspot"

    def test_same_mode_event_does_not_reset(self):
        twin = self._twin()
        twin.ingest_mode_change({"old_mode": None, "new_mode": "hotspot"})
        twin.ingest_packets([self._pkt()])
        twin.ingest_mode_change({"old_mode": "hotspot", "new_mode": "hotspot"})
        assert twin.snapshot()["nodes"]

    def test_seeded_nodes_keep_stored_liveness(self, monkeypatch):
        """A device last seen 20h ago must not render as live after restart."""
        import intelligence.twin as twin_mod
        old = time.time() - 20 * 3600
        old_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(old))

        def fake_devices(limit=500, hours=24):
            return [{"mac_address": "aa:bb:cc:00:00:07",
                     "ip_address": "192.168.1.7",
                     "hostname": "old-laptop", "vendor": "",
                     "first_seen": old_str, "last_seen": old_str}]

        import database.queries.device_queries as dq
        import database.queries.flow_queries as fq
        monkeypatch.setattr(dq, "get_all_devices", fake_devices)
        monkeypatch.setattr(fq, "get_recent_flows", lambda **kw: [])

        twin = twin_mod.TwinBuilder(bus=EventBus(), seed_from_db=True)
        twin._seed()
        node = twin._nodes["mac:aa:bb:cc:00:00:07"]
        assert node.last_seen == pytest.approx(old, abs=5)
        # And therefore it is not in the live snapshot.
        ids = {n["id"] for n in twin.snapshot()["nodes"]}
        assert "mac:aa:bb:cc:00:00:07" not in ids

    def test_ip_never_downgrades_to_link_local(self):
        twin = self._twin()
        twin.ingest_packets([self._pkt(src_ip="192.168.137.178")])
        twin.ingest_packets([
            self._pkt(src_ip="fe80::14c9:99ff:fe2b:3a27",
                      dst_ip="ff02::fb")])  # noise dst dropped anyway
        twin.ingest_packets([
            self._pkt(src_ip="fe80::14c9:99ff:fe2b:3a27",
                      dst_ip="2001:4860:4860::8888", direction="upload")])
        node = twin._nodes["mac:aa:bb:cc:00:00:01"]
        assert node.ip == "192.168.137.178"

    def test_self_ip_pinned_to_context(self):
        twin = self._twin(our_mac="aa:bb:cc:00:00:01", our_ip="192.168.1.68")
        # A mis-attributed packet claims the self MAC talks from an
        # external IP — the display address must stay authoritative.
        twin.ingest_packets([
            self._pkt(src_ip="40.104.207.66", direction="upload")])
        node = twin._nodes["mac:aa:bb:cc:00:00:01"]
        assert node.node_type == "self"
        assert node.ip == "192.168.1.68"


class TestIncidentCategoryFusion:

    def test_maclless_alerts_fuse_only_within_category(self, monkeypatch):
        from intelligence.incidents import IncidentManager
        from database.queries import incident_queries as iq

        calls = []

        def fake_find(mac, since, category=None):
            calls.append((mac, category))
            return None

        monkeypatch.setattr(iq, "find_open_incident", fake_find)
        monkeypatch.setattr(iq, "create_incident", lambda **kw: 1)
        monkeypatch.setattr(iq, "attach_alert", lambda *a, **kw: True)

        mgr = IncidentManager(window_minutes=30)
        mgr.triage(alert_id=1, alert_type="security", severity="warning",
                   device_mac=None, message="unknown device")
        mgr.triage(alert_id=2, alert_type="health", severity="warning",
                   device_mac=None, message="high cpu")
        # No-MAC lookups must be category-scoped; device lookups are not.
        assert calls == [(None, "security"), (None, "health")]

        mgr.triage(alert_id=3, alert_type="security", severity="warning",
                   device_mac="AA:BB:CC:00:00:01", message="scan")
        assert calls[-1] == ("aa:bb:cc:00:00:01", None)
