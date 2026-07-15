"""
test_threats.py - Threat Detector Pack (Phase 2)
=================================================

Unit coverage for ``intelligence.threats.ThreatDetector``: each detector
fires on its signature, stays quiet on benign traffic, dedups per
(threat, device), and emits explainable evidence + confidence.

The detector is driven directly through ``ingest_flow`` / ``ingest_dns``
with a controllable clock — no bus thread, no DB.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.threats import (
    ThreatDetector, _shannon_entropy, _registered_domain,
)


class FakeClock:
    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt
        return self.t


class RecordingAlertEngine:
    """Captures create_threat_alert calls."""

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
    return ThreatDetector(
        alert_engine=engine,
        seed_known_macs=False,
        now_fn=clock,
    )


def _flow(src="aa:bb:cc:dd:ee:01", src_ip="10.0.0.5", dst_ip="10.0.0.9",
          dst_port=80, protocol="TCP", **extra):
    row = {
        "source_mac": src, "source_ip": src_ip,
        "dest_ip": dst_ip, "dest_port": dst_port,
        "protocol": protocol, "bytes_total": 200, "packets_total": 2,
        "is_control": 0,
    }
    row.update(extra)
    return row


# ===================================================================
# Helpers
# ===================================================================

class TestHelpers:

    def test_entropy_uniform_is_low(self):
        assert _shannon_entropy("aaaaaaaa") == 0.0

    def test_entropy_random_is_high(self):
        assert _shannon_entropy("a1b2c3d4e5f6g7") > 3.0

    def test_registered_domain(self):
        assert _registered_domain("a.b.c.evil.com") == "evil.com"
        assert _registered_domain("evil.com") == "evil.com"
        assert _registered_domain("localhost") == "localhost"


# ===================================================================
# Port scan
# ===================================================================

class TestPortScan:

    def test_vertical_scan_fires(self, detector, engine):
        # rogue_device pre-registers the MAC so it doesn't also alert.
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for port in range(1000, 1020):   # 20 distinct ports, threshold 15
            detector.ingest_flow(_flow(dst_ip="10.0.0.9", dst_port=port))
        scans = [a for a in engine.alerts if a["threat_type"] == "port_scan"]
        assert len(scans) == 1
        ev = scans[0]["evidence"][0]
        assert ev["signal"] == "vertical_scan"
        assert ev["distinct_ports"] >= 15
        assert scans[0]["confidence"] > 0.5

    def test_horizontal_sweep_fires(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for host in range(1, 12):        # 11 hosts on one port, threshold 10
            detector.ingest_flow(_flow(dst_ip=f"10.0.0.{host}", dst_port=445))
        sweeps = [a for a in engine.alerts if a["threat_type"] == "port_scan"]
        assert len(sweeps) == 1
        assert sweeps[0]["evidence"][0]["signal"] == "horizontal_scan"

    def test_benign_traffic_quiet(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for _ in range(30):
            detector.ingest_flow(_flow(dst_ip="10.0.0.9", dst_port=443))
        assert [a for a in engine.alerts if a["threat_type"] == "port_scan"] == []

    def test_dedup_per_target(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for _ in range(2):
            for port in range(2000, 2020):
                detector.ingest_flow(_flow(dst_ip="10.0.0.9", dst_port=port))
        scans = [a for a in engine.alerts if a["threat_type"] == "port_scan"]
        assert len(scans) == 1


# ===================================================================
# Beaconing
# ===================================================================

class TestBeaconing:

    def test_regular_beacon_fires(self, detector, engine, clock):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for _ in range(8):               # 7 intervals, threshold 6
            detector.ingest_flow(
                _flow(dst_ip="203.0.113.7", src_ip="10.0.0.5", dst_port=443)
            )
            clock.advance(60)            # dead-steady 60s cadence
        beacons = [a for a in engine.alerts if a["threat_type"] == "beaconing"]
        assert len(beacons) == 1
        ev = beacons[0]["evidence"][0]
        assert ev["mean_interval_seconds"] == pytest.approx(60, abs=1)
        assert ev["jitter_ratio"] < 0.25

    def test_jittery_traffic_quiet(self, detector, engine, clock):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for dt in (5, 90, 12, 200, 7, 140, 33, 300):
            detector.ingest_flow(_flow(dst_ip="203.0.113.7", dst_port=443))
            clock.advance(dt)
        assert [a for a in engine.alerts if a["threat_type"] == "beaconing"] == []

    def test_internal_destination_ignored(self, detector, engine, clock):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for _ in range(10):
            detector.ingest_flow(_flow(dst_ip="10.0.0.9", dst_port=443))
            clock.advance(60)
        assert [a for a in engine.alerts if a["threat_type"] == "beaconing"] == []


# ===================================================================
# DNS tunneling
# ===================================================================

class TestDnsTunneling:

    def _dns(self, qname, src="aa:bb:cc:dd:ee:01"):
        return {"source_mac": src, "source_ip": "10.0.0.5", "qname": qname}

    def test_high_entropy_burst_fires(self, detector, engine):
        import secrets
        for _ in range(30):              # threshold 25
            label = secrets.token_hex(30)  # 60 hex chars, high entropy
            detector.ingest_dns(self._dns(f"{label}.tunnel.evil.com"))
        tun = [a for a in engine.alerts if a["threat_type"] == "dns_tunneling"]
        assert len(tun) == 1
        ev = tun[0]["evidence"][0]
        assert ev["domain"] == "evil.com"
        assert ev["queries_in_window"] >= 25

    def test_normal_dns_quiet(self, detector, engine):
        for host in ("www", "mail", "cdn", "api", "img"):
            for _ in range(10):
                detector.ingest_dns(self._dns(f"{host}.google.com"))
        assert [a for a in engine.alerts if a["threat_type"] == "dns_tunneling"] == []


# ===================================================================
# Rogue device
# ===================================================================

class TestRogueDevice:

    def test_unknown_mac_fires_once(self, detector, engine):
        detector.ingest_flow(_flow(src="de:ad:be:ef:00:01", src_ip="10.0.0.50"))
        detector.ingest_flow(_flow(src="de:ad:be:ef:00:01", src_ip="10.0.0.50"))
        rogue = [a for a in engine.alerts if a["threat_type"] == "rogue_device"]
        assert len(rogue) == 1
        assert rogue[0]["evidence"][0]["mac"] == "de:ad:be:ef:00:01"

    def test_known_mac_quiet(self, detector, engine):
        detector._known_macs.add("de:ad:be:ef:00:01")
        detector.ingest_flow(_flow(src="de:ad:be:ef:00:01", src_ip="10.0.0.50"))
        assert [a for a in engine.alerts if a["threat_type"] == "rogue_device"] == []

    def test_external_source_not_rogue(self, detector, engine):
        # A public source IP is the upstream router, not a new local device.
        detector.ingest_flow(_flow(src="de:ad:be:ef:00:02", src_ip="8.8.8.8"))
        assert [a for a in engine.alerts if a["threat_type"] == "rogue_device"] == []


# ===================================================================
# Lateral movement
# ===================================================================

class TestLateralMovement:

    def test_admin_port_fanout_fires(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for host in (10, 11, 12):        # 3 hosts, threshold 3
            detector.ingest_flow(_flow(dst_ip=f"10.0.0.{host}", dst_port=445))
        lat = [a for a in engine.alerts if a["threat_type"] == "lateral_movement"]
        assert len(lat) == 1
        assert lat[0]["evidence"][0]["distinct_hosts"] >= 3

    def test_single_host_admin_quiet(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for _ in range(10):
            detector.ingest_flow(_flow(dst_ip="10.0.0.10", dst_port=3389))
        assert [a for a in engine.alerts if a["threat_type"] == "lateral_movement"] == []

    def test_non_admin_ports_ignored(self, detector, engine):
        detector._known_macs.add("aa:bb:cc:dd:ee:01")
        for host in (10, 11, 12, 13):
            detector.ingest_flow(_flow(dst_ip=f"10.0.0.{host}", dst_port=443))
        assert [a for a in engine.alerts if a["threat_type"] == "lateral_movement"] == []


# ===================================================================
# Stats / degradation
# ===================================================================

class TestStats:

    def test_stats_shape(self, detector):
        s = detector.get_stats()
        assert set(s) >= {"running", "known_macs", "threats_found",
                          "flows_seen", "dns_seen"}

    def test_no_engine_does_not_raise(self, clock):
        det = ThreatDetector(alert_engine=None, seed_known_macs=False, now_fn=clock)
        det._known_macs.add("aa:bb:cc:dd:ee:01")
        for port in range(1000, 1020):
            det.ingest_flow(_flow(dst_ip="10.0.0.9", dst_port=port))
        assert det.threats_found >= 1
