"""
test_vpn_detector.py - VPN detection & classification (W3)
==========================================================

Detect-and-classify only: we assert the detector flags a tunnel, names the
provider from the offline IP map, and reports honest volume/duration — and
that it stays quiet on ordinary browsing.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.vpn_detector import VpnDetector


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
        self.vpn_alerts = []

    def create_vpn_alert(self, **kwargs):
        self.vpn_alerts.append(kwargs)
        return len(self.vpn_alerts)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def engine():
    return RecordingAlertEngine()


@pytest.fixture
def detector(engine, clock):
    return VpnDetector(alert_engine=engine, now_fn=clock)


def _flow(src="aa:bb:cc:dd:ee:01", dst_ip="203.0.113.9", dst_port=443,
          bytes_total=1000, protocol="UDP", **extra):
    row = {"source_mac": src, "source_ip": "192.168.137.50",
           "dest_ip": dst_ip, "dest_port": dst_port, "protocol": protocol,
           "bytes_total": bytes_total, "packets_total": 4, "is_control": 0}
    row.update(extra)
    return row


class TestProtocolSignatures:

    def test_wireguard_port_fires_immediately(self, detector, engine):
        detector.ingest_flow(_flow(dst_port=51820, bytes_total=500))
        assert len(engine.vpn_alerts) == 1
        ev = engine.vpn_alerts[0]["evidence"][0]
        assert ev["signal"] == "protocol_signature"
        assert ev["protocol"] == "WireGuard"

    def test_openvpn_and_ipsec_ports(self, detector, engine):
        detector.ingest_flow(_flow(src="aa:bb:cc:dd:ee:02", dst_port=1194))
        detector.ingest_flow(_flow(src="aa:bb:cc:dd:ee:03", dst_port=500))
        protocols = {a["evidence"][0]["protocol"] for a in engine.vpn_alerts}
        assert "OpenVPN" in protocols
        assert "IPsec/IKE" in protocols

    def test_dedup_per_device(self, detector, engine):
        for _ in range(5):
            detector.ingest_flow(_flow(dst_port=51820))
        assert len(engine.vpn_alerts) == 1


class TestTunnelShapeHeuristic:

    def test_high_volume_to_vpn_provider_fires(self, detector, engine, clock):
        # Proton range from data/ip_org_ranges.json
        proton_ip = "185.159.157.5"
        # Accumulate > 2MB over > 120s to a known VPN provider on 443.
        for _ in range(30):
            detector.ingest_flow(_flow(dst_ip=proton_ip, dst_port=443,
                                       bytes_total=100_000))
            clock.advance(10)
        vpn = [a for a in engine.vpn_alerts]
        assert len(vpn) == 1
        ev = vpn[0]["evidence"][0]
        assert ev["signal"] == "tunnel_shape"
        assert ev["provider"] == "Proton"

    def test_normal_browsing_stays_quiet(self, detector, engine, clock):
        # Lots of 443 traffic, but to a non-VPN provider (Google) → no VPN.
        for _ in range(30):
            detector.ingest_flow(_flow(dst_ip="142.250.67.46", dst_port=443,
                                       bytes_total=100_000))
            clock.advance(10)
        assert engine.vpn_alerts == []

    def test_small_flow_to_vpn_ip_below_threshold_quiet(self, detector, engine, clock):
        # A trickle to a VPN IP that never reaches the volume/duration bar.
        detector.ingest_flow(_flow(dst_ip="185.159.157.5", dst_port=443,
                                   bytes_total=1000))
        assert engine.vpn_alerts == []


class TestContextAndState:

    def test_host_and_gateway_ignored(self, detector, engine):
        detector.set_context(local_macs=["11:22:33:44:55:66"],
                             gateway_mac="aa:aa:aa:aa:aa:aa")
        detector.ingest_flow(_flow(src="11:22:33:44:55:66", dst_port=51820))
        detector.ingest_flow(_flow(src="aa:aa:aa:aa:aa:aa", dst_port=51820))
        assert engine.vpn_alerts == []

    def test_internal_destination_ignored(self, detector, engine):
        detector.ingest_flow(_flow(dst_ip="192.168.137.5", dst_port=51820))
        assert engine.vpn_alerts == []

    def test_badge_exposed(self, detector, engine):
        detector.ingest_flow(_flow(dst_port=51820))
        badge = detector.get_device_vpn("aa:bb:cc:dd:ee:01")
        assert badge is not None
        assert badge["protocol"] == "WireGuard"

    def test_stats_shape(self, detector):
        s = detector.get_stats()
        assert set(s) >= {"running", "flows_seen", "vpns_found", "active_devices"}
