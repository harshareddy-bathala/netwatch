"""
test_tls_sni.py - TLS SNI extraction + activity noise filtering
================================================================

The Activity feed's answer to encrypted DNS: clients using Private DNS
(DoH/DoT) hide their lookups, but the TLS ClientHello still names the
site (SNI).  Covers the raw parser, the flow-normalizer plumbing that
turns SNI into activity rows, and the resolver-noise filter that kept
burying the feed in ``*.in-addr.arpa`` rows.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.packet_processor import extract_tls_sni
from intelligence.flow_normalizer import FlowNormalizer, _is_noise_qname
from intelligence.event_bus import EventBus


def make_client_hello(server_name: str, with_sni: bool = True) -> bytes:
    """Minimal but structurally valid TLS 1.2 ClientHello record."""
    name = server_name.encode("ascii")
    if with_sni:
        sni_entry = b"\x00" + len(name).to_bytes(2, "big") + name
        sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
        ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    else:
        ext = b""
    # a padding-ish unknown extension before SNI to exercise the walk
    ext = b"\xff\x01\x00\x01\x00" + ext
    extensions = len(ext).to_bytes(2, "big") + ext

    body = (
        b"\x03\x03" + bytes(32)          # version + random
        + b"\x00"                        # session id (empty)
        + b"\x00\x02\x13\x01"            # one cipher suite
        + b"\x01\x00"                    # compression: null
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class TestExtractSni:

    def test_extracts_server_name(self):
        payload = make_client_hello("www.instagram.com")
        assert extract_tls_sni(payload) == "www.instagram.com"

    def test_no_sni_extension(self):
        payload = make_client_hello("x", with_sni=False)
        assert extract_tls_sni(payload) is None

    def test_not_a_client_hello(self):
        assert extract_tls_sni(b"") is None
        assert extract_tls_sni(b"\x17\x03\x03\x00\x05hello" + bytes(50)) is None

    def test_truncated_payload_is_safe(self):
        payload = make_client_hello("example.com")
        for cut in (10, 40, 60, len(payload) - 3):
            extract_tls_sni(payload[:cut])  # must not raise


class TestNoiseQnames:

    def test_reverse_dns_is_noise(self):
        assert _is_noise_qname("142.137.168.192.in-addr.arpa")
        assert _is_noise_qname("7.2.a.3.b.2.e.f.f.9.9.c.ip6.arpa")

    def test_mdns_and_wpad_are_noise(self):
        assert _is_noise_qname("_googlecast._tcp.local")
        assert _is_noise_qname("wpad")
        assert _is_noise_qname("wpad.lan")

    def test_real_sites_are_not_noise(self):
        assert not _is_noise_qname("www.instagram.com")
        assert not _is_noise_qname("i.ytimg.com")


class TestNormalizerPlumbing:

    def _normalizer(self, saved_dns):
        return FlowNormalizer(
            bus=EventBus(),
            save_flows=lambda rows: len(rows),
            save_dns=lambda rows: saved_dns.extend(rows) or len(rows),
        )

    def test_sni_becomes_activity_row(self):
        saved = []
        n = self._normalizer(saved)
        n.ingest_batch([{
            "source_ip": "192.168.137.142", "dest_ip": "57.144.168.192",
            "source_port": 51000, "dest_port": 443, "protocol": "HTTPS",
            "direction": "upload", "source_mac": "22:5e:3e:1a:d0:f3",
            "bytes": 517, "tls_sni": "gateway.instagram.com",
        }])
        n.flush(force=True)
        assert [r["qname"] for r in saved] == ["gateway.instagram.com"]
        assert saved[0]["protocol"] == "TLS"
        assert saved[0]["source_mac"] == "22:5e:3e:1a:d0:f3"

    def test_reverse_dns_rows_are_dropped(self):
        saved = []
        n = self._normalizer(saved)
        n.ingest_batch([{
            "source_ip": "192.168.137.1", "dest_ip": "192.168.137.255",
            "source_port": 5353, "dest_port": 5353, "protocol": "DNS",
            "direction": "other", "source_mac": "2e:d0:43:a5:22:70",
            "bytes": 80, "dns_qname": "1.137.168.192.in-addr.arpa",
            "dns_qtype": 12,
        }])
        n.flush(force=True)
        assert saved == []

    def test_real_dns_rows_survive(self):
        saved = []
        n = self._normalizer(saved)
        n.ingest_batch([{
            "source_ip": "192.168.137.178", "dest_ip": "192.168.137.1",
            "source_port": 40000, "dest_port": 53, "protocol": "DNS",
            "direction": "other", "source_mac": "16:c9:99:2b:3a:27",
            "bytes": 60, "dns_qname": "www.google.com", "dns_qtype": 1,
        }])
        n.flush(force=True)
        assert [r["qname"] for r in saved] == ["www.google.com"]
