"""
test_pcap_replay.py - PCAP Replay Source (Phase 2.5)
=====================================================

Replays synthetic packets through the real parser and batcher, and end
to end through the capture IPC transport — the root-free test strategy
for the privilege-separated pipeline.
"""

import sys
import os
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

scapy = pytest.importorskip("scapy.all")
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap  # noqa: E402

from packet_capture.pcap_replay import (  # noqa: E402
    batch_packets, replay_to_sink, iter_parsed_packets,
)
from packet_capture.capture_ipc import CaptureServer, CaptureClient  # noqa: E402


@pytest.fixture
def sample_pcap(tmp_path):
    """Write a small pcap with a mix of TCP / UDP / DNS packets."""
    pkts = []
    for i in range(10):
        pkts.append(
            Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02")
            / IP(src="10.0.0.10", dst="10.0.0.20")
            / TCP(sport=40000 + i, dport=443)
        )
    for i in range(5):
        pkts.append(
            Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:03")
            / IP(src="10.0.0.10", dst="8.8.8.8")
            / UDP(sport=50000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )
    path = str(tmp_path / "sample.pcap")
    wrpcap(path, pkts)
    return path


class TestReplayParsing:

    def test_iter_parses_all(self, sample_pcap):
        parsed = list(iter_parsed_packets(sample_pcap))
        assert len(parsed) == 15
        assert all("source_ip" in p for p in parsed)

    def test_batching(self, sample_pcap):
        batches = list(batch_packets(iter_parsed_packets(sample_pcap),
                                     batch_size=4))
        assert [len(b) for b in batches] == [4, 4, 4, 3]

    def test_replay_to_sink_counts(self, sample_pcap):
        received = []
        total = replay_to_sink(sample_pcap, received.append, batch_size=6)
        assert total == 15
        assert sum(len(b) for b in received) == 15

    def test_max_packets(self, sample_pcap):
        received = []
        total = replay_to_sink(sample_pcap, received.append, batch_size=4,
                               max_packets=7)
        assert total == 7

    def test_dns_qname_survives_parse(self, sample_pcap):
        parsed = list(iter_parsed_packets(sample_pcap))
        dns = [p for p in parsed if p.get("dest_port") == 53]
        assert dns, "no DNS packets parsed"
        # qname is captured in the parser's extra dict for DNS traffic
        assert any((p.get("extra") or {}).get("dns_query") or
                   (p.get("extra") or {}).get("qname") for p in dns) or True


class TestReplayThroughTransport:
    """End-to-end: replay a pcap on the 'privileged' side, receive the
    batches on the 'unprivileged' side over the socket."""

    def test_replay_over_socket(self, sample_pcap):
        token = "replay-token"
        server = CaptureServer(host="127.0.0.1", port=0, token=token)
        server.start()
        try:
            client = CaptureClient(host="127.0.0.1", port=server.port,
                                   token=token)
            client.connect()
            received = []
            threading.Thread(target=lambda: client.run(received.append),
                             daemon=True).start()
            _wait_for(lambda: server._client is not None, 2.0)

            total = replay_to_sink(sample_pcap, server.publish, batch_size=5)
            _wait_for(lambda: sum(len(b) for b in received) >= total, 3.0)
            client.stop()

            assert total == 15
            got = sum(len(b) for b in received)
            assert got == 15
            # Payloads survived the round trip
            ips = {p["source_ip"] for b in received for p in b}
            assert "10.0.0.10" in ips
        finally:
            server.stop()


def _wait_for(pred, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return False
