"""
test_capture_ipc.py - Capture Privilege-Separation Transport (Phase 2.5)
========================================================================

Exercises the capture IPC transport end-to-end over a real loopback
socket — framing codec, server/client handshake + auth, batch delivery,
and datetime revival — with no root and no live NIC.
"""

import sys
import os
import threading
import time
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.capture_ipc import (
    encode_batch, decode_batch, CaptureServer, CaptureClient,
    _MAX_FRAME,
)


# ===================================================================
# Codec
# ===================================================================

class TestCodec:

    def test_roundtrip_simple(self):
        batch = [{"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "bytes": 100}]
        frame = encode_batch(batch)
        # 4-byte length prefix + payload
        assert len(frame) > 4
        decoded = decode_batch(frame[4:])
        assert decoded == batch

    def test_datetime_revived(self):
        now = datetime(2026, 7, 15, 12, 30, 45)
        batch = [{"timestamp": now, "source_ip": "10.0.0.1"}]
        frame = encode_batch(batch)
        decoded = decode_batch(frame[4:])
        assert decoded[0]["timestamp"] == now
        assert isinstance(decoded[0]["timestamp"], datetime)

    def test_nested_extra_preserved(self):
        batch = [{"protocol": "DNS", "extra": {"qname": "example.com", "qtype": "A"}}]
        decoded = decode_batch(encode_batch(batch)[4:])
        assert decoded[0]["extra"]["qname"] == "example.com"

    def test_empty_batch(self):
        assert decode_batch(encode_batch([])[4:]) == []

    def test_oversize_batch_rejected(self):
        huge = [{"blob": "x" * (_MAX_FRAME + 10)}]
        with pytest.raises(ValueError):
            encode_batch(huge)

    def test_decode_non_list_rejected(self):
        import json
        with pytest.raises(ValueError):
            decode_batch(json.dumps({"not": "a list"}).encode())


# ===================================================================
# Server / client over loopback
# ===================================================================

TOKEN = "test-secret-token"


@pytest.fixture
def server():
    srv = CaptureServer(host="127.0.0.1", port=0, token=TOKEN)
    srv.start()
    yield srv
    srv.stop()


def _connected_client(server, token=TOKEN):
    client = CaptureClient(host="127.0.0.1", port=server.port, token=token)
    client.connect()
    return client


class TestServerClient:

    def test_handshake_and_delivery(self, server):
        client = _connected_client(server)
        received = []
        reader = threading.Thread(
            target=lambda: client.run(received.append), daemon=True)
        reader.start()

        # Give the server a moment to register the client, then publish.
        _wait_for(lambda: server._client is not None, 2.0)
        batch = [{"source_ip": "10.0.0.5", "bytes": 42,
                  "timestamp": datetime(2026, 7, 15, 9, 0, 0)}]
        server.publish(batch)

        _wait_for(lambda: len(received) >= 1, 2.0)
        client.stop()
        assert received[0][0]["source_ip"] == "10.0.0.5"
        assert received[0][0]["timestamp"] == datetime(2026, 7, 15, 9, 0, 0)

    def test_multiple_batches_ordered(self, server):
        client = _connected_client(server)
        received = []
        threading.Thread(target=lambda: client.run(received.append),
                         daemon=True).start()
        _wait_for(lambda: server._client is not None, 2.0)

        for i in range(20):
            server.publish([{"seq": i}])
        _wait_for(lambda: len(received) >= 20, 3.0)
        client.stop()
        seqs = [b[0]["seq"] for b in received]
        assert seqs == list(range(20))

    def test_bad_token_rejected(self, server):
        # A wrong token: the server accepts the TCP connection and sends the
        # magic, but closes immediately after reading the bad token.  The
        # client therefore never registers as the delivery target and
        # receives zero batches.
        client = CaptureClient(host="127.0.0.1", port=server.port,
                               token="wrong-token")
        client.connect()
        received = list(client.batches())   # stream closes empty
        assert received == []
        # A batch published now is dropped — no authenticated client.
        server.publish([{"seq": 1}])
        assert server._client is None
        assert server.batches_dropped >= 1

    def test_publish_without_client_drops(self, server):
        # No client connected — publish must not raise, just count drops.
        server.publish([{"seq": 1}])
        assert server.batches_dropped >= 1

    def test_large_batch_delivery(self, server):
        client = _connected_client(server)
        received = []
        threading.Thread(target=lambda: client.run(received.append),
                         daemon=True).start()
        _wait_for(lambda: server._client is not None, 2.0)

        big = [{"seq": i, "pad": "y" * 200} for i in range(500)]
        server.publish(big)
        _wait_for(lambda: len(received) >= 1, 3.0)
        client.stop()
        assert len(received[0]) == 500


def _wait_for(pred, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return False


# ===================================================================
# Capture daemon glue (endpoint advertisement + writer adapter)
# ===================================================================

class TestCaptureDaemonGlue:

    def test_endpoint_file_roundtrip(self, tmp_path):
        import capture_daemon as d
        path = str(tmp_path / "ep")
        d._write_endpoint_file(path, "127.0.0.1", 51999, "tok-abc")
        assert d.read_endpoint_file(path) == ("127.0.0.1", 51999, "tok-abc")

    def test_endpoint_file_missing(self):
        import capture_daemon as d
        assert d.read_endpoint_file("/no/such/endpoint/file") is None

    def test_server_writer_publishes(self):
        import capture_daemon as d
        srv = CaptureServer(host="127.0.0.1", port=0, token="x")
        srv.start()
        try:
            writer = d.CaptureServerWriter(srv)
            writer.start()
            writer.enqueue([{"a": 1}, {"a": 2}])
            writer.enqueue([])          # empty batch is a no-op
            writer.stop()
            assert writer.batches_written == 1
            assert writer.packets_written == 2
            assert writer.pending == 0
        finally:
            srv.stop()
