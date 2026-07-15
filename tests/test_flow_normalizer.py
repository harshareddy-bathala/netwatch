"""
test_flow_normalizer.py - Flow Normalizer Tests (Phase 0, AI-first)
====================================================================

Covers ``intelligence.flow_normalizer``: packet-batch aggregation into
flows, idle/max-age flushing, DNS telemetry extraction, and end-to-end
consumption from the event bus.  DB writes are injected fakes.
"""

import sys
import os
import threading
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus
from intelligence.flow_normalizer import FlowNormalizer


def _pkt(src="192.168.1.10", dst="1.2.3.4", sport=50000, dport=443,
         proto="HTTPS", direction="upload", nbytes=1000, **extra):
    d = {
        "timestamp": datetime(2026, 7, 14, 10, 0, 0),
        "source_ip": src, "dest_ip": dst,
        "source_port": sport, "dest_port": dport,
        "protocol": proto, "direction": direction,
        "bytes": nbytes,
        "source_mac": "AA:BB:CC:DD:EE:01", "dest_mac": "AA:BB:CC:DD:EE:02",
        "is_control_traffic": False,
    }
    d.update(extra)
    return d


def _make_normalizer(**kw):
    saved_flows, saved_dns = [], []
    norm = FlowNormalizer(
        bus=EventBus(),
        save_flows=lambda rows: (saved_flows.extend(rows), len(rows))[1],
        save_dns=lambda rows: (saved_dns.extend(rows), len(rows))[1],
        **kw,
    )
    return norm, saved_flows, saved_dns


class TestAggregation:

    def test_same_five_tuple_aggregates_into_one_flow(self):
        norm, flows, _ = _make_normalizer()
        norm.ingest_batch([_pkt(nbytes=100), _pkt(nbytes=200), _pkt(nbytes=300)])
        assert len(norm._flows) == 1
        norm.flush(force=True)
        assert len(flows) == 1
        assert flows[0]["bytes_total"] == 600
        assert flows[0]["packets_total"] == 3
        assert flows[0]["protocol"] == "HTTPS"
        assert flows[0]["source_mac"] == "AA:BB:CC:DD:EE:01"

    def test_distinct_tuples_create_distinct_flows(self):
        norm, flows, _ = _make_normalizer()
        norm.ingest_batch([
            _pkt(dport=443),
            _pkt(dport=80, proto="HTTP"),
            _pkt(dst="5.6.7.8"),
        ])
        norm.flush(force=True)
        assert len(flows) == 3

    def test_no_flush_while_flow_active(self):
        norm, flows, _ = _make_normalizer(idle_timeout=30, max_age=300)
        norm.ingest_batch([_pkt()])
        norm.flush(force=False)  # not idle yet
        assert flows == []
        assert len(norm._flows) == 1

    def test_idle_flow_is_flushed(self):
        norm, flows, _ = _make_normalizer(idle_timeout=0.05, max_age=300)
        norm.ingest_batch([_pkt()])
        time.sleep(0.08)
        norm.flush(force=False)
        assert len(flows) == 1
        assert norm._flows == {}

    def test_flow_completed_published_on_bus(self):
        norm, _, _ = _make_normalizer()
        sub = norm._bus.subscribe(["flow.completed"], name="listener")
        norm.ingest_batch([_pkt()])
        norm.flush(force=True)
        event = sub.get(timeout=0.1)
        assert event is not None
        assert event.payload["source_ip"] == "192.168.1.10"

    def test_max_active_guard_forces_flush(self):
        norm, flows, _ = _make_normalizer(max_active=5)
        batch = [_pkt(sport=50000 + i) for i in range(10)]
        norm.ingest_batch(batch)
        # Guard flushed mid-batch; nothing lost overall
        norm.flush(force=True)
        assert len(flows) == 10


class TestDnsTelemetry:

    def test_dns_query_packet_produces_dns_row(self):
        norm, _, dns = _make_normalizer()
        norm.ingest_batch([
            _pkt(dport=53, proto="DNS", dns_qname="example.com", dns_qtype=1),
        ])
        norm.flush(force=True)
        assert len(dns) == 1
        assert dns[0]["qname"] == "example.com"
        assert dns[0]["qtype"] == 1
        assert dns[0]["source_mac"] == "AA:BB:CC:DD:EE:01"

    def test_dns_query_published_on_bus(self):
        norm, _, _ = _make_normalizer()
        sub = norm._bus.subscribe(["dns.query"], name="dns-listener")
        norm.ingest_batch([
            _pkt(dport=53, proto="DNS", dns_qname="tunnel.evil.example", dns_qtype=16),
        ])
        event = sub.get(timeout=0.1)
        assert event is not None
        assert event.payload["qname"] == "tunnel.evil.example"

    def test_non_dns_packets_produce_no_dns_rows(self):
        norm, _, dns = _make_normalizer()
        norm.ingest_batch([_pkt()])
        norm.flush(force=True)
        assert dns == []


class TestEndToEndViaBus:

    def test_consumes_packet_batch_events(self):
        bus = EventBus()
        shutdown = threading.Event()
        saved_flows = []
        norm = FlowNormalizer(
            bus=bus,
            shutdown_event=shutdown,
            save_flows=lambda rows: (saved_flows.extend(rows), len(rows))[1],
            save_dns=lambda rows: len(rows),
            idle_timeout=0.05,
            flush_interval=0.05,
        )
        assert norm.start() is True
        try:
            bus.publish("packet.batch", [_pkt(nbytes=500)])
            deadline = time.time() + 3
            while time.time() < deadline and not saved_flows:
                time.sleep(0.05)
            assert len(saved_flows) == 1
            assert saved_flows[0]["bytes_total"] == 500
            assert norm.get_stats()["batches_ingested"] == 1
        finally:
            shutdown.set()
            norm.stop()

    def test_stop_flushes_remaining_flows(self):
        bus = EventBus()
        shutdown = threading.Event()
        saved_flows = []
        norm = FlowNormalizer(
            bus=bus,
            shutdown_event=shutdown,
            save_flows=lambda rows: (saved_flows.extend(rows), len(rows))[1],
            save_dns=lambda rows: len(rows),
            idle_timeout=300,      # would never expire naturally
            flush_interval=0.05,
        )
        assert norm.start() is True
        bus.publish("packet.batch", [_pkt()])
        deadline = time.time() + 3
        while time.time() < deadline and norm.get_stats()["batches_ingested"] == 0:
            time.sleep(0.05)
        shutdown.set()
        norm.stop()
        assert len(saved_flows) == 1


class TestDbRoundTrip:
    """Round-trip through the real flow_queries against a temp SQLite DB."""

    def test_save_and_read_back(self, tmp_path, monkeypatch):
        import sqlite3
        from contextlib import contextmanager

        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.row_factory = sqlite3.Row
        # Create tables via the migration SQL (schema parity check)
        db.execute("""
            CREATE TABLE flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_seen TIMESTAMP NOT NULL, last_seen TIMESTAMP NOT NULL,
                source_ip TEXT NOT NULL, dest_ip TEXT NOT NULL,
                source_port INTEGER, dest_port INTEGER,
                protocol TEXT NOT NULL DEFAULT 'UNKNOWN',
                direction TEXT DEFAULT 'unknown',
                source_mac TEXT, dest_mac TEXT,
                bytes_total INTEGER DEFAULT 0, packets_total INTEGER DEFAULT 0,
                is_control INTEGER DEFAULT 0, duration_seconds REAL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                source_ip TEXT, source_mac TEXT,
                qname TEXT NOT NULL, qtype INTEGER, protocol TEXT DEFAULT 'DNS'
            )
        """)

        @contextmanager
        def fake_conn():
            yield db

        import database.queries.flow_queries as fq
        monkeypatch.setattr(fq, "get_connection", fake_conn)

        n = fq.save_flows_batch([{
            "first_seen": "2026-07-14 10:00:00", "last_seen": "2026-07-14 10:00:30",
            "source_ip": "192.168.1.10", "dest_ip": "1.2.3.4",
            "source_port": 50000, "dest_port": 443,
            "protocol": "HTTPS", "direction": "upload",
            "source_mac": "AA:BB:CC:DD:EE:01", "dest_mac": None,
            "bytes_total": 600, "packets_total": 3,
            "is_control": 0, "duration_seconds": 30.0,
        }])
        assert n == 1
        rows = fq.get_recent_flows(limit=10)
        assert len(rows) == 1 and rows[0]["bytes_total"] == 600

        n = fq.save_dns_queries_batch([{
            "timestamp": "2026-07-14 10:00:00", "source_ip": "192.168.1.10",
            "source_mac": "AA:BB:CC:DD:EE:01", "qname": "example.com",
            "qtype": 1, "protocol": "DNS",
        }])
        assert n == 1
        rows = fq.get_recent_dns_queries(limit=10, mac="AA:BB:CC:DD:EE:01")
        assert len(rows) == 1 and rows[0]["qname"] == "example.com"
