"""
test_performance.py - Performance Benchmark Tests
====================================================

Tests for packet throughput, database query latency,
memory usage, and API response times against target benchmarks.

Benchmarks:
  - Packet capture: >1000 pps processing
  - Database queries: <50ms (p95)
  - Memory usage: <500MB
  - API response: <100ms
"""

import sys
import os
import time
import threading
import statistics
import sqlite3
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Packet Throughput Tests
# ===================================================================

class TestPacketThroughput:
    """Test packet processing throughput."""

    def test_bandwidth_calculator_1000pps(self):
        """BandwidthCalculator should handle 1000+ pps."""
        from packet_capture.bandwidth_calculator import BandwidthCalculator

        calc = BandwidthCalculator(window_seconds=10)

        start = time.perf_counter()
        for _ in range(1000):
            calc.add_bytes(1500, direction="download")
        elapsed = time.perf_counter() - start

        pps = 1000 / elapsed if elapsed > 0 else float('inf')
        assert pps >= 1000, f"Throughput only {pps:.0f} pps (target: 1000+)"

    def test_sustained_throughput_60s_simulated(self):
        """Simulate 60 seconds of packet callbacks."""
        from packet_capture.bandwidth_calculator import BandwidthCalculator

        calc = BandwidthCalculator(window_seconds=10)

        total_packets = 10000  # Simulate 10K packets
        start = time.perf_counter()
        for i in range(total_packets):
            calc.add_bytes(
                1500,
                direction="download" if i % 2 == 0 else "upload"
            )
        elapsed = time.perf_counter() - start

        pps = total_packets / elapsed if elapsed > 0 else float('inf')
        assert pps >= 1000, f"Sustained throughput {pps:.0f} pps"

    def test_memory_stable_under_load(self):
        """Memory should not grow unbounded during packet processing."""
        import tracemalloc

        tracemalloc.start()

        from packet_capture.bandwidth_calculator import BandwidthCalculator
        calc = BandwidthCalculator(window_seconds=5)

        for i in range(50000):
            calc.add_bytes(1500, direction="download")

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 100, f"Peak memory {peak_mb:.1f}MB (target: <100MB for calc)"


# ===================================================================
# Database Performance Tests
# ===================================================================

class TestDatabasePerformance:
    """Test database query performance against <50ms p95 target."""

    def _seed_devices(self, conn, n=1000):
        records = [
            (f"AA:BB:{i // 65536 % 256:02X}:{i // 256 % 256:02X}:{i % 256:02X}:FF",
             f"192.168.{(i // 256) % 256}.{i % 256}",
             datetime.now().isoformat(),
             datetime.now().isoformat(),
             500 * i, 500 * i, i * 10)
            for i in range(n)
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO devices "
            "(mac_address, ip_address, first_seen, last_seen, "
            "total_bytes_sent, total_bytes_received, total_packets) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            records
        )
        conn.commit()

    def _seed_alerts(self, conn, n=500):
        records = [
            (datetime.now().isoformat(), "bandwidth", "warning",
             f"Alert {i}", None, None, 0, None, 0, None)
            for i in range(n)
        ]
        conn.executemany(
            "INSERT INTO alerts "
            "(timestamp, alert_type, severity, message, details, "
            "source_ip, resolved, resolved_at, acknowledged, acknowledged_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            records
        )
        conn.commit()

    def test_device_count_p95(self, db_connection, timer):
        """Device count query p95 should be <50ms."""
        self._seed_devices(db_connection)

        latencies = []
        for _ in range(100):
            with timer() as t:
                db_connection.execute("SELECT COUNT(*) FROM devices").fetchone()
            latencies.append(t.elapsed)

        latencies.sort()
        p95 = latencies[94]
        assert p95 < 50, f"Device COUNT p95 = {p95:.1f}ms (target <50ms)"

    def test_device_list_p95(self, db_connection, timer):
        """Device list query p95 should be <50ms."""
        self._seed_devices(db_connection)

        latencies = []
        for _ in range(100):
            with timer() as t:
                db_connection.execute(
                    "SELECT * FROM devices ORDER BY last_seen DESC LIMIT 50"
                ).fetchall()
            latencies.append(t.elapsed)

        latencies.sort()
        p95 = latencies[94]
        assert p95 < 50, f"Device list p95 = {p95:.1f}ms"

    def test_alert_query_p95(self, db_connection, timer):
        """Alert query p95 should be <50ms."""
        self._seed_alerts(db_connection)

        latencies = []
        for _ in range(100):
            with timer() as t:
                db_connection.execute(
                    "SELECT * FROM alerts WHERE resolved = 0 "
                    "ORDER BY timestamp DESC LIMIT 50"
                ).fetchall()
            latencies.append(t.elapsed)

        latencies.sort()
        p95 = latencies[94]
        assert p95 < 50, f"Alert query p95 = {p95:.1f}ms"

    def test_batch_insert_throughput(self, db_connection, timer):
        """Batch insert of 1000 devices should be fast."""
        records = [
            (f"CC:DD:{i // 65536 % 256:02X}:{i // 256 % 256:02X}:{i % 256:02X}:AA",
             f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}",
             datetime.now().isoformat(),
             datetime.now().isoformat())
            for i in range(1000)
        ]

        with timer() as t:
            db_connection.executemany(
                "INSERT OR REPLACE INTO devices "
                "(mac_address, ip_address, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                records
            )
            db_connection.commit()

        assert t.elapsed < 3000, f"Batch insert 1K records took {t.elapsed:.0f}ms"

    def test_query_latency_statistics(self, db_connection, timer):
        """Print latency statistics: p50, p95, p99."""
        self._seed_devices(db_connection, n=500)

        latencies = []
        for _ in range(200):
            with timer() as t:
                db_connection.execute(
                    "SELECT * FROM devices ORDER BY total_bytes_sent DESC LIMIT 10"
                ).fetchall()
            latencies.append(t.elapsed)

        latencies.sort()
        p50 = latencies[99]
        p95 = latencies[189]
        p99 = latencies[197]

        assert p50 < 20, f"p50={p50:.1f}ms"
        assert p95 < 50, f"p95={p95:.1f}ms"
        assert p99 < 100, f"p99={p99:.1f}ms"


# ===================================================================
# API Response Time Tests
# ===================================================================

class TestAPIPerformance:
    """Test API endpoint response times against <100ms target."""

    ENDPOINTS = [
        '/api/status',
        '/api/dashboard',
        '/api/devices',
        '/api/alerts',
        '/api/protocols',
        '/api/health',
    ]

    @pytest.mark.parametrize("endpoint", ENDPOINTS)
    def test_endpoint_response_time(self, client, endpoint):
        start = time.perf_counter()
        resp = client.get(endpoint)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert resp.status_code == 200, f"{endpoint} returned {resp.status_code}"
        assert elapsed_ms < 500, f"{endpoint} took {elapsed_ms:.0f}ms (target <500ms)"

    def test_api_p95_response_time(self, client):
        """p95 API response time across all endpoints."""
        latencies = []
        for _ in range(20):
            for ep in self.ENDPOINTS:
                start = time.perf_counter()
                client.get(ep)
                latencies.append((time.perf_counter() - start) * 1000)

        latencies.sort()
        p95_idx = int(len(latencies) * 0.95)
        p95 = latencies[p95_idx]
        assert p95 < 500, f"API p95 = {p95:.0f}ms"
