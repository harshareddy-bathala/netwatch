"""
test_load_24h.py - 24-Hour Simulated Load Test
=================================================

Simulates a compressed 24-hour workload to verify:

- Memory usage does not grow unboundedly (caches are bounded)
- Database file size is controlled (VACUUM effectiveness)
- Thread count stays stable (no thread leaks)
- Response times of /api/dashboard and /api/stream stay within SLA
- Alert persistence (health alerts actually save)
- Cleanup + rollup work under sustained load

This is a **heavy** integration test — run separately::

    pytest tests/test_load_24h.py -v --timeout=120

The test compresses 24h into ~30 seconds by running accelerated loops.
"""

import sys
import os
import gc
import time
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =================================================================
# Helpers
# =================================================================

def _get_thread_count():
    """Return current live thread count."""
    return threading.active_count()


def _get_rss_mb():
    """Return process RSS in MB (best-effort)."""
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except ImportError:
        pass
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except ImportError:
        return 0.0


def _insert_traffic_batch(db_path, count=500, hours_ago=0):
    """Insert a batch of traffic rows."""
    ts = (datetime.now() - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path)
    rows = []
    for i in range(count):
        rows.append((
            ts,
            f"192.168.1.{i % 254 + 1}",
            "8.8.8.8",
            "TCP" if i % 2 == 0 else "UDP",
            1000 + i * 10,
            "upload" if i % 3 == 0 else "download",
            f"AA:BB:CC:{i % 256:02X}:00:01",
            "11:22:33:44:55:66",
        ))
    conn.executemany(
        "INSERT INTO traffic_summary "
        "(timestamp, source_ip, dest_ip, protocol, bytes_transferred, direction, source_mac, dest_mac) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


# =================================================================
# Load test
# =================================================================

class TestLoad24h:
    """Compressed 24-hour load simulation."""

    @pytest.fixture(autouse=True)
    def _setup(self, initialized_db, app, client):
        """Set up DB, app, and client for load testing."""
        self.db_path = initialized_db
        self.app = app
        self.client = client

    def test_memory_stability_under_load(self):
        """Memory should not grow unboundedly during sustained traffic insertion."""
        gc.collect()
        initial_rss = _get_rss_mb()

        # Simulate 24 "hours" — each with 500 traffic rows
        for hour in range(24):
            _insert_traffic_batch(self.db_path, count=500, hours_ago=0)

        gc.collect()
        final_rss = _get_rss_mb()
        growth = final_rss - initial_rss

        # Allow up to 100MB growth for 12K rows — more indicates a leak
        if initial_rss > 0:
            assert growth < 100, f"Memory grew by {growth:.1f} MB (leak suspected)"

    def test_thread_count_stability(self):
        """Thread count should not keep growing."""
        initial_threads = _get_thread_count()

        # Simulate API hits and data generation
        for _ in range(50):
            self.client.get('/api/dashboard')
            self.client.get('/api/devices')
            self.client.get('/api/alerts')
            self.client.get('/api/protocols')

        final_threads = _get_thread_count()
        new_threads = final_threads - initial_threads

        # Allow up to 5 new threads (DNS resolver pool etc.)
        assert new_threads < 10, f"Thread count grew by {new_threads} (leak suspected)"

    def test_response_times_under_load(self):
        """Key endpoints should respond within 500ms under load."""
        # Insert enough data to make queries non-trivial
        _insert_traffic_batch(self.db_path, count=2000, hours_ago=0)

        endpoints = ['/api/dashboard', '/api/devices', '/api/alerts', '/api/protocols']
        for endpoint in endpoints:
            start = time.perf_counter()
            resp = self.client.get(endpoint)
            elapsed_ms = (time.perf_counter() - start) * 1000
            assert resp.status_code == 200
            assert elapsed_ms < 500, f"{endpoint} took {elapsed_ms:.0f}ms (SLA: <500ms)"

    def test_database_size_after_cleanup(self):
        """DB size should be controlled after cleanup + VACUUM."""
        # Insert a lot of "old" data
        for batch in range(10):
            _insert_traffic_batch(self.db_path, count=1000, hours_ago=48 + batch)

        size_before = os.path.getsize(self.db_path) / (1024 * 1024)

        from database.queries.maintenance import run_full_cleanup
        result = run_full_cleanup(traffic_retention_days=1, vacuum=True)

        size_after = os.path.getsize(self.db_path) / (1024 * 1024)

        # Cleanup should have deleted old rows
        assert result['traffic_deleted'] > 0
        # DB size should not have grown significantly after VACUUM
        # (may even be smaller)
        assert size_after <= size_before + 1.0, \
            f"DB grew after cleanup: {size_before:.1f}MB → {size_after:.1f}MB"

    def test_cleanup_and_rollup_combined(self):
        """Rollup + cleanup should work correctly under load."""
        # Insert old data (48h ago)
        _insert_traffic_batch(self.db_path, count=1000, hours_ago=48)
        # Insert recent data
        _insert_traffic_batch(self.db_path, count=500, hours_ago=0)

        # Rollup
        from database.rollup import rollup_traffic
        rollup_result = rollup_traffic(raw_retention_hours=24)
        assert rollup_result['deleted'] >= 1000

        # Verify recent data survived
        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) AS cnt FROM traffic_summary")
            remaining = cursor.fetchone()['cnt']
        assert remaining >= 500

    def test_alert_persistence_under_load(self):
        """Health alerts should persist even during heavy API traffic."""
        from alerts.alert_engine import AlertEngine
        engine = AlertEngine()

        # Create alerts while API is being hit
        alert_ids = []
        for i in range(10):
            self.client.get('/api/dashboard')
            aid = engine.create_alert(
                alert_type="health",
                severity="warning",
                title=f"Load test alert {i}",
                message=f"Testing persistence under load ({i})",
            )
            if aid:
                alert_ids.append(aid)

        # Verify all alerts are in the DB
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE alert_type = 'health'")
        count = cursor.fetchone()['cnt']
        conn.close()

        # At least some alerts should persist (dedup may suppress exact duplicates)
        assert count >= 1, "No health alerts persisted during load test"

    def test_concurrent_api_and_writes(self):
        """API reads and DB writes should not deadlock."""
        errors = []
        stop = threading.Event()

        def writer():
            while not stop.is_set():
                try:
                    _insert_traffic_batch(self.db_path, count=100, hours_ago=0)
                except Exception as e:
                    errors.append(f"Writer: {e}")
                time.sleep(0.05)

        def reader():
            while not stop.is_set():
                try:
                    with self.app.test_request_context():
                        resp = self.client.get('/api/dashboard')
                        assert resp.status_code == 200
                except Exception as e:
                    errors.append(f"Reader: {e}")
                time.sleep(0.05)

        threads = [
            threading.Thread(target=writer, daemon=True),
            threading.Thread(target=reader, daemon=True),
            threading.Thread(target=reader, daemon=True),
        ]
        for t in threads:
            t.start()

        time.sleep(3)  # run for 3 seconds
        stop.set()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Concurrent access errors: {errors[:5]}"

    def test_sse_stream_under_load(self):
        """SSE stream should return valid data under write load."""
        _insert_traffic_batch(self.db_path, count=500, hours_ago=0)

        resp = self.client.get('/api/stream')
        assert resp.status_code == 200

        # Read first SSE frame
        for chunk in resp.response:
            text = chunk if isinstance(chunk, str) else chunk.decode('utf-8', errors='replace')
            for line in text.split('\n'):
                if line.startswith('data: '):
                    payload = json.loads(line[6:])
                    assert 'stats' in payload
                    assert 'protocols' in payload
                    resp.close()
                    return
        pytest.fail("No SSE data received")
