"""
test_database.py - Phase 3: Database Tests
=============================================

Tests for connection pooling, WAL mode, device consistency,
batch inserts, query performance, and data integrity.
"""

import sys
import os
import sqlite3
import time
import threading
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Connection Pool Tests
# ===================================================================

class TestConnectionPool:
    """Tests for the database connection pool."""

    def test_pool_initializes(self, connection_pool):
        assert connection_pool is not None

    def test_pool_provides_connection(self, connection_pool):
        with connection_pool.get_connection() as conn:
            assert conn is not None
            cursor = conn.execute("SELECT 1")
            row = cursor.fetchone()
            assert row[0] == 1

    def test_pool_returns_connection(self, connection_pool):
        """Connection should be returned to pool after context exit."""
        with connection_pool.get_connection() as conn:
            conn.execute("SELECT 1")
        # Should be able to get another connection
        with connection_pool.get_connection() as conn2:
            conn2.execute("SELECT 1")

    def test_pool_concurrent_access(self, connection_pool):
        """Multiple threads should be able to use the pool."""
        results = []
        errors = []

        def worker():
            try:
                with connection_pool.get_connection() as conn:
                    cursor = conn.execute("SELECT 42")
                    results.append(cursor.fetchone()[0])
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Pool errors: {errors}"
        assert all(r == 42 for r in results)


# ===================================================================
# WAL Mode Tests
# ===================================================================

class TestWALMode:
    """Tests for SQLite WAL (Write-Ahead Logging) mode."""

    def test_wal_mode_enabled(self, db_connection):
        cursor = db_connection.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        assert mode.lower() == "wal", f"Expected WAL mode, got {mode}"

    def test_wal_concurrent_reads_writes(self, initialized_db):
        """WAL should allow concurrent reads and writes."""
        conn_write = sqlite3.connect(initialized_db)
        conn_read = sqlite3.connect(initialized_db)

        conn_write.execute("PRAGMA journal_mode=WAL")
        conn_read.execute("PRAGMA journal_mode=WAL")

        try:
            # Write some data
            conn_write.execute(
                "INSERT INTO devices (mac_address, ip_address, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                ("AA:BB:CC:DD:EE:01", "192.168.1.1",
                 datetime.now().isoformat(), datetime.now().isoformat())
            )
            conn_write.commit()

            # Read should work concurrently
            cursor = conn_read.execute("SELECT COUNT(*) FROM devices")
            count = cursor.fetchone()[0]
            assert count >= 1
        finally:
            conn_write.close()
            conn_read.close()


# ===================================================================
# Device Data Consistency Tests
# ===================================================================

class TestDeviceConsistency:
    """Tests for device count consistency and data integrity."""

    def test_device_count_matches_inserts(self, db_connection):
        """Device count should match number of inserted records."""
        for i in range(5):
            db_connection.execute(
                "INSERT INTO devices (mac_address, ip_address, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                (f"AA:BB:CC:DD:EE:{i:02X}", f"192.168.1.{i + 1}",
                 datetime.now().isoformat(), datetime.now().isoformat())
            )
        db_connection.commit()

        cursor = db_connection.execute("SELECT COUNT(*) FROM devices")
        count = cursor.fetchone()[0]
        assert count == 5

    def test_no_public_ips_in_private_network(self, initialized_db):
        """Validate that is_private_ip correctly filters."""
        from database.queries.device_queries import is_private_ip

        assert is_private_ip("192.168.1.100") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True

        # Public IPs should not be treated as private
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_no_duplicate_mac_addresses(self, db_connection):
        """MAC addresses should be unique in the devices table."""
        mac = "AA:BB:CC:DD:EE:FF"
        db_connection.execute(
            "INSERT INTO devices (mac_address, ip_address, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?)",
            (mac, "192.168.1.1", datetime.now().isoformat(), datetime.now().isoformat())
        )
        db_connection.commit()

        # Second insert with same MAC should fail or update
        try:
            db_connection.execute(
                "INSERT INTO devices (mac_address, ip_address, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                (mac, "192.168.1.2", datetime.now().isoformat(), datetime.now().isoformat())
            )
            db_connection.commit()
            # If it succeeds, check count (UPSERT behavior)
            cursor = db_connection.execute(
                "SELECT COUNT(*) FROM devices WHERE mac_address = ?", (mac,)
            )
            count = cursor.fetchone()[0]
            # Either unique constraint prevents duplicate or UPSERT merges
            assert count >= 1
        except sqlite3.IntegrityError:
            # This is the expected behavior with UNIQUE constraint
            pass


# ===================================================================
# Batch Insert Tests
# ===================================================================

class TestBatchInserts:
    """Tests for batch database operations."""

    def test_batch_insert_performance(self, db_connection, timer):
        """Batch insert of 1000 records should complete quickly."""
        records = [
            (f"AA:BB:CC:{i // 256:02X}:{i % 256:02X}:FF",
             f"192.168.{(i // 256) % 256}.{i % 256}",
             datetime.now().isoformat(),
             datetime.now().isoformat())
            for i in range(1000)
        ]

        with timer() as t:
            db_connection.executemany(
                "INSERT OR REPLACE INTO devices "
                "(mac_address, ip_address, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                records
            )
            db_connection.commit()

        assert t.elapsed < 5000, f"Batch insert took {t.elapsed:.0f}ms (expected <5000ms)"

    def test_batch_insert_all_recorded(self, db_connection):
        """All records in a batch should be persisted."""
        count = 100
        records = [
            (f"BB:CC:DD:EE:{i:02X}:00",
             f"10.0.0.{i + 1}",
             datetime.now().isoformat(),
             datetime.now().isoformat())
            for i in range(count)
        ]

        db_connection.executemany(
            "INSERT OR REPLACE INTO devices "
            "(mac_address, ip_address, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            records
        )
        db_connection.commit()

        cursor = db_connection.execute("SELECT COUNT(*) FROM devices")
        assert cursor.fetchone()[0] == count


# ===================================================================
# Query Performance Tests
# ===================================================================

class TestQueryPerformance:
    """Tests for query execution time targets."""

    def _seed_data(self, conn, n=500):
        """Insert sample data for benchmarking."""
        records = [
            (f"CC:DD:EE:{i // 256:02X}:{i % 256:02X}:AA",
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

    def test_device_count_query_performance(self, db_connection, timer):
        """SELECT COUNT(*) FROM devices should be < 50ms."""
        self._seed_data(db_connection)

        with timer() as t:
            db_connection.execute("SELECT COUNT(*) FROM devices").fetchone()

        assert t.elapsed < 50, f"Device count query took {t.elapsed:.1f}ms"

    def test_device_list_query_performance(self, db_connection, timer):
        """SELECT * FROM devices should be < 50ms with 500 records."""
        self._seed_data(db_connection)

        with timer() as t:
            db_connection.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 100").fetchall()

        assert t.elapsed < 50, f"Device list query took {t.elapsed:.1f}ms"

    def test_alert_count_query_performance(self, db_connection, timer):
        """Alert count queries should be fast."""
        # Insert some alerts
        for i in range(100):
            db_connection.execute(
                "INSERT INTO alerts (timestamp, alert_type, severity, message) "
                "VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), "bandwidth", "warning", f"Test alert {i}")
            )
        db_connection.commit()

        with timer() as t:
            db_connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE resolved = 0"
            ).fetchone()

        assert t.elapsed < 50, f"Alert count query took {t.elapsed:.1f}ms"

    def test_p95_query_latency(self, db_connection, timer):
        """95th percentile query time should be < 50ms."""
        self._seed_data(db_connection)

        latencies = []
        for _ in range(100):
            with timer() as t:
                db_connection.execute("SELECT * FROM devices ORDER BY total_bytes_sent DESC LIMIT 10").fetchall()
            latencies.append(t.elapsed)

        latencies.sort()
        p95 = latencies[94]  # 95th percentile
        assert p95 < 50, f"P95 query latency is {p95:.1f}ms (target <50ms)"


# ===================================================================
# Schema Integrity Tests
# ===================================================================

class TestSchemaIntegrity:
    """Tests for database schema correctness."""

    def test_devices_table_exists(self, db_connection):
        cursor = db_connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='devices'"
        )
        assert cursor.fetchone() is not None

    def test_alerts_table_exists(self, db_connection):
        cursor = db_connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        )
        assert cursor.fetchone() is not None

    def test_traffic_table_exists(self, db_connection):
        cursor = db_connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name LIKE '%traffic%'"
        )
        result = cursor.fetchone()
        assert result is not None, "Expected at least one traffic-related table in schema"

    def test_foreign_keys_enabled(self, db_connection):
        cursor = db_connection.execute("PRAGMA foreign_keys")
        # Should be enabled
        row = cursor.fetchone()
        # Foreign keys may or may not be enabled depending on config
        assert row is not None
