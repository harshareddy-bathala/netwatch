"""
test_cleanup_rollup.py - Tests for Data Cleanup & Traffic Rollup
==================================================================

Tests for:
* ``cleanup_old_data()`` — deletes stale traffic & resolved alerts
* ``rollup_traffic()`` — aggregates raw rows into hourly buckets
* ``cleanup_old_rollups()`` — removes aged rollup data
"""

import sys
import os
import sqlite3
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Fixtures — use the shared initialized_db from conftest.py
# ===================================================================


@pytest.fixture(autouse=True)
def _test_db(initialized_db):
    """Re-use the shared conftest.py initialized_db fixture."""
    yield initialized_db


@pytest.fixture
def db_conn(_test_db):
    """Raw sqlite3 connection for seeding/asserting."""
    conn = sqlite3.connect(_test_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# ===================================================================
# cleanup_old_data
# ===================================================================

class TestCleanupOldData:
    """Tests for db_handler.cleanup_old_data."""

    def test_deletes_old_traffic(self, db_conn):
        """Traffic rows older than retention period should be deleted."""
        old_ts = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        new_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        db_conn.execute(
            "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '192.168.1.1', '8.8.8.8', 'TCP', 100)", (old_ts,)
        )
        db_conn.execute(
            "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '192.168.1.2', '8.8.4.4', 'UDP', 200)", (new_ts,)
        )
        db_conn.commit()

        from database.db_handler import cleanup_old_data
        deleted = cleanup_old_data(days_to_keep=7)

        # Re-query via pool (the cleanup ran via the pool connection)
        from database.connection import get_connection
        with get_connection() as pc:
            cursor = pc.execute("SELECT COUNT(*) FROM traffic_summary")
            remaining = cursor.fetchone()[0]
        # The old row should be deleted, the new one kept
        assert remaining == 1
        assert deleted >= 1

    def test_keeps_recent_traffic(self, db_conn):
        """Traffic within retention window should survive."""
        recent_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for i in range(5):
            db_conn.execute(
                "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
                "VALUES (?, ?, '8.8.8.8', 'TCP', 100)",
                (recent_ts, f"192.168.1.{i + 1}")
            )
        db_conn.commit()

        from database.db_handler import cleanup_old_data
        cleanup_old_data(days_to_keep=7)

        from database.connection import get_connection
        with get_connection() as pc:
            cursor = pc.execute("SELECT COUNT(*) FROM traffic_summary")
            assert cursor.fetchone()[0] == 5

    def test_deletes_old_resolved_alerts(self, db_conn):
        """Resolved alerts older than 30 days should be deleted."""
        old_ts = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
        db_conn.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message, resolved) "
            "VALUES (?, 'bandwidth', 'warning', 'Old alert', 1)", (old_ts,)
        )
        db_conn.commit()

        from database.db_handler import cleanup_old_data
        deleted = cleanup_old_data(days_to_keep=7)
        assert deleted >= 1

    def test_keeps_unresolved_alerts(self, db_conn):
        """Unresolved alerts should NOT be deleted regardless of age."""
        old_ts = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
        db_conn.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message, resolved) "
            "VALUES (?, 'bandwidth', 'warning', 'Active alert', 0)", (old_ts,)
        )
        db_conn.commit()

        from database.db_handler import cleanup_old_data
        cleanup_old_data(days_to_keep=7)

        from database.connection import get_connection
        with get_connection() as pc:
            cursor = pc.execute("SELECT COUNT(*) FROM alerts WHERE resolved = 0")
            assert cursor.fetchone()[0] == 1

    def test_cleanup_returns_integer(self):
        """cleanup_old_data should always return an int."""
        from database.db_handler import cleanup_old_data
        result = cleanup_old_data(days_to_keep=7)
        assert isinstance(result, int)
        assert result >= 0


# ===================================================================
# rollup_traffic
# ===================================================================

class TestRollupTraffic:
    """Tests for database.rollup.rollup_traffic."""

    def test_rollup_aggregates_old_rows(self, db_conn):
        """Old traffic rows should be aggregated into traffic_rollup."""
        old_ts = (datetime.now() - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")

        for i in range(5):
            db_conn.execute(
                "INSERT INTO traffic_summary "
                "(timestamp, source_ip, dest_ip, protocol, bytes_transferred, direction) "
                "VALUES (?, '192.168.1.1', '8.8.8.8', 'TCP', 1000, 'upload')",
                (old_ts,)
            )
        db_conn.commit()

        from database.rollup import rollup_traffic
        result = rollup_traffic(raw_retention_hours=24)

        assert isinstance(result, dict)
        assert "rolled_up" in result
        assert "deleted" in result
        # The 5 old rows should have been rolled up
        assert result["deleted"] >= 5

    def test_rollup_creates_table(self):
        """rollup_traffic should create the traffic_rollup table if missing."""
        from database.rollup import rollup_traffic
        result = rollup_traffic(raw_retention_hours=24)
        assert isinstance(result, dict)

    def test_recent_rows_not_rolled(self, db_conn):
        """Rows within retention window should NOT be rolled up."""
        recent_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db_conn.execute(
            "INSERT INTO traffic_summary "
            "(timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '10.0.0.1', '8.8.8.8', 'UDP', 500)",
            (recent_ts,)
        )
        db_conn.commit()

        from database.rollup import rollup_traffic
        rollup_traffic(raw_retention_hours=24)

        from database.connection import get_connection
        with get_connection() as pc:
            cursor = pc.execute("SELECT COUNT(*) FROM traffic_summary")
            assert cursor.fetchone()[0] == 1  # Still there

    def test_rollup_returns_stats(self):
        """Return dict should have rolled_up and deleted keys."""
        from database.rollup import rollup_traffic
        result = rollup_traffic(raw_retention_hours=24)
        assert "rolled_up" in result
        assert "deleted" in result
        assert isinstance(result["rolled_up"], int)
        assert isinstance(result["deleted"], int)


# ===================================================================
# cleanup_old_rollups
# ===================================================================

class TestCleanupOldRollups:
    """Tests for database.rollup.cleanup_old_rollups."""

    def test_deletes_aged_rollups(self, db_conn):
        """Rollups older than retention should be deleted."""
        from database.rollup import cleanup_old_rollups

        old_bucket = (datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d %H:00:00")
        db_conn.execute(
            "INSERT INTO traffic_rollup "
            "(hour_bucket, source_ip, dest_ip, protocol, direction, total_bytes, packet_count) "
            "VALUES (?, '10.0.0.1', '8.8.8.8', 'TCP', 'upload', 5000, 10)",
            (old_bucket,)
        )
        db_conn.commit()

        deleted = cleanup_old_rollups(days_to_keep=90)
        assert deleted >= 1

    def test_keeps_recent_rollups(self, db_conn):
        """Recent rollups should not be deleted."""
        from database.rollup import cleanup_old_rollups

        recent_bucket = datetime.now().strftime("%Y-%m-%d %H:00:00")
        db_conn.execute(
            "INSERT INTO traffic_rollup "
            "(hour_bucket, source_ip, dest_ip, protocol, direction, total_bytes, packet_count) "
            "VALUES (?, '10.0.0.1', '8.8.8.8', 'TCP', 'upload', 5000, 10)",
            (recent_bucket,)
        )
        db_conn.commit()

        cleanup_old_rollups(days_to_keep=90)

        from database.connection import get_connection
        with get_connection() as pc:
            cursor = pc.execute("SELECT COUNT(*) FROM traffic_rollup")
            assert cursor.fetchone()[0] == 1

    def test_returns_integer(self):
        """cleanup_old_rollups should return an int."""
        from database.rollup import cleanup_old_rollups
        result = cleanup_old_rollups(days_to_keep=90)
        assert isinstance(result, int)
        assert result >= 0
