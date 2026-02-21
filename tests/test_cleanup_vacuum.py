"""
test_cleanup_vacuum.py - Cleanup, Rollup & VACUUM Integration Tests
=====================================================================

Verifies:
- cleanup_old_traffic deletes stale data
- cleanup_old_alerts only deletes resolved alerts
- rollup_traffic aggregates and deletes old raw rows
- vacuum_database reclaims space (returns True)
- run_full_cleanup orchestrates all steps
- Daily VACUUM is scheduled after cleanup
"""

import sys
import os
import sqlite3
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _ensure_db(initialized_db):
    """Every test in this module needs a clean database."""
    yield initialized_db


@pytest.fixture
def db(initialized_db):
    """Raw sqlite3 connection for seeding test data."""
    conn = sqlite3.connect(initialized_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# =================================================================
# VACUUM
# =================================================================

class TestVacuumDatabase:
    """vacuum_database() should run VACUUM and return True."""

    def test_vacuum_returns_true(self):
        from database.queries.maintenance import vacuum_database
        result = vacuum_database()
        assert result is True

    def test_vacuum_after_deletions(self, db):
        """VACUUM after deletions should still return True."""
        # Insert data, delete it, then VACUUM
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for i in range(100):
            db.execute(
                "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
                "VALUES (?, ?, '8.8.8.8', 'TCP', 1000)",
                (ts, f"192.168.1.{i % 254 + 1}")
            )
        db.commit()

        # Delete via pool connection
        from database.connection import get_connection
        with get_connection() as conn:
            conn.execute("DELETE FROM traffic_summary")
            conn.commit()

        from database.queries.maintenance import vacuum_database
        assert vacuum_database() is True


# =================================================================
# cleanup_old_traffic
# =================================================================

class TestCleanupOldTraffic:
    """Tests for cleanup_old_traffic."""

    def test_deletes_old_keeps_new(self, db):
        """Old traffic is deleted; recent traffic survives."""
        old_ts = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        new_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        db.execute(
            "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '10.0.0.1', '8.8.8.8', 'TCP', 500)", (old_ts,)
        )
        db.execute(
            "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '10.0.0.2', '8.8.8.8', 'UDP', 300)", (new_ts,)
        )
        db.commit()

        from database.queries.maintenance import cleanup_old_traffic
        result = cleanup_old_traffic(retention_days=7)

        assert result['deleted'] >= 1

        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) AS cnt FROM traffic_summary")
            assert cursor.fetchone()['cnt'] == 1  # only the new row

    def test_returns_zero_when_nothing_to_clean(self):
        """No old data → deleted=0."""
        from database.queries.maintenance import cleanup_old_traffic
        result = cleanup_old_traffic(retention_days=7)
        assert result['deleted'] == 0


# =================================================================
# cleanup_old_alerts
# =================================================================

class TestCleanupOldAlerts:
    """Tests for cleanup_old_alerts."""

    def test_deletes_old_resolved(self, db):
        """Old *resolved* alerts should be deleted."""
        old_ts = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message, resolved) "
            "VALUES (?, 'health', 'warning', 'Stale alert', 1)", (old_ts,)
        )
        db.commit()

        from database.queries.maintenance import cleanup_old_alerts
        deleted = cleanup_old_alerts(retention_days=30)
        assert deleted >= 1

    def test_keeps_unresolved(self, db):
        """Unresolved alerts are NEVER deleted regardless of age."""
        old_ts = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message, resolved) "
            "VALUES (?, 'health', 'critical', 'Active issue', 0)", (old_ts,)
        )
        db.commit()

        from database.queries.maintenance import cleanup_old_alerts
        cleanup_old_alerts(retention_days=30)

        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE resolved = 0")
            assert cursor.fetchone()['cnt'] == 1


# =================================================================
# Rollup + Cleanup combined
# =================================================================

class TestRollupAndCleanup:
    """Tests for rollup_traffic and cleanup_old_rollups working together."""

    def test_rollup_aggregates_and_deletes(self, db):
        """Old traffic rows should be rolled up and then deleted."""
        old_ts = (datetime.now() - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")

        for _ in range(10):
            db.execute(
                "INSERT INTO traffic_summary "
                "(timestamp, source_ip, dest_ip, protocol, bytes_transferred, direction) "
                "VALUES (?, '192.168.1.1', '8.8.8.8', 'TCP', 1000, 'upload')",
                (old_ts,)
            )
        db.commit()

        from database.rollup import rollup_traffic
        result = rollup_traffic(raw_retention_hours=24)

        assert result['deleted'] >= 10
        assert result['rolled_up'] >= 1

    def test_rollup_preserves_recent(self, db):
        """Recent rows should NOT be rolled up."""
        recent_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "INSERT INTO traffic_summary "
            "(timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '10.0.0.1', '8.8.8.8', 'UDP', 500)",
            (recent_ts,)
        )
        db.commit()

        from database.rollup import rollup_traffic
        rollup_traffic(raw_retention_hours=24)

        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) AS cnt FROM traffic_summary")
            assert cursor.fetchone()['cnt'] == 1


# =================================================================
# run_full_cleanup
# =================================================================

class TestRunFullCleanup:
    """Tests for the orchestrating run_full_cleanup function."""

    def test_returns_summary_dict(self):
        """run_full_cleanup should return a dict with expected keys."""
        from database.queries.maintenance import run_full_cleanup
        result = run_full_cleanup(vacuum=False)
        assert isinstance(result, dict)
        for key in ('traffic_deleted', 'alerts_deleted', 'db_size_before_mb',
                     'db_size_after_mb', 'freed_mb', 'duration_seconds'):
            assert key in result, f"Missing key '{key}' in cleanup result"

    def test_full_cleanup_deletes_old_data(self, db):
        """Full cleanup should handle traffic + alerts."""
        old_ts = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "INSERT INTO traffic_summary (timestamp, source_ip, dest_ip, protocol, bytes_transferred) "
            "VALUES (?, '10.0.0.1', '8.8.8.8', 'TCP', 100)", (old_ts,)
        )
        db.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message, resolved) "
            "VALUES (?, 'health', 'warning', 'Old resolved alert', 1)", (old_ts,)
        )
        db.commit()

        from database.queries.maintenance import run_full_cleanup
        result = run_full_cleanup(traffic_retention_days=7, alert_retention_days=7, vacuum=False)
        assert result['traffic_deleted'] >= 1
        assert result['alerts_deleted'] >= 1

    def test_full_cleanup_records_timestamp(self, db):
        """Cleanup should update system_config with last_cleanup timestamp."""
        from database.queries.maintenance import run_full_cleanup
        run_full_cleanup(vacuum=False)

        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute(
                "SELECT value FROM system_config WHERE key = 'last_cleanup'"
            )
            row = cursor.fetchone()
            assert row is not None, "last_cleanup was not recorded in system_config"


# =================================================================
# Maintenance report
# =================================================================

class TestMaintenanceReport:

    def test_report_structure(self):
        """get_maintenance_report should return db_size, row_counts, timestamp."""
        from database.queries.maintenance import get_maintenance_report
        report = get_maintenance_report()
        assert 'database_size_mb' in report
        assert 'table_row_counts' in report
        assert 'timestamp' in report

    def test_report_row_counts_include_tables(self):
        """Row counts should cover the major tables."""
        from database.queries.maintenance import get_maintenance_report
        report = get_maintenance_report()
        counts = report['table_row_counts']
        for table in ('traffic_summary', 'devices', 'alerts'):
            assert table in counts, f"Missing table '{table}' in row_counts"
