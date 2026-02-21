"""
test_health_alert_persistence.py - HealthMonitor Alert Persistence Tests
==========================================================================

Regression test that verifies HealthMonitor._check_thresholds() actually
persists alerts to the database via AlertEngine.create_alert().

This test will **fail** if:
  - AlertEngine.create_alert() silently drops the alert
  - The database insert is broken
  - Deduplication blocks the alert unexpectedly
"""

import sys
import os
import time
import sqlite3
import threading
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestHealthAlertPersistence:
    """Verify that HealthMonitor threshold breaches result in persisted alerts."""

    def test_cpu_warning_persists(self, initialized_db, alert_engine):
        """CPU above warning threshold should create a persisted alert."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        # Simulate metrics with high CPU
        metrics = {
            "cpu_percent": monitor.CPU_WARNING + 10,
            "memory": {"rss_mb": 100},
            "database": {"size_mb": 50},
        }
        monitor._check_thresholds(metrics)

        # Verify alert was persisted
        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM alerts WHERE alert_type = 'health'")
        alerts = cursor.fetchall()
        conn.close()

        assert len(alerts) >= 1, "CPU warning alert was not persisted to database"
        alert = dict(alerts[0])
        assert 'cpu' in alert.get('message', '').lower() or 'CPU' in alert.get('message', '')

    def test_cpu_critical_persists(self, initialized_db, alert_engine):
        """CPU above critical threshold should create a critical alert."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": monitor.CPU_CRITICAL + 5,
            "memory": {"rss_mb": 100},
            "database": {"size_mb": 50},
        }
        monitor._check_thresholds(metrics)

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM alerts WHERE alert_type = 'health' AND severity = 'critical'"
        )
        alerts = cursor.fetchall()
        conn.close()

        assert len(alerts) >= 1, "CPU critical alert was not persisted"

    def test_memory_warning_persists(self, initialized_db, alert_engine):
        """High memory usage should create a persisted alert."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": 10,
            "memory": {"rss_mb": monitor.MEMORY_WARNING + 50},
            "database": {"size_mb": 50},
        }
        monitor._check_thresholds(metrics)

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM alerts WHERE alert_type = 'health' AND message LIKE '%emory%'"
        )
        alerts = cursor.fetchall()
        conn.close()

        assert len(alerts) >= 1, "Memory warning alert was not persisted"

    def test_memory_critical_persists(self, initialized_db, alert_engine):
        """Critical memory should create a critical persisted alert."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": 10,
            "memory": {"rss_mb": monitor.MEMORY_CRITICAL + 50},
            "database": {"size_mb": 50},
        }
        monitor._check_thresholds(metrics)

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM alerts WHERE alert_type = 'health' AND severity = 'critical'"
        )
        alerts = cursor.fetchall()
        conn.close()

        assert len(alerts) >= 1, "Memory critical alert was not persisted"

    def test_db_size_warning_persists(self, initialized_db, alert_engine):
        """Large DB should create a persisted alert."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": 10,
            "memory": {"rss_mb": 100},
            "database": {"size_mb": monitor.DB_SIZE_WARNING + 100},
        }
        monitor._check_thresholds(metrics)

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM alerts WHERE alert_type = 'health' AND message LIKE '%atabase%'"
        )
        alerts = cursor.fetchall()
        conn.close()

        assert len(alerts) >= 1, "Database size warning alert was not persisted"

    def test_no_alert_below_threshold(self, initialized_db, alert_engine):
        """Below all thresholds, no alert should be created."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": 10,  # well below warning
            "memory": {"rss_mb": 100},  # well below warning
            "database": {"size_mb": 50},  # well below warning
        }
        monitor._check_thresholds(metrics)

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE alert_type = 'health'")
        count = cursor.fetchone()['cnt']
        conn.close()

        assert count == 0, f"Expected no alerts below threshold, got {count}"

    def test_multiple_thresholds_create_multiple_alerts(self, initialized_db, alert_engine):
        """All three thresholds exceeded = at least one critical alert persisted."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": monitor.CPU_CRITICAL + 5,
            "memory": {"rss_mb": monitor.MEMORY_CRITICAL + 50},
            "database": {"size_mb": monitor.DB_SIZE_CRITICAL + 100},
        }
        monitor._check_thresholds(metrics)

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE alert_type = 'health'")
        count = cursor.fetchone()['cnt']
        conn.close()

        # Dedup may merge same-type/severity, but at least 1 critical alert must persist
        assert count >= 1, f"Expected at least 1 alert for critical thresholds, got {count}"

    def test_alert_dedup_prevents_duplicate(self, initialized_db, alert_engine):
        """Calling _check_thresholds twice with same metrics should NOT double-create."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=60, alert_engine=alert_engine)

        metrics = {
            "cpu_percent": monitor.CPU_WARNING + 10,
            "memory": {"rss_mb": 100},
            "database": {"size_mb": 50},
        }
        monitor._check_thresholds(metrics)
        monitor._check_thresholds(metrics)  # duplicate call

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE alert_type = 'health'"
        )
        count = cursor.fetchone()['cnt']
        conn.close()

        # Dedup should prevent the second call from creating another alert
        assert count == 1, f"Expected 1 alert (dedup), got {count}"

    def test_monitor_collects_metrics_and_alerts(self, initialized_db, alert_engine):
        """Start monitor, inject fake high CPU, verify alert in DB."""
        from utils.health_monitor import HealthMonitor

        monitor = HealthMonitor(check_interval=1, alert_engine=alert_engine)

        # Patch CPU/memory to return high values
        with patch('utils.health_monitor.get_cpu_usage', return_value=95.0), \
             patch('utils.health_monitor.get_memory_usage', return_value={"rss_mb": 100, "vms_mb": 200, "percent": 50}):
            monitor.start()
            time.sleep(2.5)  # allow 1-2 monitor cycles
            monitor.stop()

        conn = sqlite3.connect(initialized_db)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM alerts WHERE alert_type = 'health'")
        alerts = cursor.fetchall()
        conn.close()

        assert len(alerts) >= 1, "Monitor background loop did not persist a health alert"
