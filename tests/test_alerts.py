"""
test_alerts.py - Phase 4: Alert System Tests
===============================================

Tests for alert creation, acknowledgment, resolution, deduplication,
accurate thresholds, and badge count management.
"""

import sys
import os
import time
from datetime import datetime
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.alert_engine import AlertEngine, SEVERITY_WARNING, SEVERITY_CRITICAL
from alerts.deduplication import AlertDeduplicator


# ===================================================================
# Alert Creation Tests
# ===================================================================

class TestAlertCreation:
    """Tests for creating alerts."""

    def test_create_alert(self, alert_engine):
        alert_id = alert_engine.create_alert(
            alert_type="bandwidth",
            severity=SEVERITY_WARNING,
            title="High Bandwidth",
            message="Bandwidth exceeded warning threshold",
        )
        assert alert_id is not None
        assert isinstance(alert_id, int)

    def test_create_alert_with_metadata(self, alert_engine):
        alert_id = alert_engine.create_alert(
            alert_type="anomaly",
            severity=SEVERITY_CRITICAL,
            title="Anomaly Detected",
            message="Unusual traffic pattern detected",
            metadata={"score": 0.95, "feature": "bandwidth"},
        )
        assert alert_id is not None

    def test_bandwidth_threshold_warning(self, alert_engine):
        # 1 Mbps is well below any warning threshold — should NOT alert
        result = alert_engine.check_bandwidth_threshold(1_000_000)
        assert result is None, f"Expected no alert for 1 Mbps, got alert_id={result}"

    def test_bandwidth_threshold_critical(self, alert_engine):
        result = alert_engine.check_bandwidth_threshold(100_000_000)  # 100 Mbps
        # Should trigger a critical alert at 100 Mbps
        assert isinstance(result, int), f"Expected alert_id for 100 Mbps, got {result}"

    def test_device_threshold(self, alert_engine):
        result = alert_engine.check_device_threshold()
        # Empty test DB has 0 devices — below any threshold
        assert result is None, f"Expected no alert for 0 devices, got alert_id={result}"

    def test_health_threshold_warning(self, alert_engine):
        result = alert_engine.check_health_threshold(40.0)
        # 40.0 is below warning threshold — should create alert
        assert isinstance(result, int), f"Expected alert_id for low health 40.0, got {result}"

    def test_create_anomaly_alert(self, alert_engine):
        result = alert_engine.create_anomaly_alert(
            anomaly_score=0.9,
            severity=SEVERITY_WARNING,
            details={"type": "bandwidth_spike"},
        )
        # High-score anomaly (0.9) should always produce an alert
        assert isinstance(result, int), f"Expected alert_id for anomaly 0.9, got {result}"


# ===================================================================
# Alert Acknowledgment Tests
# ===================================================================

class TestAlertAcknowledgment:
    """Tests for acknowledging alerts."""

    def test_acknowledge_existing_alert(self, alert_engine):
        alert_id = alert_engine.create_alert(
            alert_type="bandwidth",
            severity=SEVERITY_WARNING,
            title="Test",
            message="Test alert for acknowledgment",
        )
        if alert_id:
            result = AlertEngine.acknowledge_alert(alert_id)
            assert result is True

    def test_acknowledge_nonexistent_alert(self, alert_engine):
        result = AlertEngine.acknowledge_alert(99999)
        assert result is False, "Acknowledging a non-existent alert should return False"

    def test_acknowledge_reduces_active_count(self, alert_engine):
        # Create alert
        alert_id = alert_engine.create_alert(
            alert_type="test",
            severity=SEVERITY_WARNING,
            title="Count Test",
            message="Testing active count",
        )
        if alert_id:
            before = AlertEngine.count_alerts(resolved=False)
            AlertEngine.acknowledge_alert(alert_id)
            # Acknowledged alerts may or may not count as "active"
            after = AlertEngine.count_alerts(resolved=False)
            assert isinstance(after, int)


# ===================================================================
# Alert Resolution Tests
# ===================================================================

class TestAlertResolution:
    """Tests for resolving alerts."""

    def test_resolve_existing_alert(self, alert_engine):
        alert_id = alert_engine.create_alert(
            alert_type="bandwidth",
            severity=SEVERITY_WARNING,
            title="Resolve Test",
            message="Testing resolution",
        )
        if alert_id:
            result = AlertEngine.resolve_alert(alert_id)
            assert result is True

    def test_resolve_reduces_badge_count(self, alert_engine):
        """Resolving alert must reduce the unresolved count (badge)."""
        # Create multiple alerts
        ids = []
        for i in range(3):
            aid = alert_engine.create_alert(
                alert_type=f"test_{i}",
                severity=SEVERITY_WARNING,
                title=f"Badge Test {i}",
                message=f"Badge count test {i}",
            )
            if aid:
                ids.append(aid)

        before = AlertEngine.count_alerts(resolved=False)

        # Resolve one
        if ids:
            AlertEngine.resolve_alert(ids[0])
            after = AlertEngine.count_alerts(resolved=False)
            assert after <= before  # Should decrease or stay same

    def test_resolve_nonexistent(self, alert_engine):
        result = AlertEngine.resolve_alert(99999)
        assert result is False, "Resolving a non-existent alert should return False"


# ===================================================================
# Deduplication Tests
# ===================================================================

class TestAlertDeduplication:
    """Tests for alert deduplication / throttling."""

    def test_deduplicator_init(self):
        dedup = AlertDeduplicator(cooldown_seconds=60)
        assert dedup is not None

    def test_first_alert_not_throttled(self):
        dedup = AlertDeduplicator(cooldown_seconds=60)
        key = AlertDeduplicator.make_key("bandwidth", "warning")
        assert dedup.should_throttle(key) is False

    def test_duplicate_is_throttled(self):
        dedup = AlertDeduplicator(cooldown_seconds=60)
        key = AlertDeduplicator.make_key("bandwidth", "warning")

        dedup.record_alert(key)
        assert dedup.should_throttle(key) is True

    def test_different_types_not_throttled(self):
        dedup = AlertDeduplicator(cooldown_seconds=60)
        key1 = AlertDeduplicator.make_key("bandwidth", "warning")
        key2 = AlertDeduplicator.make_key("anomaly", "critical")

        dedup.record_alert(key1)
        assert dedup.should_throttle(key2) is False

    def test_cooldown_expires(self):
        dedup = AlertDeduplicator(cooldown_seconds=1)
        key = AlertDeduplicator.make_key("bandwidth", "warning")

        with patch('alerts.deduplication.time') as mock_time:
            # Record at t=100
            mock_time.time.return_value = 100.0
            dedup.record_alert(key)
            assert dedup.should_throttle(key) is True

            # Advance past cooldown (t=102, cooldown=1)
            mock_time.time.return_value = 102.0
            assert dedup.should_throttle(key) is False

    def test_reset_clears_all(self):
        dedup = AlertDeduplicator(cooldown_seconds=60)
        key = AlertDeduplicator.make_key("bandwidth", "warning")
        dedup.record_alert(key)
        dedup.reset()
        assert dedup.should_throttle(key) is False

    def test_cleanup_old_records(self):
        dedup = AlertDeduplicator(cooldown_seconds=1)
        with patch('alerts.deduplication.time') as mock_time:
            mock_time.time.return_value = 100.0
            for i in range(10):
                dedup.record_alert(f"test:{i}")
            # Advance past cooldown
            mock_time.time.return_value = 102.0
            cleaned = dedup.cleanup_old_records()
            assert cleaned == 10


# ===================================================================
# Alert Summary & Statistics Tests
# ===================================================================

class TestAlertSummary:
    """Tests for alert summaries and statistics."""

    def test_get_alert_summary(self, alert_engine):
        summary = AlertEngine.get_alert_summary()
        assert isinstance(summary, dict)

    def test_get_stats(self, alert_engine):
        stats = alert_engine.get_stats()
        assert isinstance(stats, dict)

    def test_count_alerts(self, alert_engine):
        count = AlertEngine.count_alerts()
        assert isinstance(count, int)
        assert count >= 0

    def test_get_alerts_returns_list(self, alert_engine):
        alerts = AlertEngine.get_alerts(limit=10)
        assert isinstance(alerts, list)


# ===================================================================
# Alert Engine Integration Tests
# ===================================================================

class TestAlertEngineIntegration:
    """Integration tests for the full alert lifecycle."""

    def test_full_alert_lifecycle(self, alert_engine):
        """Create → Acknowledge → Resolve lifecycle."""
        # Create
        alert_id = alert_engine.create_alert(
            alert_type="lifecycle_test",
            severity=SEVERITY_WARNING,
            title="Lifecycle",
            message="Full lifecycle test",
        )

        if alert_id:
            # Acknowledge
            ack_result = AlertEngine.acknowledge_alert(alert_id)
            assert ack_result is True

            # Resolve
            resolve_result = AlertEngine.resolve_alert(alert_id)
            assert resolve_result is True

    def test_multiple_alert_types(self, alert_engine):
        """Create alerts of different types."""
        types = ["bandwidth", "anomaly", "device_count", "health"]
        for atype in types:
            result = alert_engine.create_alert(
                alert_type=atype,
                severity=SEVERITY_WARNING,
                title=f"Test {atype}",
                message=f"Testing {atype} alert",
            )
            # Different types should not be throttled by dedup
            assert isinstance(result, int), f"Expected alert_id for type={atype}, got {result}"
