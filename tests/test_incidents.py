"""
test_incidents.py - Incident Triage Tests (Phase 2)
====================================================

Covers intelligence/incidents.py (fusion rules), the AlertEngine triage
hook, database/queries/incident_queries.py, and the /api/incidents
endpoints.
"""

import sys
import os
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.incidents import IncidentManager, _max_severity
from database.queries import incident_queries
from database.queries.alert_queries import create_alert as db_create_alert

_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _make_alert(alert_type="security", severity="warning", message="test alert"):
    """Insert a raw alert row and return its id."""
    alert_id = db_create_alert(alert_type=alert_type, severity=severity,
                               message=message)
    assert alert_id is not None
    return alert_id


# ===================================================================
# Severity helpers
# ===================================================================

class TestSeverityOrdering:

    def test_critical_beats_info(self):
        assert _max_severity("info", "critical") == "critical"
        assert _max_severity("critical", "info") == "critical"

    def test_equal_severity(self):
        assert _max_severity("warning", "warning") == "warning"

    def test_unknown_severity_ranks_lowest(self):
        assert _max_severity("bogus", "low") == "low"


# ===================================================================
# Fusion rules
# ===================================================================

class TestIncidentFusion:

    def test_first_alert_opens_incident(self, initialized_db):
        manager = IncidentManager()
        alert_id = _make_alert("security", "high", "Port scan detected")
        incident_id = manager.triage(alert_id, "security", "high",
                                     device_mac="AA:BB:CC:00:00:01",
                                     message="Port scan detected")
        assert incident_id is not None

        incident = incident_queries.get_incident(incident_id)
        assert incident["status"] == "open"
        assert incident["severity"] == "high"
        assert incident["device_mac"] == "aa:bb:cc:00:00:01"  # normalised
        assert incident["alert_count"] == 1
        assert incident["categories"] == ["security"]
        assert len(incident["alerts"]) == 1
        assert incident["alerts"][0]["id"] == alert_id

    def test_same_device_fuses_into_one_incident(self, initialized_db):
        manager = IncidentManager()
        mac = "aa:bb:cc:00:00:02"
        first = manager.triage(_make_alert("security", "warning"),
                               "security", "warning", device_mac=mac)
        second = manager.triage(_make_alert("anomaly", "warning"),
                                "anomaly", "warning", device_mac=mac)
        assert first == second

        incident = incident_queries.get_incident(first)
        assert incident["alert_count"] == 2
        assert sorted(incident["categories"]) == ["anomaly", "security"]
        assert len(incident["alerts"]) == 2

    def test_severity_escalates_never_downgrades(self, initialized_db):
        manager = IncidentManager()
        mac = "aa:bb:cc:00:00:03"
        incident_id = manager.triage(_make_alert(severity="critical"),
                                     "security", "critical", device_mac=mac)
        manager.triage(_make_alert(severity="info"),
                       "anomaly", "info", device_mac=mac)
        incident = incident_queries.get_incident(incident_id)
        assert incident["severity"] == "critical"

    def test_different_devices_get_separate_incidents(self, initialized_db):
        manager = IncidentManager()
        first = manager.triage(_make_alert(), "security", "warning",
                               device_mac="aa:bb:cc:00:00:04")
        second = manager.triage(_make_alert(), "security", "warning",
                                device_mac="aa:bb:cc:00:00:05")
        assert first != second

    def test_network_wide_alerts_fuse_together(self, initialized_db):
        manager = IncidentManager()
        first = manager.triage(_make_alert("bandwidth"), "bandwidth", "warning")
        second = manager.triage(_make_alert("health"), "health", "warning")
        assert first == second
        incident = incident_queries.get_incident(first)
        assert incident["device_mac"] is None

    def test_network_wide_does_not_fuse_with_device(self, initialized_db):
        manager = IncidentManager()
        device = manager.triage(_make_alert(), "security", "warning",
                                device_mac="aa:bb:cc:00:00:06")
        network = manager.triage(_make_alert("bandwidth"), "bandwidth", "warning")
        assert device != network

    def test_window_expiry_opens_new_incident(self, initialized_db, db_connection):
        manager = IncidentManager(window_minutes=30)
        mac = "aa:bb:cc:00:00:07"
        first = manager.triage(_make_alert(), "security", "warning",
                               device_mac=mac)
        # Age the incident past the fusion window
        stale = (datetime.now() - timedelta(minutes=45)).strftime(_TS_FMT)
        db_connection.execute(
            "UPDATE incidents SET updated_at = ? WHERE id = ?", (stale, first))
        db_connection.commit()

        second = manager.triage(_make_alert(), "security", "warning",
                                device_mac=mac)
        assert second != first

    def test_resolved_incident_never_fuses(self, initialized_db):
        manager = IncidentManager()
        mac = "aa:bb:cc:00:00:08"
        first = manager.triage(_make_alert(), "security", "warning",
                               device_mac=mac)
        assert incident_queries.resolve_incident(first)
        second = manager.triage(_make_alert(), "security", "warning",
                                device_mac=mac)
        assert second != first

    def test_triage_failure_returns_none(self):
        # No database at all — triage must swallow the error, not raise.
        manager = IncidentManager()
        assert manager.triage(1, "security", "warning",
                              device_mac="aa:bb:cc:00:00:09") is None

    def test_stats_counters(self, initialized_db):
        manager = IncidentManager()
        mac = "aa:bb:cc:00:00:0a"
        manager.triage(_make_alert(), "security", "warning", device_mac=mac)
        manager.triage(_make_alert("anomaly"), "anomaly", "warning", device_mac=mac)
        stats = manager.get_stats()
        assert stats["triaged_count"] == 2
        assert stats["incidents_opened"] == 1


# ===================================================================
# AlertEngine hook
# ===================================================================

class TestAlertEngineHook:

    def test_alert_creation_triggers_triage(self, initialized_db):
        from alerts.alert_engine import AlertEngine
        engine = AlertEngine(cooldown_seconds=0)
        engine.incident_manager = IncidentManager()

        alert_id = engine.create_alert(
            alert_type="security", severity="high",
            title="Port scan", message="15 ports probed",
            metadata={"device_mac": "aa:bb:cc:00:00:0b"},
        )
        assert alert_id is not None

        incidents = incident_queries.get_incidents(status="open")
        assert len(incidents) == 1
        assert incidents[0]["device_mac"] == "aa:bb:cc:00:00:0b"
        detail = incident_queries.get_incident(incidents[0]["id"])
        assert detail["alerts"][0]["id"] == alert_id

    def test_engine_without_manager_still_creates_alert(self, initialized_db):
        from alerts.alert_engine import AlertEngine
        engine = AlertEngine(cooldown_seconds=0)  # no incident_manager
        alert_id = engine.create_alert(
            alert_type="health", severity="warning",
            title="Health", message="degraded",
        )
        assert alert_id is not None
        assert incident_queries.get_incidents() == []

    def test_broken_manager_never_blocks_alert(self, initialized_db):
        from alerts.alert_engine import AlertEngine

        class ExplodingManager:
            def triage(self, **kwargs):
                raise RuntimeError("boom")

        engine = AlertEngine(cooldown_seconds=0)
        engine.incident_manager = ExplodingManager()
        alert_id = engine.create_alert(
            alert_type="health", severity="warning",
            title="Health", message="degraded",
        )
        assert alert_id is not None


# ===================================================================
# API endpoints
# ===================================================================

class TestIncidentsAPI:

    def _seed_incident(self, mac="aa:bb:cc:00:00:0c"):
        manager = IncidentManager()
        alert_id = _make_alert("security", "high", "Port scan detected")
        return manager.triage(alert_id, "security", "high", device_mac=mac,
                              message="Port scan detected")

    def test_list_empty(self, client):
        resp = client.get('/api/incidents')
        assert resp.status_code == 200
        assert resp.get_json()['data'] == []

    def test_list_returns_incident(self, client):
        incident_id = self._seed_incident()
        resp = client.get('/api/incidents')
        data = resp.get_json()['data']
        assert len(data) == 1
        assert data[0]['id'] == incident_id
        assert data[0]['categories'] == ['security']

    def test_status_filter(self, client):
        incident_id = self._seed_incident()
        incident_queries.resolve_incident(incident_id)
        assert client.get('/api/incidents?status=open').get_json()['data'] == []
        resolved = client.get('/api/incidents?status=resolved').get_json()['data']
        assert len(resolved) == 1

    def test_bad_status_rejected(self, client):
        resp = client.get('/api/incidents?status=bogus')
        assert resp.status_code == 400

    def test_detail_includes_alerts(self, client):
        incident_id = self._seed_incident()
        resp = client.get(f'/api/incidents/{incident_id}')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['id'] == incident_id
        assert len(data['alerts']) == 1

    def test_detail_404(self, client):
        assert client.get('/api/incidents/99999').status_code == 404

    def test_resolve_endpoint(self, client):
        incident_id = self._seed_incident()
        resp = client.post(f'/api/incidents/{incident_id}/resolve')
        assert resp.status_code == 200
        assert resp.get_json()['data']['status'] == 'resolved'
        # Second resolve → 404 (already resolved)
        assert client.post(f'/api/incidents/{incident_id}/resolve').status_code == 404

    def test_stats_endpoint(self, client):
        self._seed_incident()
        resp = client.get('/api/incidents/stats')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['open_count'] == 1
