"""
test_alert_rules_export.py - Alert Rules CRUD & Export Endpoint Tests (#58)
=============================================================================

Tests for custom alert rule CRUD endpoints (POST/PUT/DELETE)
and data export endpoints (CSV/JSON).
"""

import sys
import os
import json
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Alert Rule CRUD
# ===================================================================

class TestAlertRuleCRUD:
    """Tests for /api/alert-rules endpoints."""

    def test_list_rules_empty(self, client):
        resp = client.get('/api/alert-rules')
        assert resp.status_code == 200
        data = resp.get_json()
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_create_rule_success(self, client):
        resp = client.post(
            '/api/alert-rules',
            data=json.dumps({
                "name": "High Bandwidth",
                "metric": "bandwidth_bps",
                "operator": ">",
                "threshold": 50_000_000,
                "severity": "warning",
                "description": "Alert when bandwidth > 50 Mbps",
            }),
            content_type='application/json',
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["data"]["success"] is True
        assert "id" in data["data"]

    def test_create_rule_invalid_metric(self, client):
        resp = client.post(
            '/api/alert-rules',
            data=json.dumps({
                "name": "Bad metric",
                "metric": "nonexistent_metric",
                "operator": ">",
                "threshold": 10,
            }),
            content_type='application/json',
        )
        assert resp.status_code == 400

    def test_create_rule_missing_threshold(self, client):
        resp = client.post(
            '/api/alert-rules',
            data=json.dumps({
                "name": "No threshold",
                "metric": "bandwidth_bps",
                "operator": ">",
            }),
            content_type='application/json',
        )
        assert resp.status_code == 400

    def test_create_rule_no_body(self, client):
        resp = client.post('/api/alert-rules', content_type='application/json')
        assert resp.status_code == 400

    def test_update_rule(self, client):
        # Create a rule first
        create_resp = client.post(
            '/api/alert-rules',
            data=json.dumps({
                "name": "Update me",
                "metric": "bandwidth_bps",
                "operator": ">",
                "threshold": 100,
                "severity": "warning",
            }),
            content_type='application/json',
        )
        rule_id = create_resp.get_json()["data"]["id"]

        # Update it
        resp = client.put(
            f'/api/alert-rules/{rule_id}',
            data=json.dumps({"threshold": 200}),
            content_type='application/json',
        )
        assert resp.status_code == 200

    def test_delete_rule(self, client):
        # Create then delete
        create_resp = client.post(
            '/api/alert-rules',
            data=json.dumps({
                "name": "Delete me",
                "metric": "bandwidth_bps",
                "operator": ">",
                "threshold": 100,
                "severity": "warning",
            }),
            content_type='application/json',
        )
        rule_id = create_resp.get_json()["data"]["id"]

        resp = client.delete(f'/api/alert-rules/{rule_id}')
        assert resp.status_code == 200

    def test_delete_nonexistent_rule(self, client):
        resp = client.delete('/api/alert-rules/999999')
        assert resp.status_code in (200, 404)


# ===================================================================
# Alert POST Validation
# ===================================================================

class TestAlertPostValidation:
    """Tests for POST /api/alerts input validation."""

    def test_create_alert_no_body(self, client):
        resp = client.post('/api/alerts', content_type='application/json')
        assert resp.status_code == 400

    def test_create_alert_invalid_type(self, client):
        resp = client.post(
            '/api/alerts',
            data=json.dumps({"type": "INVALID_TYPE", "severity": "warning", "message": "test"}),
            content_type='application/json',
        )
        assert resp.status_code == 400

    def test_create_alert_invalid_severity(self, client):
        resp = client.post(
            '/api/alerts',
            data=json.dumps({"type": "bandwidth", "severity": "INVALID_SEV", "message": "test"}),
            content_type='application/json',
        )
        assert resp.status_code == 400

    def test_create_alert_empty_message(self, client):
        resp = client.post(
            '/api/alerts',
            data=json.dumps({"type": "bandwidth", "severity": "warning", "message": ""}),
            content_type='application/json',
        )
        assert resp.status_code == 400

    def test_create_alert_message_too_long(self, client):
        resp = client.post(
            '/api/alerts',
            data=json.dumps({"type": "bandwidth", "severity": "warning", "message": "x" * 501}),
            content_type='application/json',
        )
        assert resp.status_code == 400


# ===================================================================
# Export Endpoints
# ===================================================================

class TestExportEndpoints:
    """Tests for /api/export/<fmt> endpoints."""

    def test_export_json_devices(self, client):
        resp = client.get('/api/export/json?type=devices')
        assert resp.status_code in [200, 403]  # 403 if export disabled
        if resp.status_code == 200:
            assert resp.content_type.startswith('application/json')

    def test_export_csv_devices(self, client):
        resp = client.get('/api/export/csv?type=devices')
        assert resp.status_code in [200, 403]

    def test_export_json_traffic(self, client):
        resp = client.get('/api/export/json?type=traffic')
        assert resp.status_code in [200, 403]

    def test_export_invalid_format(self, client):
        resp = client.get('/api/export/xml')
        assert resp.status_code in [400, 403]
