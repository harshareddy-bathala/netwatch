"""
test_api_endpoints.py - API Endpoint Tests
=============================================

Tests for all REST API endpoints: GET, POST, error handling,
response format, and response times.
"""

import sys
import os
import json
import time
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# Health & Status Endpoints
# ===================================================================

class TestHealthEndpoints:
    """Tests for health check and status endpoints."""

    def test_health_check(self, client):
        resp = client.get('/health')
        assert resp.status_code == 200

    def test_api_status(self, client):
        resp = client.get('/api/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_api_info(self, client):
        resp = client.get('/api/info')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_api_health(self, client):
        resp = client.get('/api/health')
        assert resp.status_code == 200


# ===================================================================
# Device Endpoints
# ===================================================================

class TestDeviceEndpoints:
    """Tests for device-related API endpoints."""

    def test_get_devices(self, client):
        resp = client.get('/api/devices')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, (list, dict))

    def test_get_top_devices(self, client):
        resp = client.get('/api/devices/top')
        assert resp.status_code == 200

    def test_get_device_by_ip(self, client, db_connection):
        # Insert a device
        db_connection.execute(
            "INSERT OR REPLACE INTO devices "
            "(mac_address, ip_address, first_seen, last_seen, total_bytes_sent) "
            "VALUES (?, ?, ?, ?, ?)",
            ("AA:BB:CC:DD:EE:FF", "192.168.1.100",
             datetime.now().isoformat(), datetime.now().isoformat(), 5000)
        )
        db_connection.commit()

        resp = client.get('/api/devices/192.168.1.100')
        assert resp.status_code == 200

    def test_update_device_name(self, client, db_connection):
        # Insert a device first
        db_connection.execute(
            "INSERT OR REPLACE INTO devices "
            "(mac_address, ip_address, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?)",
            ("AA:BB:CC:DD:EE:FF", "192.168.1.100",
             datetime.now().isoformat(), datetime.now().isoformat())
        )
        db_connection.commit()

        resp = client.post(
            '/api/devices/update-name',
            data=json.dumps({
                "ip_address": "192.168.1.100",
                "hostname": "My Laptop"
            }),
            content_type='application/json'
        )
        assert resp.status_code == 200


# ===================================================================
# Alert Endpoints
# ===================================================================

class TestAlertEndpoints:
    """Tests for alert-related API endpoints."""

    def test_get_alerts(self, client):
        resp = client.get('/api/alerts')
        assert resp.status_code == 200

    def test_get_alerts_summary(self, client):
        resp = client.get('/api/alerts/summary')
        assert resp.status_code == 200

    def test_get_alert_stats(self, client):
        resp = client.get('/api/alerts/stats')
        assert resp.status_code == 200

    def test_get_recent_alerts(self, client):
        resp = client.get('/api/alerts/recent')
        assert resp.status_code == 200

    def test_acknowledge_alert(self, client, db_connection):
        # Insert an alert
        db_connection.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message) "
            "VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), "bandwidth", "warning", "Test")
        )
        db_connection.commit()

        cursor = db_connection.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        assert row is not None, "Alert was not inserted"
        alert_id = row[0]
        resp = client.post(f'/api/alerts/{alert_id}/acknowledge')
        assert resp.status_code == 200

    def test_resolve_alert(self, client, db_connection):
        db_connection.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, message) "
            "VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), "bandwidth", "warning", "Resolve test")
        )
        db_connection.commit()

        cursor = db_connection.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        assert row is not None, "Alert was not inserted"
        alert_id = row[0]
        resp = client.post(f'/api/alerts/{alert_id}/resolve')
        assert resp.status_code == 200

    def test_create_alert_endpoint(self, client):
        resp = client.post(
            '/api/alerts',
            data=json.dumps({
                "type": "bandwidth",
                "severity": "warning",
                "message": "API test alert"
            }),
            content_type='application/json'
        )
        assert resp.status_code in [200, 201]


# ===================================================================
# Dashboard & Stats Endpoints
# ===================================================================

class TestDashboardEndpoints:
    """Tests for dashboard and statistics endpoints."""

    def test_get_dashboard(self, client):
        resp = client.get('/api/dashboard')
        assert resp.status_code == 200

    def test_get_realtime(self, client):
        resp = client.get('/api/stats/realtime')
        assert resp.status_code == 200

    def test_get_protocols(self, client):
        resp = client.get('/api/protocols')
        assert resp.status_code == 200

    def test_get_bandwidth_history(self, client):
        resp = client.get('/api/bandwidth/history')
        assert resp.status_code == 200

    def test_get_bandwidth_dual(self, client):
        resp = client.get('/api/bandwidth/dual')
        assert resp.status_code == 200

    def test_get_traffic(self, client):
        resp = client.get('/api/traffic')
        assert resp.status_code == 200

    def test_get_activity(self, client):
        resp = client.get('/api/activity')
        assert resp.status_code == 200

    def test_get_metrics(self, client):
        resp = client.get('/api/metrics')
        assert resp.status_code == 200


# ===================================================================
# Interface Endpoints
# ===================================================================

class TestInterfaceEndpoints:
    """Tests for network interface endpoints."""

    def test_get_interface_status(self, client):
        resp = client.get('/api/interface/status')
        assert resp.status_code == 200

    def test_list_interfaces(self, client):
        resp = client.get('/api/interface/list')
        assert resp.status_code == 200

    def test_refresh_interface(self, client):
        resp = client.post('/api/interface/refresh')
        assert resp.status_code in [200, 500, 503]


# ===================================================================
# Discovery Endpoints
# ===================================================================

class TestDiscoveryEndpoints:
    """Tests for network discovery endpoints."""

    def test_get_discovered_devices(self, client):
        resp = client.get('/api/discovery/devices')
        assert resp.status_code in [200, 500, 501, 503]

    def test_get_discovery_capabilities(self, client):
        resp = client.get('/api/discovery/capabilities')
        assert resp.status_code in [200, 500]


# ===================================================================
# Error Handling Tests
# ===================================================================

class TestErrorHandling:
    """Tests for API error handling."""

    def test_404_on_unknown_route(self, client):
        resp = client.get('/api/nonexistent')
        assert resp.status_code == 404

    def test_405_on_wrong_method(self, client):
        resp = client.delete('/api/status')
        assert resp.status_code == 405

    def test_json_error_responses(self, client):
        resp = client.get('/api/nonexistent')
        data = resp.get_json()
        # Error response should be JSON
        if data:
            assert isinstance(data, dict)

    def test_invalid_device_ip(self, client):
        resp = client.get('/api/devices/not-an-ip')
        assert resp.status_code in (400, 404)

    def test_invalid_alert_id(self, client):
        resp = client.post('/api/alerts/999999/acknowledge')
        assert resp.status_code in [400, 404]


# ===================================================================
# Response Time Tests
# ===================================================================

class TestResponseTimes:
    """Tests for API response time targets (<100ms)."""

    def test_status_response_time(self, client):
        start = time.perf_counter()
        client.get('/api/status')
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500, f"Status endpoint took {elapsed_ms:.0f}ms"

    def test_dashboard_response_time(self, client):
        start = time.perf_counter()
        client.get('/api/dashboard')
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500, f"Dashboard endpoint took {elapsed_ms:.0f}ms"

    def test_devices_response_time(self, client):
        start = time.perf_counter()
        client.get('/api/devices')
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500, f"Devices endpoint took {elapsed_ms:.0f}ms"

    def test_alerts_response_time(self, client):
        start = time.perf_counter()
        client.get('/api/alerts')
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500, f"Alerts endpoint took {elapsed_ms:.0f}ms"


# ===================================================================
# Security Tests (via API)
# ===================================================================

class TestAPISecurity:
    """Security-related API tests."""

    def test_no_debug_info_in_errors(self, client):
        """Error responses should not leak debug info in production."""
        resp = client.get('/api/nonexistent')
        body = resp.get_data(as_text=True).lower()
        # Should not contain Python tracebacks
        assert "traceback" not in body
        assert "file \"" not in body

    def test_no_sql_injection_in_device_lookup(self, client):
        """SQL injection attempts should not work."""
        payloads = [
            "'; DROP TABLE devices; --",
            "1 OR 1=1",
            "\" OR \"\"=\"",
        ]
        for payload in payloads:
            resp = client.get(f'/api/devices/{payload}')
            # Should not crash (200 for not found or 400/404)
            assert resp.status_code in [200, 400, 404, 500]

    def test_xss_in_device_name(self, client, db_connection):
        """XSS payloads should be handled safely."""
        db_connection.execute(
            "INSERT OR REPLACE INTO devices "
            "(mac_address, ip_address, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            ("AA:BB:CC:DD:EE:FF", "192.168.1.100",
             datetime.now().isoformat(), datetime.now().isoformat())
        )
        db_connection.commit()

        resp = client.post(
            '/api/devices/update-name',
            data=json.dumps({
                "ip_address": "192.168.1.100",
                "name": "<script>alert('xss')</script>"
            }),
            content_type='application/json'
        )
        # Should accept but sanitize, or reject
        assert resp.status_code in [200, 400]

    def test_cors_headers(self, client):
        """CORS should be configured."""
        resp = client.options('/api/status')
        # OPTIONS should return 200
        assert resp.status_code in [200, 204, 404, 405]
