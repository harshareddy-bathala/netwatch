"""
test_dashboard_bandwidth.py - Dashboard API Bandwidth Format Tests
====================================================================

Verifies that ``/api/dashboard`` always returns bandwidth data in the
**dual** format (separate download/upload) both when the CaptureEngine
is running and when it is not.
"""

import json
import sys
import os
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =================================================================
# Helpers
# =================================================================

def _make_mock_engine():
    """Return a mock CaptureEngine with realistic bandwidth stats."""
    engine = MagicMock()
    engine.is_running = True
    engine.bandwidth.get_stats.return_value = {
        'total_bps': 1_250_000,
        'total_mbps': 10.0,
        'upload_bps': 500_000,
        'upload_mbps': 4.0,
        'download_bps': 750_000,
        'download_mbps': 6.0,
        'packets_per_second': 850,
    }
    engine.bandwidth.get_recent_rate.return_value = {
        'total_bps': 1_250_000,
        'total_mbps': 10.0,
        'upload_bps': 500_000,
        'upload_mbps': 4.0,
        'download_bps': 750_000,
        'download_mbps': 6.0,
    }
    engine.bandwidth.get_current_bps.return_value = 1_250_000
    return engine


# =================================================================
# Dashboard structure tests
# =================================================================

class TestDashboardStructure:
    """Verify the shape of /api/dashboard response."""

    def test_returns_200(self, client):
        resp = client.get('/api/dashboard')
        assert resp.status_code == 200

    def test_has_required_top_level_keys(self, client):
        """Dashboard must include stats, health, devices, protocols, bandwidth, alerts."""
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        for key in ('stats', 'health', 'devices', 'protocols', 'bandwidth', 'alerts'):
            assert key in data, f"Missing top-level key '{key}' in dashboard response"

    def test_bandwidth_is_dict_with_history(self, client):
        """bandwidth should be {history: [...]} (dual format)."""
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        bw = data.get('bandwidth')
        assert isinstance(bw, dict), f"Expected bandwidth to be dict, got {type(bw)}"
        assert 'history' in bw, f"bandwidth missing 'history' key: {bw}"

    def test_bandwidth_history_is_list(self, client):
        """bandwidth.history should be a list (possibly empty)."""
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        history = data.get('bandwidth', {}).get('history', None)
        assert isinstance(history, list), f"Expected list, got {type(history)}"

    def test_alert_stats_present(self, client):
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        assert 'alert_stats' in data

    def test_mode_present(self, client):
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        assert 'mode' in data
        mode = data['mode']
        assert 'mode' in mode or 'mode_display' in mode


# =================================================================
# Dual bandwidth format tests (no engine)
# =================================================================

class TestDashboardBandwidthFallback:
    """Without a CaptureEngine the bandwidth should still be dual format."""

    def test_fallback_bandwidth_dict(self, client):
        """Even without engine, bandwidth is a dict with 'history'."""
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        bw = data.get('bandwidth')
        assert isinstance(bw, dict)
        assert 'history' in bw

    def test_fallback_stats_exists(self, client):
        """Stats dict should exist (from DB aggregation)."""
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        assert data.get('stats') is not None


# =================================================================
# Dual bandwidth with engine (mocked)
# =================================================================

class TestDashboardBandwidthLive:
    """With a CaptureEngine the dashboard should include live dual fields."""

    def test_live_stats_upload_download(self, app, client):
        """Stats should have upload_mbps and download_mbps."""
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        stats = data.get('stats', {})
        assert 'upload_mbps' in stats, f"Missing upload_mbps in stats={stats}"
        assert 'download_mbps' in stats, f"Missing download_mbps in stats={stats}"

    def test_live_stats_values(self, app, client):
        """Upload/download values should match what the engine reports."""
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        stats = data.get('stats', {})
        # Engine mock returns upload_mbps=4.0, download_mbps=6.0
        assert stats.get('upload_mbps') == 4.0
        assert stats.get('download_mbps') == 6.0

    def test_live_stats_bandwidth_bps(self, app, client):
        """Stats should have bandwidth_bps (total bits/sec)."""
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        stats = data.get('stats', {})
        assert 'bandwidth_bps' in stats

    def test_live_stats_packets_per_second(self, app, client):
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        resp = client.get('/api/dashboard')
        data = resp.get_json()
        stats = data.get('stats', {})
        assert stats.get('packets_per_second') == 850


# =================================================================
# /api/bandwidth/dual endpoint
# =================================================================

class TestBandwidthDualEndpoint:
    """Verify /api/bandwidth/dual returns dual-format data."""

    def test_returns_200(self, client):
        resp = client.get('/api/bandwidth/dual')
        assert resp.status_code == 200

    def test_response_has_data(self, client):
        resp = client.get('/api/bandwidth/dual')
        data = resp.get_json()
        assert 'data' in data

    def test_response_has_meta(self, client):
        resp = client.get('/api/bandwidth/dual')
        data = resp.get_json()
        assert 'meta' in data

    def test_data_is_list(self, client):
        resp = client.get('/api/bandwidth/dual')
        data = resp.get_json()
        assert isinstance(data['data'], list)

    def test_interval_validation(self, client):
        """Invalid interval falls back to 'minute'."""
        resp = client.get('/api/bandwidth/dual?interval=bogus')
        assert resp.status_code == 200

    def test_hours_validation(self, client):
        """Hours are clamped to [1, 168]."""
        resp = client.get('/api/bandwidth/dual?hours=0')
        assert resp.status_code == 200
        resp2 = client.get('/api/bandwidth/dual?hours=200')
        assert resp2.status_code == 200
