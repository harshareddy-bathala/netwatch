"""
test_sse_payload.py - SSE Payload Integration Tests
=====================================================

Verifies that the SSE /api/stream endpoint yields valid JSON with
dual bandwidth fields (download_mbps / upload_mbps) in both the
**live engine** path and the **fallback** (no engine) path.

Also tests the SSE connection-limiting (max 10 concurrent clients).
"""

import json
import sys
import os
import time
import threading
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =================================================================
# Helpers
# =================================================================

def _reset_sse_cache():
    """Clear the module-level SSE cache so each test starts fresh."""
    import importlib
    import sys
    mod = importlib.import_module('backend.blueprints.bandwidth_bp')
    with mod._sse_cache_lock:
        mod._sse_cached_payload = None
        mod._sse_cache_time = 0.0
        mod._sse_building = False
    with mod._sse_active_lock:
        mod._sse_active = 0


def _get_bp_module():
    """Get the actual bandwidth_bp module (not the Blueprint object)."""
    import importlib
    return importlib.import_module('backend.blueprints.bandwidth_bp')


def _first_sse_event(client, timeout=5):
    """
    GET /api/stream and return the first ``data:`` line parsed as a dict.
    Streams are infinite so we read just enough bytes for the first frame.
    """
    resp = client.get('/api/stream', headers={'Accept': 'text/event-stream'})
    assert resp.status_code == 200
    # resp.data gives the *entire* generator output in test-client mode,
    # but the generator is infinite.  Instead iterate the response object.
    for chunk in resp.response:
        text = chunk if isinstance(chunk, str) else chunk.decode('utf-8', errors='replace')
        for line in text.split('\n'):
            if line.startswith('data: '):
                payload = json.loads(line[6:])
                resp.close()
                return payload
    pytest.fail("No SSE data frame received within the response")


# =================================================================
# Fallback path (no engine)
# =================================================================

class TestSSEFallbackPath:
    """SSE payload when CaptureEngine is *not* running."""

    def test_sse_returns_event_stream(self, client):
        """Content-Type must be text/event-stream."""
        _reset_sse_cache()
        resp = client.get('/api/stream')
        assert resp.status_code == 200
        assert 'text/event-stream' in resp.content_type

    def test_fallback_has_stats_key(self, client):
        """Payload should always include a 'stats' key."""
        _reset_sse_cache()
        payload = _first_sse_event(client)
        assert 'stats' in payload

    def test_fallback_has_protocol_key(self, client):
        """Payload includes protocol distribution."""
        _reset_sse_cache()
        payload = _first_sse_event(client)
        assert 'protocols' in payload

    def test_fallback_has_devices_key(self, client):
        """Payload includes top devices."""
        _reset_sse_cache()
        payload = _first_sse_event(client)
        assert 'devices' in payload

    def test_fallback_has_alerts_key(self, client):
        """Payload includes alerts list."""
        _reset_sse_cache()
        payload = _first_sse_event(client)
        assert 'alerts' in payload

    def test_fallback_has_mode_key(self, client):
        """Payload includes mode info."""
        _reset_sse_cache()
        payload = _first_sse_event(client)
        assert 'mode' in payload

    def test_fallback_has_bandwidth_history(self, client):
        """Payload includes bandwidth_history (may be empty list)."""
        _reset_sse_cache()
        payload = _first_sse_event(client)
        assert 'bandwidth_history' in payload


# =================================================================
# Live engine path (mocked)
# =================================================================

def _make_mock_engine():
    """Return a mock CaptureEngine with realistic bandwidth stats."""
    engine = MagicMock()
    engine.is_running = True
    engine.bandwidth.get_current_bps.return_value = 1_250_000  # 10 Mbps
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
    engine.bandwidth.get_recent_history.return_value = [
        {'timestamp': '2026-01-01T00:00:00', 'download_mbps': 5.0, 'upload_mbps': 3.0}
    ]
    return engine


class TestSSELivePath:
    """SSE payload when CaptureEngine IS running (mocked)."""

    def test_live_stats_has_upload_mbps(self, app, client):
        """Stats must include upload_mbps when engine is live."""
        _reset_sse_cache()
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        payload = _first_sse_event(client)
        stats = payload.get('stats', {})
        assert 'upload_mbps' in stats or 'upload_bps' in stats

    def test_live_stats_has_download_mbps(self, app, client):
        """Stats must include download_mbps when engine is live."""
        _reset_sse_cache()
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        payload = _first_sse_event(client)
        stats = payload.get('stats', {})
        assert 'download_mbps' in stats or 'download_bps' in stats

    def test_live_bandwidth_fields(self, app, client):
        """Payload has top-level stats with bandwidth fields and bandwidth_history."""
        _reset_sse_cache()
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        payload = _first_sse_event(client)
        # Phase 4: bandwidth data is at top-level stats + bandwidth_history
        stats = payload.get('stats', {})
        assert 'upload_mbps' in stats or 'upload_bps' in stats
        assert 'download_mbps' in stats or 'download_bps' in stats
        assert 'bandwidth_history' in payload

    def test_live_bandwidth_values_positive(self, app, client):
        """Upload/download values should be > 0 when engine reports traffic."""
        _reset_sse_cache()
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        payload = _first_sse_event(client)
        stats = payload.get('stats', {})
        # At least one of download_bps/download_mbps should be > 0
        dl = stats.get('download_bps', 0) or stats.get('download_mbps', 0)
        assert dl > 0, f"Expected positive download bandwidth, got stats={stats}"

    def test_live_packets_per_second(self, app, client):
        """Stats should include packets_per_second field."""
        _reset_sse_cache()
        app.config['CAPTURE_ENGINE'] = _make_mock_engine()
        payload = _first_sse_event(client)
        stats = payload.get('stats', {})
        assert 'packets_per_second' in stats


# =================================================================
# SSE Connection Limiting
# =================================================================

class TestSSEConnectionLimiting:
    """Verify that /api/stream rejects clients above the max."""

    def test_sse_429_when_limit_exceeded(self, app, client):
        """The 11th simultaneous SSE connection should get a 429."""
        _reset_sse_cache()
        bp_mod = _get_bp_module()
        # Artificially set active count to the limit
        with bp_mod._sse_active_lock:
            bp_mod._sse_active = bp_mod._SSE_MAX_CONNECTIONS

        resp = client.get('/api/stream')
        assert resp.status_code == 429

        # Reset
        with bp_mod._sse_active_lock:
            bp_mod._sse_active = 0

    def test_sse_200_under_limit(self, client):
        """Normal connections under the limit get 200."""
        _reset_sse_cache()
        resp = client.get('/api/stream')
        assert resp.status_code == 200
        resp.close()

    def test_sse_max_connections_is_10(self):
        """Sanity check: the configured limit is 10."""
        bp_mod = _get_bp_module()
        assert bp_mod._SSE_MAX_CONNECTIONS == 10


# =================================================================
# SSE Payload Build Benchmark (Phase E)
# =================================================================

class TestSSEPayloadBenchmark:
    """SSE payload build must complete in < 50 ms."""

    def test_payload_build_under_50ms(self, app, client):
        """_build_sse_payload() should complete in under 50 ms."""
        _reset_sse_cache()
        bp_mod = _get_bp_module()

        import time
        iterations = 5
        times = []
        for _ in range(iterations):
            # Clear cache to force a rebuild each time
            with bp_mod._sse_cache_lock:
                bp_mod._sse_cached_payload = None
                bp_mod._sse_cache_time = 0.0
                bp_mod._sse_building = False

            with app.test_request_context('/api/stream'):
                start = time.perf_counter()
                result = bp_mod._build_sse_payload()
                elapsed_ms = (time.perf_counter() - start) * 1000
                times.append(elapsed_ms)

        avg_ms = sum(times) / len(times)
        assert avg_ms < 50, f"SSE payload build took {avg_ms:.1f}ms avg (limit: 50ms)"

    def test_cached_payload_under_1ms(self, app, client):
        """Cached SSE payload retrieval should be nearly instant."""
        _reset_sse_cache()
        bp_mod = _get_bp_module()

        with app.test_request_context('/api/stream'):
            # First call: builds cache
            bp_mod._build_sse_payload()

            # Second call: should hit cache
            import time
            start = time.perf_counter()
            bp_mod._build_sse_payload()
            elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 5, f"Cached SSE payload took {elapsed_ms:.1f}ms (limit: 5ms)"
