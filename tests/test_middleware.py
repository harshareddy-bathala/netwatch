"""
test_middleware.py - Security Middleware Tests (Phase E)
=========================================================

Verifies:
- HSTS header when X-Forwarded-Proto is https
- CSP no longer contains 'unsafe-inline'
- API key auth enforced on /api/stream (EventSource via query param)
- /api/status strips version for unauthenticated requests
- Rate limiter basics
"""

import os
import sys
import hmac

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===================================================================
# HSTS Header
# ===================================================================

class TestHSTSHeader:
    """HSTS should be present only when behind HTTPS proxy."""

    def test_no_hsts_without_forwarded_proto(self, client):
        """Plain HTTP request should NOT include HSTS."""
        resp = client.get('/api/status')
        assert 'Strict-Transport-Security' not in resp.headers

    def test_hsts_with_https_forwarded_proto(self, client):
        """Request with X-Forwarded-Proto: https MUST include HSTS."""
        resp = client.get('/api/status', headers={
            'X-Forwarded-Proto': 'https',
        })
        hsts = resp.headers.get('Strict-Transport-Security', '')
        assert 'max-age=' in hsts
        assert 'includeSubDomains' in hsts

    def test_hsts_not_set_for_http_proto(self, client):
        """X-Forwarded-Proto: http should NOT set HSTS."""
        resp = client.get('/api/status', headers={
            'X-Forwarded-Proto': 'http',
        })
        assert 'Strict-Transport-Security' not in resp.headers


# ===================================================================
# CSP without unsafe-inline
# ===================================================================

class TestCSPPolicy:
    """Content-Security-Policy must not contain unsafe-inline."""

    def test_no_unsafe_inline_in_csp(self, client):
        """CSP should not have 'unsafe-inline' for script or style."""
        resp = client.get('/api/status')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert "'unsafe-inline'" not in csp

    def test_csp_default_src_self(self, client):
        resp = client.get('/api/status')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp

    def test_csp_allows_cdn(self, client):
        resp = client.get('/api/status')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert 'cdn.jsdelivr.net' in csp

    def test_csp_allows_google_fonts(self, client):
        resp = client.get('/api/status')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert 'fonts.googleapis.com' in csp


# ===================================================================
# API Key Auth on /api/stream
# ===================================================================

class TestSSEAuth:
    """/api/stream should require API key when auth is enabled."""

    def test_stream_accessible_without_auth_when_disabled(self, client):
        """When AUTH_ENABLED is False, /api/stream should work."""
        import config
        if config.AUTH_ENABLED and config.API_KEY:
            pytest.skip("Auth enabled in this env")
        resp = client.get('/api/stream')
        assert resp.status_code in (200, 429)  # 429 if rate-limited
        resp.close()

    def test_stream_requires_key_via_query_param(self, app, client):
        """When auth is enforced, /api/stream?api_key=... must authenticate."""
        import config
        original_auth = config.AUTH_ENABLED
        original_key = config.API_KEY

        try:
            config.AUTH_ENABLED = True
            config.API_KEY = 'test-secret-key-12345'

            # Reload middleware references so the before_request hooks
            # pick up the new config values.
            import backend.middleware as mw_mod
            mw_mod.AUTH_ENABLED = True
            mw_mod.API_KEY = 'test-secret-key-12345'

            # Without key → 401
            resp = client.get('/api/stream')
            assert resp.status_code == 401
            resp.close()

            # With key in query param → 200
            resp = client.get('/api/stream?api_key=test-secret-key-12345')
            assert resp.status_code in (200, 429)
            resp.close()
        finally:
            config.AUTH_ENABLED = original_auth
            config.API_KEY = original_key
            import backend.middleware as mw_mod2
            mw_mod2.AUTH_ENABLED = original_auth
            mw_mod2.API_KEY = original_key


# ===================================================================
# Version stripping on /api/status
# ===================================================================

class TestVersionStripping:
    """/api/status should strip version for unauthenticated requests."""

    @staticmethod
    def _get_system_bp_module():
        """Return the real module object (not the Blueprint) for patching."""
        import sys
        return sys.modules['backend.blueprints.system_bp']

    def test_status_no_version_when_unauthed(self, app, client):
        """Unauthenticated /api/status must not expose version."""
        import config
        sbp_mod = self._get_system_bp_module()
        original_auth = config.AUTH_ENABLED
        original_key = config.API_KEY
        mod_orig_auth = sbp_mod.AUTH_ENABLED
        mod_orig_key = sbp_mod.API_KEY

        try:
            config.AUTH_ENABLED = True
            config.API_KEY = 'test-secret-key-12345'
            sbp_mod.AUTH_ENABLED = True
            sbp_mod.API_KEY = 'test-secret-key-12345'

            # /api/status is auth-exempt for access, but version is stripped
            resp = client.get('/api/status')
            data = resp.get_json()
            assert 'version' not in data
        finally:
            config.AUTH_ENABLED = original_auth
            config.API_KEY = original_key
            sbp_mod.AUTH_ENABLED = mod_orig_auth
            sbp_mod.API_KEY = mod_orig_key

    def test_status_has_version_when_authed(self, app, client):
        """Authenticated /api/status should include version."""
        import config
        sbp_mod = self._get_system_bp_module()
        original_auth = config.AUTH_ENABLED
        original_key = config.API_KEY
        mod_orig_auth = sbp_mod.AUTH_ENABLED
        mod_orig_key = sbp_mod.API_KEY

        try:
            config.AUTH_ENABLED = True
            config.API_KEY = 'test-secret-key-12345'
            sbp_mod.AUTH_ENABLED = True
            sbp_mod.API_KEY = 'test-secret-key-12345'

            resp = client.get('/api/status', headers={
                'X-API-Key': 'test-secret-key-12345',
            })
            data = resp.get_json()
            assert 'version' in data
        finally:
            config.AUTH_ENABLED = original_auth
            config.API_KEY = original_key
            sbp_mod.AUTH_ENABLED = mod_orig_auth
            sbp_mod.API_KEY = mod_orig_key

    def test_status_has_version_when_auth_disabled(self, client):
        """When auth is disabled, version should be included."""
        import config
        sbp_mod = self._get_system_bp_module()
        original_auth = config.AUTH_ENABLED
        original_key = config.API_KEY
        mod_orig_auth = sbp_mod.AUTH_ENABLED
        mod_orig_key = sbp_mod.API_KEY

        try:
            config.AUTH_ENABLED = False
            config.API_KEY = ''
            sbp_mod.AUTH_ENABLED = False
            sbp_mod.API_KEY = ''

            resp = client.get('/api/status')
            data = resp.get_json()
            assert 'version' in data
        finally:
            config.AUTH_ENABLED = original_auth
            config.API_KEY = original_key
            sbp_mod.AUTH_ENABLED = mod_orig_auth
            sbp_mod.API_KEY = mod_orig_key


# ===================================================================
# Rate Limiter Unit Test
# ===================================================================

class TestRateLimiter:
    """Basic rate limiter behaviour."""

    def test_rate_limiter_allows_requests(self):
        from backend.middleware import RateLimiter
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.is_allowed('test-ip') is True
        assert limiter.is_allowed('test-ip') is False

    def test_rate_limiter_remaining(self):
        from backend.middleware import RateLimiter
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        assert limiter.remaining('test-ip') == 10
        limiter.is_allowed('test-ip')
        assert limiter.remaining('test-ip') == 9
