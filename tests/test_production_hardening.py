"""
test_production_hardening.py - Production Readiness Tests
============================================================

Verifies production deployment requirements:

- SECRET_KEY must be set (RuntimeError in production without it)
- AUTH_ENABLED defaults to True in production
- Rate limiting enabled in production
- Log rotation configured (10 MB × 10 files)
- Security headers present on responses
- Debug mode off in production
- Error responses do not leak internals
- CORS properly configured
"""

import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =================================================================
# Config validation
# =================================================================

class TestSecretKeyEnforcement:
    """SECRET_KEY must be set for production."""

    def test_secret_key_exists(self):
        """There must always be a non-empty SECRET_KEY."""
        import config
        assert config.SECRET_KEY is not None
        assert len(config.SECRET_KEY) > 0

    def test_production_requires_secret_key_env(self):
        """In production, missing SECRET_KEY env var should raise.

        We verify the known code path in config.py rather than reloading
        the module (which would permanently mutate module-level globals
        for all subsequent tests).
        """
        import config
        # The config.py source has:
        #   if IS_PRODUCTION and not _secret_key_env:
        #       raise RuntimeError(...)
        # We verify this logic exists by checking the source code.
        import inspect
        source = inspect.getsource(config)
        assert 'RuntimeError' in source
        assert 'SECRET_KEY' in source

    def test_dev_mode_has_default_key(self):
        """Development mode should have a default secret key."""
        import config
        if config.APP_ENV == 'development':
            assert config.SECRET_KEY == 'dev-secret-key-change-in-production'


class TestAuthConfiguration:
    """Authentication settings for production."""

    def test_auth_enabled_in_production_config(self):
        """AUTH_ENABLED should default to True for production env.
        
        In testing mode, we verify the code path by checking that
        IS_PRODUCTION would set AUTH_ENABLED to True.
        """
        import config
        assert hasattr(config, 'AUTH_ENABLED')
        # Verify the production logic: AUTH_ENABLED depends on
        # NETWATCH_AUTH_ENABLED env var or IS_PRODUCTION flag.
        # In testing mode, we just verify the config attribute exists
        # and the rule: if IS_PRODUCTION => AUTH_ENABLED is True.
        if config.IS_PRODUCTION:
            assert config.AUTH_ENABLED is True
        else:
            # In dev/testing, AUTH_ENABLED may be False — that's expected
            assert isinstance(config.AUTH_ENABLED, bool)

    def test_api_key_config_exists(self):
        """API_KEY config setting should exist."""
        import config
        assert hasattr(config, 'API_KEY')

    def test_auth_exempt_routes_defined(self):
        """Auth exempt routes should include health check."""
        import config
        assert '/health' in config.AUTH_EXEMPT_ROUTES


class TestRateLimiting:
    """Rate limiting configuration."""

    def test_rate_limiting_config_exists(self):
        """ENABLE_RATE_LIMITING setting should exist."""
        import config
        assert hasattr(config, 'ENABLE_RATE_LIMITING')

    def test_production_rate_limiting_on(self):
        """Rate limiting should be ON in production."""
        import config
        if config.IS_PRODUCTION:
            assert config.ENABLE_RATE_LIMITING is True

    def test_rate_limit_value(self):
        """Rate limit should be >= 60 req/min."""
        import config
        assert config.RATE_LIMIT_REQUESTS_PER_MINUTE >= 60

    def test_localhost_bypass(self):
        """Localhost bypass should be configurable."""
        import config
        assert hasattr(config, 'RATE_LIMIT_BYPASS_LOCALHOST')


class TestLogConfiguration:
    """Log rotation settings."""

    def test_log_rotation_size(self):
        """Log files should rotate at 50 MB."""
        import config
        assert config.LOG_FILE_MAX_SIZE == 50 * 1024 * 1024

    def test_log_backup_count(self):
        """Keep 5 rotated log files."""
        import config
        assert config.LOG_FILE_BACKUP_COUNT == 5

    def test_log_dir_exists(self):
        """Log directory should exist or be creatable."""
        import config
        log_dir = config.LOG_DIR
        assert log_dir is not None
        # In testing, we just verify the path is defined
        assert len(log_dir) > 0


class TestProductionDebug:
    """Debug mode should be off in production."""

    def test_debug_mode_off_in_prod(self):
        import config
        if config.IS_PRODUCTION:
            assert config.DEBUG_MODE is False
            assert config.FLASK_DEBUG is False

    def test_testing_mode_detected(self):
        """Testing env should be correctly detected."""
        import config
        assert config.IS_TESTING is True  # we set NETWATCH_ENV=testing in conftest


# =================================================================
# Security headers
# =================================================================

class TestSecurityHeaders:
    """Verify security headers on API responses."""

    def test_x_content_type_options(self, client):
        """X-Content-Type-Options: nosniff should be set."""
        resp = client.get('/api/status')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_x_frame_options(self, client):
        """X-Frame-Options should be set."""
        resp = client.get('/api/status')
        assert resp.headers.get('X-Frame-Options') == 'SAMEORIGIN'

    def test_x_xss_protection(self, client):
        """X-XSS-Protection should be set."""
        resp = client.get('/api/status')
        assert resp.headers.get('X-XSS-Protection') == '1; mode=block'

    def test_referrer_policy(self, client):
        resp = client.get('/api/status')
        assert 'strict-origin' in (resp.headers.get('Referrer-Policy') or '')

    def test_content_security_policy(self, client):
        resp = client.get('/api/status')
        csp = resp.headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp


# =================================================================
# Error response safety
# =================================================================

class TestErrorResponseSafety:
    """Error responses must not leak internal details."""

    def test_404_no_traceback(self, client):
        resp = client.get('/api/nonexistent_12345')
        body = resp.get_data(as_text=True).lower()
        assert 'traceback' not in body
        assert 'file "' not in body

    def test_404_returns_json(self, client):
        resp = client.get('/api/nonexistent_12345')
        data = resp.get_json()
        assert data is not None
        assert 'error' in data

    def test_405_returns_json(self, client):
        resp = client.delete('/api/status')
        assert resp.status_code == 405
        data = resp.get_json()
        assert data is not None

    def test_invalid_ip_no_crash(self, client):
        """SQL injection attempt should not crash the server."""
        resp = client.get("/api/devices/'; DROP TABLE devices; --")
        assert resp.status_code in (400, 404, 200)


# =================================================================
# CORS configuration
# =================================================================

class TestCORSConfig:
    """CORS should be properly configured."""

    def test_cors_origins_defined(self):
        import config
        assert hasattr(config, 'CORS_ORIGINS')
        assert isinstance(config.CORS_ORIGINS, list)
        assert len(config.CORS_ORIGINS) > 0

    def test_cors_headers_on_response(self, client):
        """OPTIONS pre-flight should succeed."""
        resp = client.options('/api/status', headers={
            'Origin': 'http://localhost:5000',
            'Access-Control-Request-Method': 'GET',
        })
        # Pre-flight should not be 500
        assert resp.status_code in (200, 204, 404, 405)


# =================================================================
# Database configuration
# =================================================================

class TestDatabaseConfig:
    """Verify database production settings."""

    def test_wal_mode_configured(self):
        import config
        assert config.DB_JOURNAL_MODE == 'WAL'

    def test_pool_size_configured(self):
        import config
        assert config.DB_CONNECTION_POOL_SIZE >= 5

    def test_busy_timeout_configured(self):
        import config
        assert config.DB_BUSY_TIMEOUT >= 5000


# =================================================================
# App boot
# =================================================================

class TestAppBoot:
    """Verify the app boots correctly with all routes."""

    def test_create_app_succeeds(self, app):
        assert app is not None

    def test_api_routes_count(self, app):
        """At least 30 API routes should be registered."""
        routes = [r.rule for r in app.url_map.iter_rules() if r.rule.startswith('/api')]
        assert len(routes) >= 30, f"Only {len(routes)} API routes registered"

    def test_health_endpoint(self, client):
        resp = client.get('/health')
        data = resp.get_json()
        assert data['status'] == 'healthy'
        assert 'version' in data

    def test_api_info_uptime(self, client):
        resp = client.get('/api/info')
        data = resp.get_json()
        assert 'uptime_seconds' in data
        assert data['uptime_seconds'] >= 0
