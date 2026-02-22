"""
middleware.py - Security Middleware (Auth + Rate Limiting)
===========================================================

Provides:
* **API Key authentication** — protects ``/api/*`` routes.
  Enabled via ``AUTH_ENABLED=True`` + ``NETWATCH_API_KEY`` env var.
  In development mode auth is off by default so the dashboard works
  out-of-box without a key.

* **Rate limiting** — simple in-memory sliding-window limiter.
  Prevents abuse and reduces load from misbehaving clients.

Both middlewares are applied via Flask ``before_request`` hooks.
"""

import hmac
import os
import sys
import time
import logging
import threading
from collections import defaultdict
from typing import Optional

from flask import Flask, request, jsonify

# Production logging / metrics / exceptions
try:
    from utils.logger import set_request_id, get_request_id
    from utils.metrics import metrics_collector
    from utils.exceptions import APIError, NetWatchError
    _PRODUCTION_UTILS = True
except ImportError:
    _PRODUCTION_UTILS = False

# Setup path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import (
    AUTH_ENABLED,
    API_KEY,
    AUTH_EXEMPT_ROUTES,
    AUTH_EXEMPT_PREFIXES,
    ENABLE_RATE_LIMITING,
    RATE_LIMIT_REQUESTS_PER_MINUTE,
    RATE_LIMIT_REQUESTS_PER_HOUR,
    RATE_LIMIT_BYPASS_LOCALHOST,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Sliding-window in-memory rate limiter keyed by client IP.

    Supports a primary window (e.g., per-minute) and optional secondary
    window (e.g., per-hour) without changing the public API. Cleans up
    stale entries automatically every 60 s.
    """

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        *,
        secondary_max_requests: int | None = None,
        secondary_window_seconds: int | None = None,
    ):
        self.max_requests = max_requests
        self.window = window_seconds
        self.secondary_max = secondary_max_requests
        self.secondary_window = secondary_window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def _trim(self, timestamps: list[float], cutoff: float) -> list[float]:
        return [t for t in timestamps if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        """Return *True* if the request is within the configured limits."""
        now = time.time()
        cutoff_primary = now - self.window
        cutoff_secondary = now - self.secondary_window if self.secondary_window else None

        with self._lock:
            # Periodic cleanup of stale keys (every 60 s)
            if now - self._last_cleanup > 60:
                stale_keys = [k for k, v in self._hits.items() if not v or v[-1] < cutoff_primary]
                for k in stale_keys:
                    del self._hits[k]
                self._last_cleanup = now

            timestamps = self._trim(self._hits[key], cutoff_primary)

            # Primary window check
            if len(timestamps) >= self.max_requests:
                self._hits[key] = timestamps
                return False

            # Secondary window check (optional)
            if self.secondary_max and self.secondary_window:
                ts_secondary = self._trim(timestamps, cutoff_secondary)
                if len(ts_secondary) >= self.secondary_max:
                    self._hits[key] = timestamps
                    return False

            timestamps.append(now)
            self._hits[key] = timestamps
            return True

    def remaining(self, key: str) -> int:
        """How many requests remain for *key* in the primary window."""
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            current = [t for t in self._hits.get(key, []) if t > cutoff]
        return max(0, self.max_requests - len(current))


# Module-level limiter instance
_limiter = RateLimiter(
    max_requests=RATE_LIMIT_REQUESTS_PER_MINUTE,
    window_seconds=60,
    secondary_max_requests=RATE_LIMIT_REQUESTS_PER_HOUR,
    secondary_window_seconds=3600,
)


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------

def register_middleware(app: Flask) -> None:
    """
    Register authentication and rate-limiting hooks on *app*.

    Call this once during ``create_app()``.
    """

    @app.before_request
    def _check_auth():
        """Enforce API-key authentication on /api/* routes."""
        if not AUTH_ENABLED or not API_KEY:
            return  # Auth disabled — allow everything

        path = request.path

        # Skip auth for exempt routes
        if path in AUTH_EXEMPT_ROUTES:
            return
        for prefix in AUTH_EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return
        # Only protect /api/* paths
        if not path.startswith('/api/'):
            return

        # Check API key in header or query param
        provided_key = (
            request.headers.get('X-API-Key')
            or request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
            or request.args.get('api_key')
        )

        if not provided_key or not hmac.compare_digest(provided_key, API_KEY):
            logger.warning("Unauthorized API access attempt from %s to %s", request.remote_addr, path)
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Valid API key required. Pass via X-API-Key header.'
            }), 401

    @app.before_request
    def _check_rate_limit():
        """Enforce per-IP rate limiting."""
        if not ENABLE_RATE_LIMITING:
            return

        client_ip = request.remote_addr or '127.0.0.1'

        # Bypass for localhost if configured
        if RATE_LIMIT_BYPASS_LOCALHOST and client_ip in ('127.0.0.1', '::1'):
            return

        if not _limiter.is_allowed(client_ip):
            logger.warning("Rate limit exceeded for %s", client_ip)
            return jsonify({
                'error': 'Too Many Requests',
                'message': f'Rate limit: {RATE_LIMIT_REQUESTS_PER_MINUTE} requests/minute.',
                'retry_after': 60,
            }), 429

    # -----------------------------------------------------------------
    # Request ID & Timing (production metrics)
    # -----------------------------------------------------------------

    @app.before_request
    def _inject_request_context():
        """Assign a unique request ID and start a timer for every request."""
        if _PRODUCTION_UTILS:
            set_request_id()  # generates a short uuid and stores in contextvars
        request._start_time = time.time()  # type: ignore[attr-defined]

    @app.after_request
    def _record_metrics(response):
        """Record request metrics and add security/trace headers."""
        # Metrics
        if _PRODUCTION_UTILS and hasattr(request, '_start_time'):
            duration_ms = (time.time() - request._start_time) * 1000  # type: ignore[attr-defined]
            metrics_collector.record_request(
                request.path, duration_ms, response.status_code,
            )
            # Inject request ID into response header for tracing
            rid = get_request_id()
            if rid:
                response.headers['X-Request-ID'] = rid

        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self' https://fonts.gstatic.com"
        )

        # HSTS header when behind HTTPS reverse proxy
        if request.headers.get('X-Forwarded-Proto') == 'https':
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains'
            )

        # Rate-limit headers
        if ENABLE_RATE_LIMITING:
            client_ip = request.remote_addr or '127.0.0.1'
            response.headers['X-RateLimit-Limit'] = str(RATE_LIMIT_REQUESTS_PER_MINUTE)
            response.headers['X-RateLimit-Remaining'] = str(_limiter.remaining(client_ip))
            if RATE_LIMIT_REQUESTS_PER_HOUR:
                response.headers['X-RateLimit-Limit-Hour'] = str(RATE_LIMIT_REQUESTS_PER_HOUR)
        return response

    # -----------------------------------------------------------------
    # Global error handlers
    # -----------------------------------------------------------------

    if _PRODUCTION_UTILS:
        @app.errorhandler(APIError)
        def _handle_api_error(error):
            """Handle custom API errors with proper status codes."""
            return jsonify({
                'error': error.__class__.__name__,
                'message': str(error),
                'status': error.status_code,
            }), error.status_code

        @app.errorhandler(Exception)
        def _handle_unexpected_error(error):
            """Catch-all for unhandled exceptions — never leak internals."""
            logger.error("Unhandled exception: %s", error, exc_info=True)
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred. Please try again.',
                'status': 500,
            }), 500

    logger.info(
        "Security middleware registered (auth=%s, rate_limit=%s, metrics=%s)",
        'ON' if (AUTH_ENABLED and API_KEY) else 'OFF',
        'ON' if ENABLE_RATE_LIMITING else 'OFF',
        'ON' if _PRODUCTION_UTILS else 'OFF',
    )
