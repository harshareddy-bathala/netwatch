"""
exceptions.py - NetWatch Custom Exception Hierarchy
======================================================

Provides a structured set of exceptions for clear error categorisation,
consistent API error responses, and targeted retry logic.

Usage::

    from utils.exceptions import CaptureError, DatabaseError, APIError

    raise CaptureError("Requires administrator privileges")
    raise APIError("Device not found", status_code=404)
"""


class NetWatchError(Exception):
    """Base exception for all NetWatch-specific errors."""
    pass


class CaptureError(NetWatchError):
    """Packet capture related errors (permissions, interface issues)."""
    pass


class DatabaseError(NetWatchError):
    """Database operation errors (connection, query, integrity)."""
    pass


class ConfigurationError(NetWatchError):
    """Configuration or environment errors."""
    pass


class InterfaceError(NetWatchError):
    """Network interface detection / management errors."""
    pass


class DetectorError(NetWatchError):
    """Anomaly detection / ML model errors."""
    pass


class APIError(NetWatchError):
    """
    API endpoint errors — carries an HTTP status code.

    Attributes:
        status_code: HTTP status code to return to the client (default 500).
    """

    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Backward-compatible re-exports (moved to utils/resilience.py in Phase 4)
# ---------------------------------------------------------------------------

from utils.resilience import retry, CircuitBreaker  # noqa: F401, E402
