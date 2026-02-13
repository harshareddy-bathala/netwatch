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
# Retry helper
# ---------------------------------------------------------------------------

import time
import logging
from functools import wraps

_retry_logger = logging.getLogger(__name__)


def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0,
          exceptions: tuple = (DatabaseError, ConnectionError, OSError)):
    """
    Decorator to retry a function on transient failures.

    Args:
        max_attempts: Maximum number of attempts.
        delay: Initial delay between retries (seconds).
        backoff: Multiplier applied to delay after each retry.
        exceptions: Tuple of exception types that trigger a retry.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay

            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt >= max_attempts:
                        _retry_logger.error(
                            "%s failed after %d attempts: %s",
                            func.__qualname__, max_attempts, e,
                        )
                        raise

                    _retry_logger.warning(
                        "%s failed (attempt %d/%d), retrying in %.1fs: %s",
                        func.__qualname__, attempt, max_attempts, current_delay, e,
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Prevent cascading failures by tracking consecutive errors.

    States:
        CLOSED   — normal operation, calls pass through.
        OPEN     — too many failures, calls are rejected immediately.
        HALF_OPEN — after timeout, allow one probe call to check recovery.

    Usage::

        db_breaker = CircuitBreaker(failure_threshold=5, timeout=60)

        def query_db():
            return db_breaker.call(execute_query, "SELECT 1")
    """

    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time: float = 0.0
        self.state = "CLOSED"
        self._logger = logging.getLogger(f"{__name__}.CircuitBreaker")

    def call(self, func, *args, **kwargs):
        """
        Execute *func* through the circuit breaker.

        Raises ``NetWatchError`` when the circuit is OPEN and the
        timeout has not yet elapsed.
        """
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "HALF_OPEN"
                self._logger.info("Circuit breaker HALF_OPEN — probing %s", func.__name__)
            else:
                raise NetWatchError(
                    f"Circuit breaker OPEN for {func.__name__} "
                    f"(failures: {self.failure_count})"
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure(func)
            raise

    def _on_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def _on_failure(self, func) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            self._logger.error(
                "Circuit breaker OPEN for %s (failures: %d)",
                getattr(func, "__name__", str(func)), self.failure_count,
            )

    @property
    def is_open(self) -> bool:
        return self.state == "OPEN"

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED."""
        self.failure_count = 0
        self.state = "CLOSED"
