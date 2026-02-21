"""
performance_logger.py - Performance Monitoring & Logging
==========================================================

Provides decorators and utilities for tracking slow function calls
and logging system health metrics.

Usage::

    from utils.performance_logger import log_performance, log_system_health

    @log_performance(threshold_ms=100)
    def expensive_query():
        ...

    # Call periodically:
    log_system_health()
"""

import time
import functools
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Performance decorator
# ---------------------------------------------------------------------------

def log_performance(threshold_ms: float = 100, logger_override: Optional[logging.Logger] = None):
    """
    Decorator to log function calls that exceed *threshold_ms*.

    Logs a WARNING when the wrapped function takes longer than the threshold,
    which makes it easy to spot regressions in production logs.

    Args:
        threshold_ms: Minimum execution time (ms) to trigger a warning.
        logger_override: Optional logger to use instead of the module logger.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            except Exception:
                raise
            finally:
                duration_ms = (time.perf_counter() - start) * 1000

                if duration_ms > threshold_ms:
                    (logger_override or logger).warning(
                        "Slow execution: %s took %.1fms (threshold: %dms)",
                        func.__qualname__,
                        duration_ms,
                        threshold_ms,
                        extra={
                            "function_name": func.__qualname__,
                            "duration_ms": round(duration_ms, 1),
                            "threshold_ms": threshold_ms,
                        },
                    )
                elif duration_ms > threshold_ms * 0.5:
                    # Debug-level if approaching threshold
                    (logger_override or logger).debug(
                        "%s took %.1fms", func.__qualname__, duration_ms,
                    )

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# System health snapshot
# ---------------------------------------------------------------------------

def log_system_health() -> dict:
    """
    Log current system resource usage and return a health dict.

    Uses ``psutil`` when available; falls back to basic os-level metrics.
    """
    health_data: dict = {}

    try:
        import psutil

        process = psutil.Process(os.getpid())

        health_data = {
            "cpu_percent": process.cpu_percent(interval=0.5),
            "memory_mb": round(process.memory_info().rss / (1024 * 1024), 1),
            "threads": process.num_threads(),
        }

        # open_files() and net_connections() may raise AccessDenied or
        # AttributeError on Windows — guard each independently.
        try:
            health_data["open_files"] = len(process.open_files())
        except (psutil.AccessDenied, AttributeError, psutil.NoSuchProcess):
            health_data["open_files"] = 0

        try:
            health_data["connections"] = len(process.net_connections())
        except (psutil.AccessDenied, AttributeError, psutil.NoSuchProcess):
            health_data["connections"] = 0

        logger.info(
            "System health: CPU=%.1f%%, Memory=%.1fMB, Threads=%d, Files=%d, Conns=%d",
            health_data["cpu_percent"],
            health_data["memory_mb"],
            health_data["threads"],
            health_data["open_files"],
            health_data["connections"],
            extra=health_data,
        )

    except ImportError:
        logger.debug("psutil not available — system health metrics limited")
        import threading

        health_data = {
            "cpu_percent": 0,
            "memory_mb": 0,
            "threads": threading.active_count(),
            "open_files": 0,
            "connections": 0,
        }

    except Exception as e:
        logger.error("Error collecting system health: %s", e)

    return health_data
