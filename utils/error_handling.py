"""
error_handling.py - Consistent Error Handling for Packet Capture
=================================================================

Provides decorators and utilities for consistent error handling across
the packet_capture module, replacing the mixed patterns
(bare except, silent swallows, inconsistent logging).

Usage::

    from utils.error_handling import handle_capture_error, handle_parse_error

    @handle_capture_error
    def start_capture():
        ...

    @handle_parse_error
    def parse_packet(pkt):
        ...
"""

import logging
from functools import wraps
from typing import Any, Optional

logger = logging.getLogger(__name__)


def handle_capture_error(func):
    """
    Decorator for capture-related functions.

    Handles:
    * ``PermissionError`` — logs and re-raises (admin required)
    * ``OSError``          — logs and returns None (interface issues)
    * ``Exception``        — logs with traceback and re-raises
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionError:
            logger.error(
                "%s: Requires admin/root privileges for packet capture",
                func.__name__,
            )
            raise
        except OSError as e:
            logger.error("%s: OS error — %s", func.__name__, e)
            return None
        except Exception as e:
            logger.error(
                "%s: Unexpected error", func.__name__, exc_info=True
            )
            raise
    return wrapper


def handle_parse_error(default=None):
    """
    Decorator for packet parsing functions.

    On any exception, logs a debug message and returns ``default``.
    This prevents one malformed packet from crashing the entire pipeline.

    Usage::

        @handle_parse_error(default={})
        def extract_ip_info(pkt):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.debug(
                    "%s: Parse error — %s", func.__name__, e
                )
                return default
        return wrapper
    return decorator


def handle_network_error(func):
    """
    Decorator for network I/O functions (DNS lookups, vendor resolution, etc.).

    On timeout or network errors, returns None without crashing.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except TimeoutError:
            logger.debug("%s: Timed out", func.__name__)
            return None
        except OSError as e:
            logger.debug("%s: Network error — %s", func.__name__, e)
            return None
        except Exception as e:
            logger.debug("%s: Error — %s", func.__name__, e)
            return None
    return wrapper


def safe_import(module_name: str, fallback: Any = None) -> Any:
    """
    Safely import a module, returning ``fallback`` if unavailable.

    Usage::

        scapy = safe_import('scapy.all')
        if scapy:
            scapy.sniff(...)
    """
    try:
        import importlib
        return importlib.import_module(module_name)
    except ImportError:
        logger.debug("Optional module '%s' not available", module_name)
        return fallback
