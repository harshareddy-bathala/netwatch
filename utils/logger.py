"""
logger.py - Production Logging Configuration
===============================================

Provides structured JSON logging with rotation for production use.

Features:
* JSON-formatted file logs for machine parsing
* Human-readable console output for development
* Separate error log file for quick issue triage
* Rotating file handlers to cap disk usage
* Request-ID context filter for tracing API calls

Usage::

    from utils.logger import setup_logging

    setup_logging(log_dir='logs', log_level='INFO')

    import logging
    logger = logging.getLogger(__name__)
    logger.info("Application started")
"""

import logging
import logging.handlers
import json
import time
import contextvars
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Context variable for request-level tracing
# ---------------------------------------------------------------------------

request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "request_id", default=None
)


def get_request_id() -> Optional[str]:
    """Return the current request ID (set by Flask middleware)."""
    return request_id_var.get()


def set_request_id(rid: Optional[str] = None) -> str:
    """Set (or generate) a request ID for the current context."""
    rid = rid or uuid.uuid4().hex[:8]
    request_id_var.set(rid)
    return rid


# ---------------------------------------------------------------------------
# JSON Formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Emit each log record as a single JSON line.

    Includes timestamp, level, logger name, message, module/function/line,
    request_id (if set), and exception info when present.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Attach request ID if available
        rid = request_id_var.get()
        if rid:
            log_data["request_id"] = rid

        # Attach extra fields passed via ``extra={}``
        for key in ("duration_ms", "threshold_ms", "function_name",
                     "cpu_percent", "memory_mb", "threads",
                     "open_files", "connections", "endpoint",
                     "status_code", "method"):
            val = getattr(record, key, None)
            if val is not None:
                log_data[key] = val

        # Exception info
        if record.exc_info and record.exc_info[1] is not None:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


# ---------------------------------------------------------------------------
# Request-ID log filter
# ---------------------------------------------------------------------------

class RequestIDFilter(logging.Filter):
    """Inject request_id into every LogRecord so formatters can use ``%(request_id)s``."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get() or "N/A"  # type: ignore[attr-defined]
        return True


# ---------------------------------------------------------------------------
# Console formatter (human-readable, with request ID)
# ---------------------------------------------------------------------------

CONSOLE_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] %(message)s"
CONSOLE_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S+00:00"  # UTC format matching JSON handler


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logging(
    log_dir: str = "logs",
    log_level: str = "INFO",
    enable_console: bool = True,
    enable_json_file: bool = True,
    enable_error_file: bool = True,
    max_bytes: int = 50 * 1024 * 1024,  # 50 MB
    backup_count: int = 5,
    error_max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    error_backup_count: int = 3,
) -> logging.Logger:
    """
    Configure production logging for the entire application.

    Args:
        log_dir: Directory for log files (created if missing).
        log_level: Root log level (DEBUG / INFO / WARNING / ERROR / CRITICAL).
        enable_console: Attach a human-readable StreamHandler.
        enable_json_file: Attach a rotating JSON file handler.
        enable_error_file: Attach a rotating error-only file handler.
        max_bytes: Max size per log file before rotation.
        backup_count: Number of rotated log files to keep.
        error_max_bytes: Max size per error log file.
        error_backup_count: Number of rotated error log files.

    Returns:
        The root logger.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    # Clear any existing handlers to prevent duplicates on re-init
    root_logger.handlers.clear()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Global request-ID filter
    rid_filter = RequestIDFilter()

    # 1. Console handler (human-readable)
    if enable_console:
        import sys
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.addFilter(rid_filter)
        console_fmt = logging.Formatter(CONSOLE_FORMAT, datefmt=CONSOLE_DATE_FORMAT)
        console_fmt.converter = time.gmtime  # Use UTC, consistent with JSON handler
        console_handler.setFormatter(console_fmt)
        root_logger.addHandler(console_handler)

    # 2. JSON rotating file handler (all levels)
    if enable_json_file:
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_path / "netwatch.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.addFilter(rid_filter)
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # 3. Error-only rotating file handler (ERROR and above)
    if enable_error_file:
        error_handler = logging.handlers.RotatingFileHandler(
            str(log_path / "netwatch_errors.log"),
            maxBytes=error_max_bytes,
            backupCount=error_backup_count,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.addFilter(rid_filter)
        error_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(error_handler)

    # Suppress noisy third-party loggers
    for noisy in ("werkzeug", "urllib3", "scapy", "matplotlib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    root_logger.info(
        "Logging configured: level=%s, dir=%s, json=%s, errors=%s",
        log_level, log_dir, enable_json_file, enable_error_file,
    )
    return root_logger
