"""
connection.py - Thread-safe SQLite Connection Pool
====================================================

Provides a connection pool for SQLite with WAL mode enabled.
Reduces lock contention by reusing connections rather than
opening/closing on every query.

Usage:
    from database.connection import get_connection, init_pool, shutdown_pool

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ...")
"""

import sqlite3
import logging
import threading
import queue
import os
import sys
from contextlib import contextmanager
from typing import Optional

# Setup path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import (
    DATABASE_PATH,
    DATABASE_TIMEOUT,
    DB_CONNECTION_POOL_SIZE,
    DB_JOURNAL_MODE,
    DB_SYNCHRONOUS,
    DB_CACHE_SIZE,
    DB_TEMP_STORE,
    DB_FOREIGN_KEYS,
    DB_BUSY_TIMEOUT,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_pool: Optional["ConnectionPool"] = None
_pool_lock = threading.Lock()
_pool_permanently_closed = False  # set by shutdown_pool(); prevents re-creation


class ConnectionPool:
    """
    Thread-safe SQLite connection pool.

    * Pre-creates *pool_size* connections.
    * Every connection has WAL mode, synchronous=NORMAL, and other
      performance PRAGMAs applied once on creation.
    * Connections are handed out via a blocking queue and returned
      automatically through the context manager.
    """

    def __init__(self, db_path: str = DATABASE_PATH, pool_size: int = DB_CONNECTION_POOL_SIZE):
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool: queue.Queue[sqlite3.Connection] = queue.Queue(maxsize=pool_size)
        self._all_connections: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._closed = False
        self._borrow_count = 0
        self._wait_count = 0
        self._replace_count = 0

        # Pre-fill the pool
        for _ in range(pool_size):
            conn = self._create_connection()
            self._pool.put(conn)
            self._all_connections.append(conn)

        logger.info(
            "Connection pool initialised – %d connections, WAL=%s, sync=%s",
            pool_size,
            DB_JOURNAL_MODE,
            DB_SYNCHRONOUS,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_connection(self) -> sqlite3.Connection:
        """Create a single connection with all PRAGMAs applied."""
        conn = sqlite3.connect(self.db_path, timeout=DATABASE_TIMEOUT, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        # Performance PRAGMAs (applied once per connection lifetime)
        conn.execute(f"PRAGMA journal_mode={DB_JOURNAL_MODE}")
        conn.execute(f"PRAGMA synchronous={DB_SYNCHRONOUS}")
        conn.execute(f"PRAGMA cache_size={DB_CACHE_SIZE}")
        conn.execute(f"PRAGMA temp_store={DB_TEMP_STORE}")
        conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT}")
        if DB_FOREIGN_KEYS:
            conn.execute("PRAGMA foreign_keys=ON")

        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @contextmanager
    def get_connection(self):
        """
        Borrow a connection from the pool.

        Usage::

            with pool.get_connection() as conn:
                conn.execute(...)
                conn.commit()

        The connection is **returned to the pool** in the finally block –
        it is NOT closed. Validates the connection with ``SELECT 1`` on
        borrow and replaces stale connections transparently.
        """
        if self._closed:
            raise RuntimeError("Connection pool is shut down")

        conn: Optional[sqlite3.Connection] = None
        try:
            conn = self._pool.get(timeout=DATABASE_TIMEOUT)
            self._borrow_count += 1

            # Validate connection — replace if stale
            try:
                conn.execute("SELECT 1")
            except (sqlite3.Error, sqlite3.ProgrammingError):
                logger.debug("Replacing stale connection from pool")
                try:
                    conn.close()
                except Exception:
                    pass
                conn = self._create_connection()
                self._replace_count += 1

            yield conn
        except queue.Empty:
            active = self.pool_size - self._pool.qsize()
            logger.error(
                "Connection pool exhausted! size=%d, active=%d, timeout=%ds. "
                "Likely caused by nested get_connection() calls or long-running queries.",
                self.pool_size, active, DATABASE_TIMEOUT,
            )
            raise RuntimeError(
                f"Connection pool exhausted (size={self.pool_size}, active={active}). "
                "Increase DB_CONNECTION_POOL_SIZE or reduce concurrent access."
            )
        except sqlite3.Error:
            # If an SQLite error occurred the connection may be broken.
            # Replace it with a fresh one and return the *new* connection
            # to the pool (not the broken one).
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                replacement = self._create_connection()
                try:
                    self._pool.put_nowait(replacement)
                except queue.Full:
                    replacement.close()
                conn = None  # Prevent finally from re-queuing the broken conn
            raise
        finally:
            if conn is not None:
                try:
                    self._pool.put_nowait(conn)
                except queue.Full:
                    # Shouldn't happen, but close gracefully
                    conn.close()

    def shutdown(self):
        """Close every connection in the pool."""
        self._closed = True
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except queue.Empty:
                break
        for conn in self._all_connections:
            try:
                conn.close()
            except Exception:
                pass
        self._all_connections.clear()
        logger.info("Connection pool shut down")

    def pool_stats(self) -> dict:
        """Return pool utilization statistics.

        Exposed via ``/api/system/health`` for monitoring.
        """
        available = self._pool.qsize()
        return {
            "total": self.pool_size,
            "available": available,
            "in_use": self.pool_size - available,
            "borrow_count": self._borrow_count,
            "wait_count": self._wait_count,
            "replace_count": self._replace_count,
        }


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def init_pool(db_path: str = DATABASE_PATH, pool_size: int = DB_CONNECTION_POOL_SIZE) -> ConnectionPool:
    """
    Initialise (or re-initialise) the global connection pool.
    Safe to call multiple times; existing pool is shut down first.
    """
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.shutdown()
        _pool = ConnectionPool(db_path=db_path, pool_size=pool_size)
    return _pool


def shutdown_pool():
    """Shut down the global pool (call on application exit)."""
    global _pool, _pool_permanently_closed
    with _pool_lock:
        _pool_permanently_closed = True
        if _pool is not None:
            _pool.shutdown()
            _pool = None


@contextmanager
def get_connection():
    """
    Module-level context manager that lazily creates the pool.

    Drop-in replacement for the old ``db_handler.get_connection()``.
    After ``shutdown_pool()`` has been called, raises ``RuntimeError``
    instead of re-creating the pool (prevents lingering Waitress
    threads from spawning a new pool after shutdown).
    """
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool_permanently_closed:
                raise RuntimeError("Connection pool has been shut down")
            if _pool is None:
                _pool = ConnectionPool()
    with _pool.get_connection() as conn:
        yield conn


def dict_from_row(row: sqlite3.Row) -> Optional[dict]:
    """Convert a ``sqlite3.Row`` to a plain ``dict``."""
    if row is None:
        return None
    return dict(zip(row.keys(), row))


def wal_checkpoint(mode: str = "PASSIVE") -> bool:
    """
    Run a WAL checkpoint to merge the write-ahead log into the main DB.

    Call this periodically after heavy write bursts (batch inserts) to
    keep the WAL file from growing (which degrades read latency).

    *mode* can be ``PASSIVE`` (default – non-blocking), ``FULL``
    (blocks readers briefly), or ``TRUNCATE`` (FULL + truncate WAL).

    Returns True on success.
    """
    valid_modes = ("PASSIVE", "FULL", "TRUNCATE", "RESTART")
    mode = mode.upper()
    if mode not in valid_modes:
        mode = "PASSIVE"
    try:
        with get_connection() as conn:
            conn.execute(f"PRAGMA wal_checkpoint({mode})")
        return True
    except Exception as e:
        logger.debug("WAL checkpoint (%s) failed: %s", mode, e)
        return False


def pool_stats() -> dict:
    """Return pool utilization stats from the global pool.

    Returns empty dict if pool is not initialized.
    """
    if _pool is not None:
        return _pool.pool_stats()
    return {
        "total": 0, "available": 0, "in_use": 0,
        "borrow_count": 0, "wait_count": 0, "replace_count": 0,
    }
