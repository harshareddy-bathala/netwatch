"""
migrate_add_direction.py - Database Migration: Add direction column
====================================================================

Phase 2 migration: ensures the ``traffic_summary`` table has a ``direction``
column and adds a ``bandwidth_realtime`` table for per-second bandwidth
records.

Safe to run multiple times (idempotent).

Usage::

    python -m database.migrate_add_direction
"""

import logging
import os
import sys

# Ensure project root is on path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def migrate():
    """Run all Phase 2 migrations."""
    _add_direction_column()
    _create_bandwidth_realtime_table()
    _add_direction_index()
    _update_schema_version()
    logger.info("Phase 2 migration complete")


def _add_direction_column():
    """Add ``direction`` column to ``traffic_summary`` if missing."""
    with get_connection() as conn:
        cursor = conn.cursor()
        # Check if column already exists
        cursor.execute("PRAGMA table_info(traffic_summary)")
        columns = {row["name"] for row in cursor.fetchall()}
        if "direction" not in columns:
            cursor.execute(
                "ALTER TABLE traffic_summary ADD COLUMN direction TEXT DEFAULT 'unknown'"
            )
            conn.commit()
            logger.info("Added 'direction' column to traffic_summary")
        else:
            logger.info("'direction' column already exists — skipping")


def _create_bandwidth_realtime_table():
    """Create ``bandwidth_realtime`` table for per-second bandwidth records."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bandwidth_realtime (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                bytes_upload INTEGER DEFAULT 0,
                bytes_download INTEGER DEFAULT 0,
                bytes_other INTEGER DEFAULT 0,
                packets_upload INTEGER DEFAULT 0,
                packets_download INTEGER DEFAULT 0,
                packets_other INTEGER DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bw_realtime_ts
            ON bandwidth_realtime(timestamp)
        """)
        conn.commit()
        logger.info("Ensured bandwidth_realtime table exists")


def _add_direction_index():
    """Add a composite index on (timestamp, direction) for efficient queries."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_traffic_ts_direction
            ON traffic_summary(timestamp, direction)
        """)
        conn.commit()
        logger.info("Ensured index idx_traffic_ts_direction exists")


def _update_schema_version():
    """Bump schema version to 2.0.0."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO system_config (key, value, updated_at)
            VALUES ('schema_version', '2.0.0', datetime('now'))
        """)
        conn.commit()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    migrate()
