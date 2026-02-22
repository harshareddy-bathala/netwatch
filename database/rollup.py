"""
rollup.py - Traffic Data Rollup & Archival
=============================================

Aggregates raw ``traffic_summary`` rows into hourly buckets in the
``traffic_rollup`` table, then deletes raw rows older than *raw_retention_hours*.

This keeps the hot ``traffic_summary`` table small (last 24 h) while
preserving historical data in a compact format for long-term charts.

Designed to run periodically (e.g. every 15 minutes, Phase 4) from a background thread.
"""

import sqlite3
import logging
from datetime import datetime, timedelta

from database.connection import get_connection

logger = logging.getLogger(__name__)


def ensure_rollup_table() -> None:
    """Create the ``traffic_rollup`` table if it doesn't exist yet."""
    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_rollup (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hour_bucket TEXT NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    protocol TEXT,
                    direction TEXT DEFAULT 'unknown',
                    total_bytes INTEGER DEFAULT 0,
                    packet_count INTEGER DEFAULT 0,
                    UNIQUE(hour_bucket, source_ip, dest_ip, protocol, direction)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rollup_hour ON traffic_rollup(hour_bucket)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rollup_protocol ON traffic_rollup(protocol)")
            conn.commit()
    except sqlite3.Error as e:
        logger.error("ensure_rollup_table error: %s", e)


def rollup_traffic(raw_retention_hours: int = 24) -> dict:
    """
    1. Aggregate ``traffic_summary`` rows older than *raw_retention_hours* into
       hourly buckets in ``traffic_rollup``.
    2. Delete the aggregated raw rows.

    Returns:
        dict with ``rolled_up`` (rows inserted/updated) and ``deleted`` (raw rows removed).
    """
    ensure_rollup_table()

    cutoff = (datetime.now() - timedelta(hours=raw_retention_hours)).strftime("%Y-%m-%d %H:%M:%S")
    rolled_up = 0
    deleted = 0

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Step 1: Aggregate old raw rows into hourly buckets
            cursor.execute("""
                INSERT INTO traffic_rollup
                    (hour_bucket, source_ip, dest_ip, protocol, direction,
                     total_bytes, packet_count)
                SELECT
                    strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
                    source_ip,
                    dest_ip,
                    protocol,
                    COALESCE(direction, 'unknown'),
                    SUM(bytes_transferred),
                    COUNT(*)
                FROM traffic_summary t
                WHERE timestamp < ?
                GROUP BY hour_bucket, source_ip, dest_ip, protocol, direction
                ON CONFLICT(hour_bucket, source_ip, dest_ip, protocol, direction)
                DO UPDATE SET
                    total_bytes = traffic_rollup.total_bytes + excluded.total_bytes,
                    packet_count = traffic_rollup.packet_count + excluded.packet_count
            """, (cutoff,))
            rolled_up = cursor.rowcount

            # Step 2: Delete the old raw rows
            cursor.execute("DELETE FROM traffic_summary WHERE timestamp < ?", (cutoff,))
            deleted = cursor.rowcount

            conn.commit()

            logger.info(
                "Traffic rollup complete: %d buckets upserted, %d raw rows deleted (cutoff: %s)",
                rolled_up, deleted, cutoff,
            )

    except sqlite3.Error as e:
        logger.error("rollup_traffic error: %s", e)

    return {"rolled_up": rolled_up, "deleted": deleted}


def cleanup_old_rollups(days_to_keep: int = 90) -> int:
    """Delete rollup rows older than *days_to_keep* days.

    Disk space reclamation (VACUUM) is NOT done here — it should be
    scheduled as a separate maintenance operation to avoid blocking
    concurrent readers/writers.
    """
    cutoff = (datetime.now() - timedelta(days=days_to_keep)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM traffic_rollup WHERE hour_bucket < ?", (cutoff,))
            conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("Cleaned up %d old rollup rows (>%d days)", deleted, days_to_keep)
            return deleted
    except sqlite3.Error as e:
        logger.error("cleanup_old_rollups error: %s", e)
        return 0

