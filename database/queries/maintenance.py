"""
maintenance.py - Data Retention & Database Maintenance (Phase 2)
=================================================================

Manages automatic data cleanup, retention policies, and database
health to prevent unbounded growth during 24/7 operation.

Key responsibilities:
* Delete old traffic data (default: 7 days for raw, 90 days for rollups)
* Delete resolved alerts older than retention window
* VACUUM database to reclaim disk space after large deletions
* Schedule daily cleanup at 3 AM
* Report database size and cleanup metrics

Design principles:
* Never delete un-resolved alerts
* Always log before and after sizes
* Run expensive operations (VACUUM) only after large deletions
* Thread-safe — can be called from any background thread
"""

import os
import sqlite3
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from database.connection import get_connection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core cleanup functions
# ---------------------------------------------------------------------------

def cleanup_old_traffic(retention_days: int = 7) -> Dict[str, int]:
    """
    Delete old packet data from ``traffic_summary`` to prevent database bloat.

    Why needed?
    - 2 devices × 100 packets/sec ≈ 17.3 million packets/day
    - After 7 days ≈ 121 million records
    - Database size ≈ 5–10 GB
    - Queries slow down significantly

    Solution:
    - Keep recent *retention_days* of detailed packets
    - Delete older packets
    - Return metrics

    Args:
        retention_days: Number of days of traffic data to keep (default 7).

    Returns:
        Dict with ``deleted`` count and ``freed_mb``.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cutoff = (datetime.now() - timedelta(days=retention_days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # Count packets to be deleted
            cursor.execute(
                "SELECT COUNT(*) AS cnt FROM traffic_summary WHERE timestamp < ?",
                (cutoff,),
            )
            row = cursor.fetchone()
            count = (row["cnt"] or 0) if row else 0

            if count == 0:
                logger.info("No old traffic data to clean up (retention: %d days)", retention_days)
                return {"deleted": 0, "freed_mb": 0.0}

            logger.info(
                "Deleting %s old packet records (older than %d days)",
                f"{count:,}", retention_days,
            )

            # Delete in batches to avoid long locks
            total_deleted = 0
            batch_size = 50_000
            while True:
                cursor.execute(
                    "DELETE FROM traffic_summary WHERE rowid IN "
                    "(SELECT rowid FROM traffic_summary WHERE timestamp < ? LIMIT ?)",
                    (cutoff, batch_size),
                )
                batch_deleted = cursor.rowcount
                conn.commit()
                total_deleted += batch_deleted
                if batch_deleted < batch_size:
                    break

            logger.info("Deleted %s traffic records", f"{total_deleted:,}")
            return {"deleted": total_deleted, "freed_mb": 0.0}

    except sqlite3.Error as e:
        logger.error("cleanup_old_traffic error: %s", e)
        return {"deleted": 0, "freed_mb": 0.0, "error": str(e)}


def cleanup_old_alerts(retention_days: int = 30) -> int:
    """
    Delete **resolved** alerts older than *retention_days*.

    Un-resolved alerts are NEVER deleted — only resolved ones are cleaned up.

    Args:
        retention_days: Days to keep resolved alerts (default 30).

    Returns:
        Number of alerts deleted.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=retention_days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            cursor.execute(
                "DELETE FROM alerts WHERE resolved = 1 AND timestamp < ?",
                (cutoff,),
            )
            conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("Deleted %d old resolved alerts (>%d days)", deleted, retention_days)
            return deleted
    except sqlite3.Error as e:
        logger.error("cleanup_old_alerts error: %s", e)
        return 0


def cleanup_old_bandwidth_stats(retention_days: int = 30) -> int:
    """Delete old bandwidth_stats records."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=retention_days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            cursor.execute(
                "DELETE FROM bandwidth_stats WHERE timestamp < ?", (cutoff,)
            )
            conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("Deleted %d old bandwidth_stats records", deleted)
            return deleted
    except sqlite3.Error as e:
        logger.error("cleanup_old_bandwidth_stats error: %s", e)
        return 0


def cleanup_old_protocol_stats(retention_days: int = 30) -> int:
    """Delete old protocol_stats records."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=retention_days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            cursor.execute(
                "DELETE FROM protocol_stats WHERE timestamp < ?", (cutoff,)
            )
            conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("Deleted %d old protocol_stats records", deleted)
            return deleted
    except sqlite3.Error as e:
        logger.error("cleanup_old_protocol_stats error: %s", e)
        return 0


def cleanup_old_daily_usage(retention_days: int = 90) -> int:
    """Delete old daily_usage records."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=retention_days)).strftime("%Y-%m-%d")
            cursor.execute("DELETE FROM daily_usage WHERE date < ?", (cutoff,))
            conn.commit()
            deleted = cursor.rowcount
            if deleted:
                logger.info("Deleted %d old daily_usage records", deleted)
            return deleted
    except sqlite3.Error as e:
        logger.error("cleanup_old_daily_usage error: %s", e)
        return 0


# ---------------------------------------------------------------------------
# Database health
# ---------------------------------------------------------------------------

def get_database_size_mb(db_path: Optional[str] = None) -> float:
    """Return the database file size in megabytes."""
    if db_path is None:
        from config import DATABASE_PATH
        db_path = DATABASE_PATH
    try:
        return os.path.getsize(db_path) / (1024 * 1024)
    except OSError:
        return 0.0


def get_table_row_counts() -> Dict[str, int]:
    """Return row counts for all major tables in a single query pass."""
    counts = {}
    tables = [
        "traffic_summary", "devices", "alerts", "bandwidth_stats",
        "protocol_stats", "daily_usage", "traffic_rollup",
    ]
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # Use UNION ALL to get all counts in one round-trip
            parts = []
            for table in tables:
                parts.append(
                    f"SELECT '{table}' AS tbl, COUNT(*) AS cnt FROM {table}"
                )
            query = " UNION ALL ".join(parts)
            try:
                cursor.execute(query)
                for row in cursor.fetchall():
                    counts[row["tbl"]] = row["cnt"] or 0
            except sqlite3.OperationalError:
                # Fallback: some tables might not exist yet
                for table in tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) AS cnt FROM {table}")
                        row = cursor.fetchone()
                        counts[table] = (row["cnt"] or 0) if row else 0
                    except sqlite3.OperationalError:
                        counts[table] = -1
    except sqlite3.Error as e:
        logger.error("get_table_row_counts error: %s", e)
    return counts


def vacuum_database() -> bool:
    """
    Run VACUUM to reclaim disk space.

    Note: VACUUM requires exclusive access and can take a while for large
    databases. Only call after significant deletions.
    """
    try:
        with get_connection() as conn:
            db_size_before = get_database_size_mb()
            conn.execute("ANALYZE")
            conn.execute("VACUUM")
            db_size_after = get_database_size_mb()
            freed = db_size_before - db_size_after
            logger.info(
                "VACUUM complete: %.1f MB → %.1f MB (freed %.1f MB)",
                db_size_before, db_size_after, freed,
            )
            return True
    except sqlite3.Error as e:
        logger.error("vacuum_database error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Comprehensive cleanup
# ---------------------------------------------------------------------------

def run_full_cleanup(
    traffic_retention_days: int = 7,
    alert_retention_days: int = 30,
    stats_retention_days: int = 30,
    daily_usage_retention_days: int = 90,
    vacuum: bool = True,
) -> Dict:
    """
    Run all cleanup tasks. This is the main entry point for scheduled cleanup.

    Args:
        traffic_retention_days: Days to keep raw traffic data.
        alert_retention_days: Days to keep resolved alerts.
        stats_retention_days: Days to keep aggregated stats.
        daily_usage_retention_days: Days to keep daily usage records.
        vacuum: Whether to run VACUUM after deletions.

    Returns:
        Summary dict with counts of deleted records.
    """
    logger.info("🧹 Full database cleanup starting...")
    start_time = time.time()

    db_size_before = get_database_size_mb()

    results = {
        "traffic_deleted": 0,
        "alerts_deleted": 0,
        "bandwidth_stats_deleted": 0,
        "protocol_stats_deleted": 0,
        "daily_usage_deleted": 0,
        "db_size_before_mb": round(db_size_before, 1),
        "db_size_after_mb": 0.0,
        "freed_mb": 0.0,
        "duration_seconds": 0.0,
    }

    # Run all cleanup tasks
    traffic_result = cleanup_old_traffic(traffic_retention_days)
    results["traffic_deleted"] = traffic_result.get("deleted", 0)

    results["alerts_deleted"] = cleanup_old_alerts(alert_retention_days)
    results["bandwidth_stats_deleted"] = cleanup_old_bandwidth_stats(stats_retention_days)
    results["protocol_stats_deleted"] = cleanup_old_protocol_stats(stats_retention_days)
    results["daily_usage_deleted"] = cleanup_old_daily_usage(daily_usage_retention_days)

    total_deleted = sum([
        results["traffic_deleted"],
        results["alerts_deleted"],
        results["bandwidth_stats_deleted"],
        results["protocol_stats_deleted"],
        results["daily_usage_deleted"],
    ])

    # Only VACUUM if significant data was deleted
    if vacuum and total_deleted > 10_000:
        vacuum_database()

    db_size_after = get_database_size_mb()
    results["db_size_after_mb"] = round(db_size_after, 1)
    results["freed_mb"] = round(db_size_before - db_size_after, 1)
    results["duration_seconds"] = round(time.time() - start_time, 2)

    # Update system_config with last cleanup timestamp
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_config (key, value, updated_at) "
                "VALUES ('last_cleanup', ?, datetime('now'))",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),),
            )
            conn.commit()
    except sqlite3.Error:
        pass

    logger.info(
        "✅ Cleanup complete: deleted %s records, freed %.1f MB (took %.1fs)",
        f"{total_deleted:,}", results["freed_mb"], results["duration_seconds"],
    )

    return results


# ---------------------------------------------------------------------------
# Scheduled cleanup (background thread)
# ---------------------------------------------------------------------------

_cleanup_thread: Optional[threading.Thread] = None
_cleanup_stop = threading.Event()


def schedule_daily_cleanup(
    run_at_hour: int = 3,
    traffic_retention_days: int = 7,
    check_interval: int = 3600,
) -> threading.Thread:
    """
    Schedule cleanup to run daily at *run_at_hour* (default 3 AM).

    Uses a simple polling loop with hourly checks. The thread is a daemon
    so it will be killed when the main process exits.

    Args:
        run_at_hour: Hour of day (0–23) to run cleanup (default 3).
        traffic_retention_days: Days to keep raw traffic data.
        check_interval: Seconds between checks (default 3600 = 1 hour).

    Returns:
        The background thread.
    """
    global _cleanup_thread

    def _cleanup_loop():
        last_cleanup_date = None

        while not _cleanup_stop.is_set():
            try:
                now = datetime.now()
                today = now.date()

                # Run cleanup if:
                #   1. It's past the scheduled hour
                #   2. We haven't already cleaned up today
                if now.hour >= run_at_hour and last_cleanup_date != today:
                    run_full_cleanup(traffic_retention_days=traffic_retention_days)
                    last_cleanup_date = today

            except Exception as e:
                logger.error("Scheduled cleanup error: %s", e)

            _cleanup_stop.wait(check_interval)

    _cleanup_thread = threading.Thread(
        target=_cleanup_loop,
        daemon=True,
        name="MaintenanceCleanup",
    )
    _cleanup_thread.start()
    logger.info(
        "Daily cleanup scheduled for %02d:00 (traffic retention: %d days)",
        run_at_hour, traffic_retention_days,
    )
    return _cleanup_thread


def stop_scheduled_cleanup():
    """Stop the scheduled cleanup thread."""
    _cleanup_stop.set()
    if _cleanup_thread and _cleanup_thread.is_alive():
        _cleanup_thread.join(timeout=5)
    logger.info("Scheduled cleanup stopped")


# ---------------------------------------------------------------------------
# Maintenance report
# ---------------------------------------------------------------------------

def get_maintenance_report() -> Dict:
    """
    Generate a maintenance report with database health metrics.

    Returns:
        Dict with DB size, row counts, last cleanup time, etc.
    """
    report = {
        "database_size_mb": round(get_database_size_mb(), 1),
        "table_row_counts": get_table_row_counts(),
        "timestamp": datetime.now().isoformat(),
    }

    # Get last cleanup time
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM system_config WHERE key = 'last_cleanup'"
            )
            row = cursor.fetchone()
            report["last_cleanup"] = row["value"] if row else "Never"
    except sqlite3.Error:
        report["last_cleanup"] = "Unknown"

    return report
