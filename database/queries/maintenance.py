"""
maintenance.py - Data Retention & Database Maintenance (Phase 2+3)
===================================================================

Manages automatic data cleanup, retention policies, and database
health to prevent unbounded growth during 24/7 operation.

Key responsibilities:
* Delete old traffic data (default: 7 days for raw, 90 days for rollups)
* Delete resolved alerts older than retention window
* VACUUM database to reclaim disk space after large deletions
* Schedule daily cleanup at 3 AM
* Report database size and cleanup metrics
* Adaptive retention — halve retention when DB exceeds MAX_DATABASE_SIZE_GB
* WAL checkpoint after cleanup cycles
* Disk space monitoring support

Design principles:
* Never delete un-resolved alerts
* Always log before and after sizes
* Run expensive operations (VACUUM) only after large deletions
* Thread-safe — can be called from any background thread
"""

import os
import shutil
import sqlite3
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from database.connection import get_connection, wal_checkpoint

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
            batches_since_checkpoint = 0
            while True:
                cursor.execute(
                    "DELETE FROM traffic_summary WHERE rowid IN "
                    "(SELECT rowid FROM traffic_summary WHERE timestamp < ? LIMIT ?)",
                    (cutoff, batch_size),
                )
                batch_deleted = cursor.rowcount
                conn.commit()
                total_deleted += batch_deleted
                batches_since_checkpoint += 1
                # Checkpoint WAL every 5 batches (250K rows) to prevent
                # unbounded WAL growth during large cleanup operations
                if batches_since_checkpoint >= 5:
                    try:
                        wal_checkpoint("PASSIVE")
                    except Exception:
                        pass  # non-critical
                    batches_since_checkpoint = 0
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


def auto_resolve_stale_alerts(stale_days: int = 7) -> int:
    """
    Auto-resolve unresolved alerts older than *stale_days*.

    Prevents indefinite accumulation of unresolved alerts during 24/7
    operation.  Tagged with ``resolved_by='auto-stale'`` so operators
    can distinguish auto-resolved from manually resolved alerts.

    Args:
        stale_days: Days after which unresolved alerts are auto-resolved.

    Returns:
        Number of alerts auto-resolved.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=stale_days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            cursor.execute(
                "UPDATE alerts SET resolved = 1, resolved_at = datetime('now'), "
                "resolved_by = 'auto-stale' "
                "WHERE resolved = 0 AND timestamp < ?",
                (cutoff,),
            )
            conn.commit()
            count = cursor.rowcount
            if count:
                logger.info("Auto-resolved %d stale alerts (>%d days)", count, stale_days)
            return count
    except sqlite3.Error as e:
        logger.error("auto_resolve_stale_alerts error: %s", e)
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
    logger.info("Full database cleanup starting...")
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

    # Auto-resolve stale unresolved alerts before deleting old resolved ones
    results["alerts_auto_resolved"] = auto_resolve_stale_alerts(stale_days=7)
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
        "Cleanup complete: deleted %s records, freed %.1f MB (took %.1fs)",
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


# ---------------------------------------------------------------------------
# Phase 3: Adaptive retention & WAL checkpoint
# ---------------------------------------------------------------------------

def get_wal_size_mb(db_path: Optional[str] = None) -> float:
    """Return the WAL file size in megabytes."""
    if db_path is None:
        from config import DATABASE_PATH
        db_path = DATABASE_PATH
    wal_path = db_path + "-wal"
    try:
        return os.path.getsize(wal_path) / (1024 * 1024)
    except OSError:
        return 0.0


def run_wal_checkpoint(mode: str = "PASSIVE") -> bool:
    """Run a WAL checkpoint to prevent unbounded WAL growth.

    Called by the cleanup cycle after batch deletes. Uses PASSIVE mode
    by default (non-blocking). Returns True on success.
    """
    wal_size = get_wal_size_mb()
    # Only checkpoint if WAL is >10 MB or mode is explicit
    if wal_size < 10 and mode == "PASSIVE":
        return True  # nothing to do
    result = wal_checkpoint(mode)
    if result:
        new_wal_size = get_wal_size_mb()
        logger.info(
            "WAL checkpoint (%s): %.1f MB -> %.1f MB",
            mode, wal_size, new_wal_size,
        )
    return result


def adaptive_cleanup() -> Dict:
    """Run cleanup with adaptive retention based on database size.

    When the database exceeds ``MAX_DATABASE_SIZE_GB``, retention
    is progressively shortened to bring it under control.

    Returns a summary dict like ``run_full_cleanup``.
    """
    from config import (
        MAX_DATABASE_SIZE_GB,
        EMERGENCY_RETENTION_HOURS,
        HOURLY_CLEANUP_BATCH_SIZE,
    )

    db_size_mb = get_database_size_mb()
    max_size_mb = MAX_DATABASE_SIZE_GB * 1024

    # Determine adaptive retention
    if db_size_mb > max_size_mb * 1.5:
        # Emergency: DB is 50% over limit — use emergency retention
        traffic_retention_days = max(1, EMERGENCY_RETENTION_HOURS / 24)
        logger.warning(
            "DB size %.1f MB exceeds 150%% of limit (%.0f MB) — "
            "emergency retention: %.1f days",
            db_size_mb, max_size_mb, traffic_retention_days,
        )
    elif db_size_mb > max_size_mb:
        # Over limit — halve normal retention
        traffic_retention_days = 3
        logger.warning(
            "DB size %.1f MB exceeds limit (%.0f MB) — "
            "reduced retention: %d days",
            db_size_mb, max_size_mb, traffic_retention_days,
        )
    else:
        # Normal operation
        traffic_retention_days = 7

    result = run_full_cleanup(
        traffic_retention_days=traffic_retention_days,
        alert_retention_days=30,
        stats_retention_days=30,
        daily_usage_retention_days=90,
        vacuum=(db_size_mb > max_size_mb),
    )

    # Always checkpoint WAL after cleanup
    run_wal_checkpoint("PASSIVE")

    return result


def get_disk_space_info(db_path: Optional[str] = None) -> Dict:
    """Return disk space information for the database partition.

    Returns dict with ``total_gb``, ``free_gb``, ``used_gb``,
    ``free_percent``, and ``status`` (good/warning/critical).
    """
    if db_path is None:
        from config import DATABASE_PATH
        db_path = DATABASE_PATH

    try:
        from config import DISK_SPACE_WARNING_PERCENT, DISK_SPACE_CRITICAL_PERCENT
    except ImportError:
        DISK_SPACE_WARNING_PERCENT = 10
        DISK_SPACE_CRITICAL_PERCENT = 5

    try:
        usage = shutil.disk_usage(os.path.dirname(db_path) or ".")
        total_gb = usage.total / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        used_gb = usage.used / (1024 ** 3)
        free_percent = (usage.free / usage.total * 100) if usage.total else 0

        if free_percent < DISK_SPACE_CRITICAL_PERCENT:
            status = "critical"
        elif free_percent < DISK_SPACE_WARNING_PERCENT:
            status = "warning"
        else:
            status = "good"

        return {
            "total_gb": round(total_gb, 2),
            "free_gb": round(free_gb, 2),
            "used_gb": round(used_gb, 2),
            "free_percent": round(free_percent, 1),
            "status": status,
        }
    except OSError as e:
        logger.error("get_disk_space_info error: %s", e)
        return {
            "total_gb": 0, "free_gb": 0, "used_gb": 0,
            "free_percent": 0, "status": "unknown",
        }


def emergency_cleanup() -> Dict:
    """Run emergency cleanup when disk space is critically low.

    Shortens retention to EMERGENCY_RETENTION_HOURS, deletes
    aggressively in batches, checkpoints WAL, and vacuums.
    """
    from config import EMERGENCY_RETENTION_HOURS

    retention_hours = EMERGENCY_RETENTION_HOURS
    logger.warning(
        "EMERGENCY CLEANUP: disk space critically low — "
        "retention reduced to %d hours", retention_hours,
    )

    result = run_full_cleanup(
        traffic_retention_days=max(1, retention_hours / 24),
        alert_retention_days=7,
        stats_retention_days=7,
        daily_usage_retention_days=30,
        vacuum=True,
    )

    # Force a TRUNCATE checkpoint to reclaim WAL space
    run_wal_checkpoint("TRUNCATE")

    return result
