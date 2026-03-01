"""
orchestration/background_tasks.py - Background Task Management
================================================================

Cleanup scheduler, anomaly detector, health monitor, and thread watchdog.
All tasks run as daemon threads and respect ``state.shutdown_event``.
"""

import logging
import threading
import time
from datetime import datetime, timedelta

from orchestration import state

logger = logging.getLogger(__name__)


# =========================================================================
# Anomaly detector
# =========================================================================

def start_anomaly_detector(alert_engine):
    """Start ML anomaly detector in background thread."""
    from alerts.anomaly_detector import AnomalyDetector

    try:
        state.detector = AnomalyDetector(
            alert_engine=alert_engine,
            shutdown_event=state.shutdown_event,
        )

        state.detector_thread = threading.Thread(
            target=state.detector.run,
            daemon=True,
            name="AnomalyDetector"
        )
        state.detector_thread.start()
        return True
    except Exception as e:
        logger.error("Failed to start anomaly detector: %s", e)
        return False


# =========================================================================
# Health monitor
# =========================================================================

def start_health_monitor(alert_engine):
    """Start system health monitoring in background thread."""
    from utils.health_monitor import HealthMonitor

    try:
        state.health_monitor = HealthMonitor(
            check_interval=60,
            alert_engine=alert_engine,
        )
        state.health_monitor.start()
        return True
    except Exception as e:
        logger.error("Failed to start health monitor: %s", e)
        return False


# =========================================================================
# Cleanup task
# =========================================================================

def start_cleanup_task():
    """Start periodic cleanup task for 24/7 operation.

    Phase 3 enhancements:
    * Uses adaptive_cleanup() which adjusts retention based on DB size
    * WAL checkpoint after each cleanup cycle
    * Stale device pruning from in-memory state every 5 minutes
    """
    from database.rollup import rollup_traffic, cleanup_old_rollups
    from database.queries.maintenance import (
        run_full_cleanup, adaptive_cleanup, run_wal_checkpoint,
    )

    def cleanup_loop():
        from database.queries.maintenance import get_database_size_mb

        last_cleanup = datetime.now()
        last_full_cleanup_date = None
        last_device_prune = time.time()
        last_wal_check = time.time()

        while not state.shutdown_event.is_set():
            try:
                now = datetime.now()
                now_ts = time.time()

                # Every 5 minutes: prune stale devices from memory (Phase 3)
                try:
                    from config import STALE_DEVICE_PRUNE_INTERVAL, STALE_DEVICE_TIMEOUT_HOURS
                except ImportError:
                    STALE_DEVICE_PRUNE_INTERVAL = 300
                    STALE_DEVICE_TIMEOUT_HOURS = 2

                if now_ts - last_device_prune >= STALE_DEVICE_PRUNE_INTERVAL:
                    try:
                        from utils.realtime_state import dashboard_state
                        dashboard_state.prune_stale_devices(
                            stale_hours=STALE_DEVICE_TIMEOUT_HOURS
                        )
                    except Exception as e:
                        logger.error("Stale device prune error: %s", e)
                    last_device_prune = now_ts

                # Every 60 minutes: check WAL size and checkpoint if large
                if now_ts - last_wal_check >= 3600:
                    try:
                        from database.queries.maintenance import get_wal_size_mb
                        wal_mb = get_wal_size_mb()
                        if wal_mb > 100:
                            logger.warning(
                                "WAL file is %.1f MB — running TRUNCATE checkpoint",
                                wal_mb,
                            )
                            run_wal_checkpoint("TRUNCATE")
                        elif wal_mb > 50:
                            run_wal_checkpoint("PASSIVE")
                    except Exception as e:
                        logger.error("WAL size check error: %s", e)
                    last_wal_check = now_ts

                # Every 15 minutes: rollup traffic data + adaptive cleanup
                if now - last_cleanup >= timedelta(minutes=15):
                    try:
                        result = rollup_traffic(raw_retention_hours=24)
                        if result["deleted"] > 0:
                            logger.info("Traffic rollup: %d raw rows archived", result["deleted"])
                    except Exception as e:
                        logger.error("Traffic rollup error: %s", e)

                    try:
                        cleanup_old_rollups(days_to_keep=90)
                    except Exception as e:
                        logger.error("Rollup cleanup error: %s", e)

                    # Phase 3: adaptive cleanup with WAL checkpoint
                    try:
                        result = adaptive_cleanup()
                        total_deleted = sum(v for k, v in result.items() if k.endswith('_deleted'))
                        if total_deleted > 0:
                            logger.info("Periodic cleanup: removed %s records, freed %.1f MB",
                                         f"{total_deleted:,}", result.get('freed_mb', 0))
                    except Exception as e:
                        logger.error("Periodic cleanup error: %s", e)

                    last_cleanup = now

                # Daily at 3 AM: full comprehensive cleanup
                if now.hour >= 3 and last_full_cleanup_date != now.date():
                    logger.info("Daily cleanup starting...")
                    try:
                        result = run_full_cleanup(
                            traffic_retention_days=7,
                            alert_retention_days=30,
                            stats_retention_days=30,
                            daily_usage_retention_days=90,
                        )
                        logger.info(
                            "Daily cleanup complete: deleted %s records, freed %.1f MB",
                            f"{sum(v for k, v in result.items() if k.endswith('_deleted')):,}",
                            result.get('freed_mb', 0),
                        )
                    except Exception as e:
                        logger.error("Daily cleanup error: %s", e)

                    # Always VACUUM daily to reclaim space
                    try:
                        from database.queries.maintenance import vacuum_database
                        vacuum_database()
                    except Exception as e:
                        logger.error("Daily VACUUM error: %s", e)

                    # Phase 3: TRUNCATE checkpoint daily to fully reclaim WAL
                    try:
                        run_wal_checkpoint("TRUNCATE")
                    except Exception as e:
                        logger.error("Daily WAL checkpoint error: %s", e)

                    last_full_cleanup_date = now.date()

                state.shutdown_event.wait(60)  # 60s base interval for responsive scheduling
            except Exception as e:
                logger.error("Cleanup task error: %s", e)
                state.shutdown_event.wait(60)

    state.cleanup_thread = threading.Thread(
        target=cleanup_loop,
        daemon=True,
        name="CleanupTask"
    )
    state.cleanup_thread.start()
    return True


# =========================================================================
# Thread watchdog
# =========================================================================

_WATCHED_THREAD_PATTERNS = {
    # Capture engine threads (Scapy capture + processor)
    "CaptureEngine": ("CaptureEngine-Capture", "CaptureEngine-Process"),
    # Background hostname resolver + mDNS browser
    "HostnameResolver": ("HostnameResolver-BG", "mDNS-Browse"),
    # Periodic tasks
    "DiscoveryTask": ("DiscoveryTask",),
    "CleanupTask": ("CleanupTask",),
    "AnomalyDetector": ("AnomalyDetector",),
    "HealthMonitor": ("HealthMonitor",),
}


def _thread_watchdog():
    """Periodically check that critical daemon threads are alive.

    Runs every 30s.  If a watched thread has disappeared, logs a
    warning so operators can detect silent crashes.  For safe-to-restart
    threads (CleanupTask), attempts auto-restart with cooldown.
    """
    # Restart tracking: label -> (restart_count, window_start_time)
    _restart_tracker: dict = {}
    _MAX_RESTARTS_PER_HOUR = 3

    # Restart handlers for threads that are safe to auto-restart.
    # CaptureEngine is excluded because it requires mode context.
    _restart_handlers = {
        "CleanupTask": start_cleanup_task,
    }

    start = time.time()
    while not state.shutdown_event.is_set():
        # Give threads a short grace period to start before warning
        if time.time() - start < 30:
            state.shutdown_event.wait(5)
            continue
        alive_names = {t.name for t in threading.enumerate() if t.is_alive()}
        for label, patterns in _WATCHED_THREAD_PATTERNS.items():
            present = any(
                any(name.startswith(pat) for pat in patterns)
                for name in alive_names
            )
            if not present:
                logger.warning(
                    "Thread watchdog: '%s' is not alive -- it may have crashed silently",
                    label,
                )
                # Attempt auto-restart for safe threads
                if label in _restart_handlers:
                    now_ts = time.time()
                    count, window_start = _restart_tracker.get(label, (0, now_ts))
                    # Reset counter if window expired
                    if now_ts - window_start > 3600:
                        count, window_start = 0, now_ts
                    if count < _MAX_RESTARTS_PER_HOUR:
                        logger.warning("Thread watchdog: attempting auto-restart of '%s'", label)
                        try:
                            _restart_handlers[label]()
                            _restart_tracker[label] = (count + 1, window_start)
                            logger.info("Thread watchdog: '%s' restarted successfully", label)
                        except Exception as e:
                            logger.error("Thread watchdog: failed to restart '%s': %s", label, e)
                    else:
                        logger.error(
                            "Thread watchdog: '%s' exceeded max restarts (%d/hr) -- not restarting",
                            label, _MAX_RESTARTS_PER_HOUR,
                        )
        state.shutdown_event.wait(30)


def start_thread_watchdog():
    """Start the thread watchdog in a daemon thread."""
    t = threading.Thread(target=_thread_watchdog, daemon=True, name="ThreadWatchdog")
    t.start()
    return True
