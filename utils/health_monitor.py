"""
health_monitor.py - System Health Monitoring (Phase 2+3)
=========================================================

Monitors system-level health metrics for 24/7 production operation:
* CPU usage
* Memory usage
* Database size and growth rate
* Disk space monitoring with auto-response
* Connection pool utilization
* Packet capture status
* ML model status
* Thread health

Designed to run periodically and expose metrics via the ``/api/system/health``
endpoint. Alerts are raised through ``AlertEngine`` when thresholds are breached.
"""

import os
import sys
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cached CPU usage — sampled by a background thread so callers never block
# ---------------------------------------------------------------------------

_cached_cpu: float = 0.0
_cpu_lock = threading.Lock()
_cpu_thread_started = False


def _cpu_sampler_loop():
    """Background thread that samples CPU usage every 2 seconds.

    Uses ``psutil.cpu_percent(percpu=False)`` which returns system-wide
    CPU usage normalised to 0–100 regardless of core count.  The previous
    ``process.cpu_percent()`` call could report >100% on multi-core
    systems (e.g. 196.9% on a dual-core).
    """
    global _cached_cpu
    try:
        import psutil
        # Prime the baseline measurement (required by psutil)
        psutil.cpu_percent(percpu=False)
    except Exception:
        return

    while True:
        try:
            usage = psutil.cpu_percent(interval=2.0, percpu=False)
            with _cpu_lock:
                _cached_cpu = min(usage, 100.0)
        except Exception:
            break


def _ensure_cpu_sampler():
    """Start the CPU sampler thread once (thread-safe)."""
    global _cpu_thread_started
    if _cpu_thread_started:
        return
    with _cpu_lock:
        if _cpu_thread_started:  # double-check under lock
            return
        _cpu_thread_started = True
    t = threading.Thread(target=_cpu_sampler_loop, daemon=True, name="CPUSampler")
    t.start()


# ---------------------------------------------------------------------------
# System metrics collection
# ---------------------------------------------------------------------------

def get_cpu_usage() -> float:
    """
    Return current process CPU usage as a percentage (0–100).

    Returns a cached value updated by a background thread every 2 s,
    so this call **never blocks** the caller.
    """
    try:
        import psutil  # noqa: F401 — just check availability
        _ensure_cpu_sampler()
        with _cpu_lock:
            return _cached_cpu
    except ImportError:
        # Fallback: parse /proc/stat on Linux or return 0 on other platforms
        return _fallback_cpu_usage()
    except Exception as e:
        logger.debug("CPU usage check failed: %s", e)
        return 0.0


def get_memory_usage() -> Dict[str, float]:
    """
    Return current process memory usage.

    Returns:
        Dict with ``rss_mb`` (resident set), ``vms_mb`` (virtual),
        and ``percent`` (of total system RAM).
    """
    try:
        import psutil
        process = psutil.Process(os.getpid())
        mem = process.memory_info()
        return {
            "rss_mb": round(mem.rss / (1024 * 1024), 1),
            "vms_mb": round(mem.vms / (1024 * 1024), 1),
            "percent": round(process.memory_percent(), 1),
        }
    except ImportError:
        return _fallback_memory_usage()
    except Exception as e:
        logger.debug("Memory usage check failed: %s", e)
        return {"rss_mb": 0, "vms_mb": 0, "percent": 0}


def get_thread_count() -> int:
    """Return the number of active threads."""
    return threading.active_count()


def get_thread_names() -> List[str]:
    """Return names of all active threads."""
    return [t.name for t in threading.enumerate()]


def _fallback_cpu_usage() -> float:
    """Rough CPU usage estimate without psutil (capped to 0–100)."""
    try:
        if sys.platform == "win32":
            # Windows: use WMI or return 0
            return 0.0
        else:
            # Linux/Mac: parse /proc/stat for system-wide usage
            # Use two samples 0.5s apart for a delta-based measurement
            import time as _time

            def _read_stat():
                with open("/proc/stat", "r") as f:
                    line = f.readline()  # first line: "cpu ..."
                    parts = line.split()
                    idle = int(parts[4])
                    total = sum(int(x) for x in parts[1:])
                    return idle, total

            idle1, total1 = _read_stat()
            _time.sleep(0.5)
            idle2, total2 = _read_stat()
            d_idle = idle2 - idle1
            d_total = total2 - total1
            if d_total == 0:
                return 0.0
            usage = ((d_total - d_idle) / d_total) * 100.0
            return min(max(usage, 0.0), 100.0)
    except Exception:
        return 0.0


def _fallback_memory_usage() -> Dict[str, float]:
    """Rough memory usage estimate without psutil."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(pmc), pmc.cb
            ):
                rss_mb = pmc.WorkingSetSize / (1024 * 1024)
                return {"rss_mb": round(rss_mb, 1), "vms_mb": 0, "percent": 0}
        else:
            # Linux: parse /proc/self/status
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        return {
                            "rss_mb": round(rss_kb / 1024, 1),
                            "vms_mb": 0,
                            "percent": 0,
                        }
    except Exception:
        pass
    return {"rss_mb": 0, "vms_mb": 0, "percent": 0}


# ---------------------------------------------------------------------------
# Health Monitor class
# ---------------------------------------------------------------------------

class HealthMonitor:
    """
    Collects and exposes system health metrics.

    Usage::

        monitor = HealthMonitor()
        monitor.start()

        # Get current snapshot
        metrics = monitor.get_metrics()

        # Stop monitoring
        monitor.stop()
    """

    # Thresholds for alerting
    # CPU thresholds are set higher because packet capture and ML
    # detection legitimately use CPU.  50% triggered false warnings
    # during normal browsing with only 2 devices.
    CPU_WARNING = 75.0        # %
    CPU_CRITICAL = 90.0       # %
    MEMORY_WARNING = 500.0    # MB RSS
    MEMORY_CRITICAL = 800.0   # MB RSS
    DB_SIZE_WARNING = 2000.0  # MB
    DB_SIZE_CRITICAL = 5000.0 # MB

    def __init__(
        self,
        check_interval: int = 60,
        alert_engine=None,
    ):
        """
        Args:
            check_interval: Seconds between health checks (default 60).
            alert_engine: Optional AlertEngine for threshold alerts.
        """
        self.check_interval = check_interval
        self.alert_engine = alert_engine
        self._running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time = datetime.now()

        # Latest metrics snapshot
        self._metrics: Dict = {}
        self._metrics_lock = threading.Lock()

        # History for trend analysis (last 60 readings = 1 hour at 60s interval)
        self._history: List[Dict] = []
        self._max_history = 60

        logger.info("HealthMonitor initialised (interval=%ds)", check_interval)

    def start(self) -> None:
        """Start the background health monitoring thread."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="HealthMonitor",
        )
        self._thread.start()
        logger.info("HealthMonitor started")

    def stop(self) -> None:
        """Stop the health monitoring thread."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("HealthMonitor stopped")

    def get_metrics(self) -> Dict:
        """Return the latest health metrics snapshot."""
        with self._metrics_lock:
            return dict(self._metrics) if self._metrics else self._collect_metrics()

    def get_history(self) -> List[Dict]:
        """Return recent metrics history for trend analysis."""
        with self._metrics_lock:
            return list(self._history)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Background loop that collects metrics periodically."""
        while self._running and not self._stop_event.is_set():
            try:
                metrics = self._collect_metrics()

                with self._metrics_lock:
                    self._metrics = metrics
                    self._history.append({
                        "timestamp": metrics["timestamp"],
                        "cpu_percent": metrics.get("cpu_percent", 0),
                        "memory_rss_mb": metrics.get("memory", {}).get("rss_mb", 0),
                        "db_size_mb": metrics.get("database", {}).get("size_mb", 0),
                    })
                    # Trim history
                    if len(self._history) > self._max_history:
                        self._history = self._history[-self._max_history:]

                # Check thresholds and raise alerts
                self._check_thresholds(metrics)

                # Phase 3: check disk space thresholds
                self._check_disk_thresholds(metrics.get("disk", {}))

                # Phase 4: push health snapshot into in-memory dashboard
                # state so the SSE loop can serve it without a DB query.
                self._push_health_to_dashboard(metrics)

            except Exception as e:
                logger.error("Health monitor error: %s", e)

            self._stop_event.wait(self.check_interval)

    def _collect_metrics(self) -> Dict:
        """Collect all system health metrics."""
        now = datetime.now()
        uptime = (now - self._start_time).total_seconds()

        memory = get_memory_usage()
        cpu = get_cpu_usage()

        # Database metrics
        db_metrics = self._get_db_metrics()

        # Disk space metrics (Phase 3)
        disk_metrics = self._get_disk_metrics()

        # Connection pool metrics (Phase 3)
        pool_metrics = self._get_pool_metrics()

        # Thread info
        thread_info = {
            "count": get_thread_count(),
            "names": get_thread_names(),
        }

        # Overall health status
        status = "good"
        issues = []

        if cpu > self.CPU_CRITICAL:
            status = "critical"
            issues.append(f"CPU usage: {cpu:.0f}%")
        elif cpu > self.CPU_WARNING:
            if status != "critical":
                status = "warning"
            issues.append(f"CPU usage: {cpu:.0f}%")

        if memory["rss_mb"] > self.MEMORY_CRITICAL:
            status = "critical"
            issues.append(f"Memory: {memory['rss_mb']:.0f} MB")
        elif memory["rss_mb"] > self.MEMORY_WARNING:
            if status != "critical":
                status = "warning"
            issues.append(f"Memory: {memory['rss_mb']:.0f} MB")

        db_size = db_metrics.get("size_mb", 0)
        if db_size > self.DB_SIZE_CRITICAL:
            status = "critical"
            issues.append(f"Database: {db_size:.0f} MB")
        elif db_size > self.DB_SIZE_WARNING:
            if status != "critical":
                status = "warning"
            issues.append(f"Database: {db_size:.0f} MB")

        # Disk space status (Phase 3)
        disk_status = disk_metrics.get("status", "unknown")
        if disk_status == "critical":
            status = "critical"
            issues.append(f"Disk space: {disk_metrics.get('free_percent', 0):.1f}% free")
        elif disk_status == "warning":
            if status != "critical":
                status = "warning"
            issues.append(f"Disk space: {disk_metrics.get('free_percent', 0):.1f}% free")

        return {
            "status": status,
            "issues": issues,
            "uptime_seconds": round(uptime, 0),
            "uptime_human": self._format_uptime(uptime),
            "cpu_percent": round(cpu, 1),
            "memory": memory,
            "database": db_metrics,
            "disk": disk_metrics,
            "pool": pool_metrics,
            "threads": thread_info,
            "timestamp": now.isoformat(),
        }

    def _get_db_metrics(self) -> Dict:
        """Collect database-specific metrics."""
        try:
            from database.queries.maintenance import (
                get_database_size_mb,
                get_table_row_counts,
            )

            size_mb = get_database_size_mb()
            row_counts = get_table_row_counts()

            return {
                "size_mb": round(size_mb, 1),
                "row_counts": row_counts,
                "total_rows": sum(
                    v for v in row_counts.values() if isinstance(v, int) and v > 0
                ),
            }
        except Exception as e:
            logger.debug("DB metrics error: %s", e)
            return {"size_mb": 0, "row_counts": {}, "total_rows": 0}

    def _check_thresholds(self, metrics: Dict) -> None:
        """Check metrics against thresholds and create alerts if needed."""
        if not self.alert_engine:
            return

        try:
            # CPU alert
            cpu = metrics.get("cpu_percent", 0)
            if cpu > self.CPU_CRITICAL:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="critical",
                    title="Critical CPU Usage",
                    message=f"CPU usage at {cpu:.0f}% (threshold: {self.CPU_CRITICAL}%)",
                    metadata={"cpu_percent": cpu, "health_subsystem": "cpu"},
                )
            elif cpu > self.CPU_WARNING:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="warning",
                    title="High CPU Usage",
                    message=f"CPU usage at {cpu:.0f}% (threshold: {self.CPU_WARNING}%)",
                    metadata={"cpu_percent": cpu, "health_subsystem": "cpu"},
                )

            # Memory alert
            rss_mb = metrics.get("memory", {}).get("rss_mb", 0)
            if rss_mb > self.MEMORY_CRITICAL:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="critical",
                    title="Critical Memory Usage",
                    message=f"Memory: {rss_mb:.0f} MB (threshold: {self.MEMORY_CRITICAL} MB)",
                    metadata={"memory_rss_mb": rss_mb, "health_subsystem": "memory"},
                )
            elif rss_mb > self.MEMORY_WARNING:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="warning",
                    title="High Memory Usage",
                    message=f"Memory: {rss_mb:.0f} MB (threshold: {self.MEMORY_WARNING} MB)",
                    metadata={"memory_rss_mb": rss_mb, "health_subsystem": "memory"},
                )

            # Database size alert
            db_size = metrics.get("database", {}).get("size_mb", 0)
            if db_size > self.DB_SIZE_CRITICAL:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="critical",
                    title="Critical Database Size",
                    message=f"Database: {db_size:.0f} MB (threshold: {self.DB_SIZE_CRITICAL} MB)",
                    metadata={"db_size_mb": db_size, "health_subsystem": "database"},
                )
            elif db_size > self.DB_SIZE_WARNING:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="warning",
                    title="Large Database",
                    message=f"Database: {db_size:.0f} MB (threshold: {self.DB_SIZE_WARNING} MB)",
                    metadata={"db_size_mb": db_size, "health_subsystem": "database"},
                )

            # Connection pool exhaustion alert
            pool = metrics.get("pool", {})
            pool_total = pool.get("total", 0)
            pool_available = pool.get("available", 0)
            if pool_total > 0 and pool_available == 0:
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="critical",
                    title="Connection Pool Exhausted",
                    message=(
                        f"All {pool_total} database connections are in use. "
                        "Queries may time out."
                    ),
                    metadata={"pool_total": pool_total, "health_subsystem": "pool"},
                )

        except Exception as e:
            logger.error("Threshold check error: %s", e)

    def _check_disk_thresholds(self, disk_metrics: Dict) -> None:
        """Check disk space thresholds and trigger emergency cleanup if needed."""
        if not self.alert_engine:
            return

        status = disk_metrics.get("status", "unknown")
        free_pct = disk_metrics.get("free_percent", 100)
        free_gb = disk_metrics.get("free_gb", 0)

        try:
            if status == "critical":
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="critical",
                    title="Critical Disk Space",
                    message=(
                        f"Disk space critically low: {free_pct:.1f}% free "
                        f"({free_gb:.1f} GB). Emergency cleanup triggered."
                    ),
                    metadata={
                        "free_percent": free_pct,
                        "free_gb": free_gb,
                        "health_subsystem": "disk",
                    },
                )
                # Trigger emergency cleanup
                try:
                    from database.queries.maintenance import emergency_cleanup
                    emergency_cleanup()
                except Exception as e:
                    logger.error("Emergency cleanup failed: %s", e)

            elif status == "warning":
                self.alert_engine.create_alert(
                    alert_type="health",
                    severity="warning",
                    title="Low Disk Space",
                    message=(
                        f"Disk space low: {free_pct:.1f}% free "
                        f"({free_gb:.1f} GB). Consider cleanup."
                    ),
                    metadata={
                        "free_percent": free_pct,
                        "free_gb": free_gb,
                        "health_subsystem": "disk",
                    },
                )
        except Exception as e:
            logger.error("Disk threshold check error: %s", e)

    @staticmethod
    def _get_disk_metrics() -> Dict:
        """Collect disk space metrics for the database partition."""
        try:
            from database.queries.maintenance import get_disk_space_info
            return get_disk_space_info()
        except Exception as e:
            logger.debug("Disk metrics error: %s", e)
            return {
                "total_gb": 0, "free_gb": 0, "used_gb": 0,
                "free_percent": 0, "status": "unknown",
            }

    @staticmethod
    def _get_pool_metrics() -> Dict:
        """Collect connection pool utilization metrics."""
        try:
            from database.connection import pool_stats
            return pool_stats()
        except Exception as e:
            logger.debug("Pool metrics error: %s", e)
            return {
                "total": 0, "available": 0, "in_use": 0,
                "borrow_count": 0, "wait_count": 0, "replace_count": 0,
            }

    @staticmethod
    def _push_health_to_dashboard(metrics: Dict) -> None:
        """Push the network health score into the in-memory dashboard state.

        Called every ``check_interval`` seconds so the SSE loop can
        serve health data from memory instead of a DB query.

        Uses ``get_health_score()`` from stats_queries which returns
        the ``{"score": N, "status": "..."}`` format the frontend expects.
        """
        try:
            from database.queries.stats_queries import get_health_score
            from utils.realtime_state import dashboard_state
            health = get_health_score()
            dashboard_state.set_health_score(health)
        except Exception as exc:
            logger.debug("_push_health_to_dashboard failed: %s", exc)

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        """Format uptime seconds into human-readable string."""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)

        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return " ".join(parts)
