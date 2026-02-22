"""
main.py - NetWatch Application Entry Point
============================================

Production-ready entry point for the NetWatch network monitoring application.
Orchestrates database, packet capture, anomaly detection, and web server.

Usage:
    python main.py              # Normal start
    python main.py --reset-db   # Reset database and start fresh
    python main.py --port 8080  # Use custom port
"""

import threading
import signal
import sys
import logging
import logging.handlers
import time
import argparse
import ctypes
import os
from datetime import datetime, timedelta

# Hard guard: NetWatch is validated only on Python 3.11.x
if sys.version_info[:2] != (3, 11):
    _ver = sys.version.split()[0]
    msg = (
        f"Unsupported Python version {_ver}. NetWatch requires Python 3.11.x. "
        "Please run with Python 3.11 to continue."
    )
    sys.stderr.write(msg + "\n")
    sys.exit(1)

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    LOG_LEVEL, LOG_FORMAT, LOG_FILE, LOG_FILE_MAX_SIZE, LOG_FILE_BACKUP_COUNT,
    APP_NAME, APP_VERSION, APP_ENV, IS_PRODUCTION,
    DATABASE_PATH, DB_CONNECTION_POOL_SIZE,
    IS_WINDOWS, IS_LINUX, IS_MACOS,
    WAITRESS_THREADS
)

# Import modules
from database.init_db import initialize_database
from database.connection import init_pool, shutdown_pool, get_connection
from packet_capture.interface_manager import InterfaceManager
from packet_capture.capture_engine import CaptureEngine
from backend.app import create_app
from alerts.anomaly_detector import AnomalyDetector
from alerts.alert_engine import AlertEngine
from alerts import set_shared_engine

# Internal project imports hoisted from inline locations (#36)
import ipaddress
from database.rollup import rollup_traffic, cleanup_old_rollups
from database.queries.maintenance import run_full_cleanup
from database.queries.device_queries import (
    set_subnet_from_ip, set_current_mode, set_gateway_ip,
    set_capture_interface,
)
from packet_capture.network_discovery import NetworkDiscovery
from utils.health_monitor import HealthMonitor
from packet_capture.hostname_resolver import (
    learn_hostname as _learn_hostname,
    enqueue_for_resolution as _enqueue_resolution,
    start_background_resolver as _start_bg_resolver,
    start_mdns_browser as _start_mdns_browser,
    close_resolver as _close_resolver,
)

# Production logging / metrics
try:
    from utils.logger import setup_logging as _production_setup_logging
    from utils.metrics import metrics_collector
    _HAS_PRODUCTION_LOGGING = True
except ImportError:
    _HAS_PRODUCTION_LOGGING = False

# Global shutdown event
shutdown_event = threading.Event()

# Global references for cleanup
_interface_manager = None
_capture_engine = None
_engine_lock = threading.Lock()   # protects _capture_engine mutations
_mode_transition_lock = threading.Lock()  # held during mode transitions; DB writer skips writes while held
_detector = None
_detector_thread = None
_cleanup_thread = None
_discovery_thread = None
_cached_discovery = None              # NetworkDiscovery singleton for discovery_loop
_cached_discovery_lock = threading.Lock()  # protects _cached_discovery lifecycle
_health_monitor = None
_health_log_thread = None
_app = None
_logger = None
_shutting_down = False
_shutdown_lock = threading.Lock()


def setup_logging(log_level=None, log_file=None):
    """Configure application logging with rotation support.

    Uses the production structured-logging module (utils.logger) when
    available, falling back to basic stdlib logging otherwise.
    """
    level = log_level or LOG_LEVEL

    if _HAS_PRODUCTION_LOGGING:
        # Production: JSON file logs + human console + error file
        root = _production_setup_logging(
            log_dir=os.path.join(PROJECT_ROOT, 'logs'),
            log_level=level,
            enable_console=True,
            enable_json_file=True,
            enable_error_file=True,
        )
    else:
        # Fallback: basic logging
        root = logging.getLogger()
        root.handlers.clear()
        root.setLevel(getattr(logging, level, logging.INFO))

        formatter = logging.Formatter(LOG_FORMAT)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(getattr(logging, level, logging.INFO))
        console.setFormatter(formatter)
        root.addHandler(console)

        target_log = log_file or LOG_FILE
        if target_log:
            log_dir = os.path.dirname(target_log)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                target_log,
                maxBytes=LOG_FILE_MAX_SIZE,
                backupCount=LOG_FILE_BACKUP_COUNT
            )
            file_handler.setLevel(getattr(logging, level, logging.INFO))
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)

    global _logger
    _logger = logging.getLogger(__name__)
    return _logger


def check_admin_privileges():
    """Check if running with administrator/root privileges."""
    try:
        if IS_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=f'{APP_NAME} v{APP_VERSION} - Network Monitoring System'
    )
    parser.add_argument(
        '--reset-db', action='store_true',
        help='Reset database (clear all stored data)'
    )
    parser.add_argument(
        '--port', type=int, default=None,
        help=f'Web server port (default: {FLASK_PORT})'
    )
    parser.add_argument(
        '--host', type=str, default=None,
        help=f'Web server host (default: {FLASK_HOST})'
    )
    parser.add_argument(
        '--no-capture', action='store_true',
        help='Start without packet capture (dashboard only)'
    )
    parser.add_argument(
        '--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default=None, help='Override log level'
    )
    parser.add_argument(
        '--log-file', type=str, default=None,
        help='Log to file (path)'
    )
    return parser.parse_args()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully.

    Sets the shutdown event and raises ``KeyboardInterrupt`` to break
    out of blocking calls (e.g. ``waitress_serve()``).  The exception
    is caught by the ``except KeyboardInterrupt`` in ``__main__`` or
    the ``finally`` block in ``main()``.
    """
    shutdown_event.set()
    raise KeyboardInterrupt


def shutdown():
    """Graceful shutdown of all services.

    Protected by ``_shutdown_lock`` so only the first caller runs the
    teardown sequence.  A 10-second watchdog forces ``sys.exit(1)`` if
    any step hangs (e.g. a blocking ``join()`` on a stuck thread).
    """
    global _shutting_down, _cached_discovery
    with _shutdown_lock:
        if _shutting_down:
            return
        _shutting_down = True

    logger = _logger or logging.getLogger(__name__)
    logger.info("Shutting down...")

    # ── 10-second watchdog ──────────────────────────────────────────
    # Only spawn the watchdog if there's actually something to shut
    # down (capture engine, interface manager, etc.).  During tests,
    # shutdown() is called at atexit with nothing initialised, and
    # the watchdog's ``os._exit(1)`` would kill the pytest process.
    _has_work = any([
        _capture_engine, _interface_manager, _detector, _health_monitor,
    ])
    if _has_work:
        def _watchdog():
            """Force-exit if shutdown hangs for longer than 10 seconds."""
            time.sleep(10)
            logger.error("Shutdown watchdog triggered — forcing exit")
            os._exit(1)

        wd = threading.Thread(target=_watchdog, name="ShutdownWatchdog", daemon=True)
        wd.start()

    if _capture_engine:
        try:
            _capture_engine.stop()
            logger.info("Capture engine stopped")
        except Exception as e:
            logger.error("Error stopping capture engine: %s", e)

    # Shut down hostname resolver (ThreadPoolExecutor + background thread)
    try:
        _close_resolver()
        logger.info("Hostname resolver stopped")
    except Exception as e:
        logger.error("Error stopping hostname resolver: %s", e)

    if _interface_manager:
        try:
            _interface_manager.stop_monitoring()
            logger.info("Interface manager stopped")
        except Exception as e:
            logger.error("Error stopping interface manager: %s", e)

    # Phase 5: stop any running NetworkDiscovery
    with _cached_discovery_lock:
        disc = _cached_discovery
        _cached_discovery = None
    if disc is not None:
        try:
            disc.stop_continuous_discovery()
        except Exception:
            pass

    if _detector:
        try:
            _detector.stop()
            logger.info("Anomaly detector stopped")
        except Exception as e:
            logger.error("Error stopping anomaly detector: %s", e)
    if _health_monitor:
        try:
            _health_monitor.stop()
            logger.info("Health monitor stopped")
        except Exception as e:
            logger.error("Error stopping health monitor: %s", e)
    try:
        shutdown_pool()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error("Error closing database pool: %s", e)

    logger.info("Shutdown complete")


def _create_capture_engine(mode):
    """
    Factory: create the Scapy-based capture engine.

    Uses Npcap on Windows for reliable packet capture.
    Passes the capture strategy from InterfaceManager when available.
    """
    iface = mode.interface.name
    strategy = None
    if _interface_manager:
        try:
            strategy = _interface_manager.get_capture_strategy()
        except Exception as e:
            _logger.debug("Could not get capture strategy: %s", e)
    _logger.info(
        "Creating Scapy/Npcap capture engine on '%s' (strategy=%s)",
        iface, type(strategy).__name__ if strategy else 'None',
    )
    engine = CaptureEngine(mode, interface=iface, strategy=strategy)

    # Register a callback that passively learns hostnames from
    # mDNS, NetBIOS-NS, and DNS response packets so the hostname
    # resolver can display them without active probing.
    engine.on_packet(_passive_hostname_callback)

    # Register interface-lost callback so the InterfaceManager
    # immediately re-detects when the capture interface disappears
    # (e.g. hotspot turned off → virtual adapter gone).
    engine.on_interface_lost(_on_interface_lost)

    return engine


def _on_interface_lost():
    """Callback fired by CaptureEngine when the interface vanishes.

    Forces the InterfaceManager to skip the stability threshold and
    immediately switch to the best available mode.

    **Important:** This callback is invoked *from* the capture thread.
    The mode-change handler will try to ``stop()`` the old capture
    engine, which calls ``join()`` on that same capture thread —
    creating a deadlock.  We therefore dispatch the re-detection to
    a short-lived background thread so the capture thread can exit.
    """
    logger = _logger or logging.getLogger(__name__)
    logger.warning("Capture interface lost — triggering immediate mode re-detection")
    if _interface_manager:
        def _redetect():
            try:
                _interface_manager.notify_interface_lost()
            except Exception as e:
                logger.error("Error during interface-lost re-detection: %s", e)

        t = threading.Thread(target=_redetect, name="InterfaceLost-Redetect", daemon=True)
        t.start()


def _passive_hostname_callback(pkt_data):
    """
    Extract hostnames from mDNS, NetBIOS-NS, DNS, DHCP, and SSDP packets
    and feed them to the hostname resolver's passive cache.

    Also enqueues devices without known hostnames for background resolution.
    """
    try:
        proto = (pkt_data.protocol or "").upper()
        if proto in ("MDNS", "NETBIOS-NS", "LLMNR", "DNS", "DHCP", "SSDP"):
            # For mDNS/LLMNR/NetBIOS/DHCP/SSDP: the device_name field may carry the hostname
            if pkt_data.device_name:
                ip = pkt_data.source_ip
                if ip:
                    _learn_hostname(ip, pkt_data.device_name)
        else:
            # For any other protocol: enqueue the source device for
            # background resolution if we haven't resolved it yet
            ip = pkt_data.source_ip
            mac = pkt_data.source_mac
            if ip and mac:
                _enqueue_resolution(ip, mac)
    except Exception:
        pass  # Never fail the capture pipeline


def _resolve_gateway_mac(gateway_ip: str) -> str:
    """Look up the MAC address corresponding to a gateway IP.

    Tries:
    1. The ``devices`` table (gateway already discovered via ARP/traffic).
    2. Platform ARP table (``arp -a`` / ``ip neigh``).

    Returns an empty string when resolution fails — callers treat that as
    "unknown gateway MAC" and simply don't tag the gateway.
    """
    if not gateway_ip:
        return ""

    # 1. Check the devices table
    try:
        from database.connection import get_connection
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT mac_address FROM devices "
                "WHERE ipv4_address = ? OR ip_address = ? LIMIT 1",
                (gateway_ip, gateway_ip),
            )
            row = cur.fetchone()
            if row:
                mac = row["mac_address"] if isinstance(row, dict) else row[0]
                if mac and mac.lower() not in ("", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    return mac.lower()
    except Exception:
        pass

    # 2. Parse platform ARP table
    try:
        import subprocess, re, sys as _sys
        if _sys.platform == "win32":
            out = subprocess.check_output(
                ["arp", "-a", gateway_ip],
                text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            out = subprocess.check_output(
                ["arp", "-n", gateway_ip], text=True, timeout=3,
            )
        mac_re = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", out)
        if mac_re:
            return mac_re.group(0).replace("-", ":").lower()
    except Exception:
        pass

    return ""


def _on_mode_change(old_mode, new_mode):
    """Callback fired by InterfaceManager when the network mode changes."""
    global _capture_engine
    logger = _logger or logging.getLogger(__name__)

    with _engine_lock:
        _on_mode_change_locked(old_mode, new_mode, logger)


def _on_mode_change_locked(old_mode, new_mode, logger):
    """Inner implementation — must be called while holding *_engine_lock*.

    Phase 5: Acquires ``_mode_transition_lock`` during the critical window
    between ``reset_subnet_cache()`` and the new engine being ready.  The
    ``DatabaseWriter`` / ``_flush_processed_batch`` checks this lock and
    re-queues (skips) DB writes while it is held, eliminating the race
    where packets are written against the wrong subnet.
    """
    global _capture_engine, _cached_discovery
    old_name = old_mode.get_mode_name().value if old_mode else 'None'
    new_name = new_mode.get_mode_name().value

    # Skip if mode didn't actually change (same mode, same interface)
    if (old_mode is not None
        and old_name == new_name
        and old_mode.interface.name == new_mode.interface.name
        and old_mode.interface.ip_address == new_mode.interface.ip_address):
        logger.debug("Mode unchanged: %s — skipping restart", new_name)
        return

    logger.info("Mode changed: %s -> %s — restarting capture engine", old_name, new_name)

    # Check if we're now disconnected (no real interface)
    new_ip = new_mode.interface.ip_address
    new_iface_name = new_mode.interface.name
    is_disconnected = (
        not new_ip or new_ip == "0.0.0.0"
        or new_iface_name in ("none", "unknown", "")
        or getattr(new_mode.interface, "interface_type", "") == "disconnected"
    )

    if is_disconnected:
        logger.info("Network disconnected — pausing capture engine")
        if _capture_engine and _capture_engine.is_running:
            try:
                _capture_engine.stop()
            except Exception as e:
                logger.error("Error stopping capture engine: %s", e)
        _capture_engine = None
        _expose_engine_to_routes()
        # Send SSE event so frontend shows disconnected state
        _send_mode_changed_sse(new_name, is_disconnected=True)
        return

    # ── Phase 5: acquire mode-transition lock ────────────────────────
    # While this lock is held the DatabaseWriter skips writes so no
    # packets are committed against the stale subnet.
    _mode_transition_lock.acquire()
    try:
        # ── Phase 5: full state reset ────────────────────────────────
        # 1. Clear BandwidthCalculator on the old engine
        if _capture_engine and hasattr(_capture_engine, 'bandwidth'):
            try:
                bw = _capture_engine.bandwidth
                with bw._lock:
                    bw._records.clear()
                    bw._packet_count = 0
            except Exception:
                pass

        # 2. Clear InMemoryDashboardState
        try:
            from utils.realtime_state import dashboard_state
            dashboard_state.clear()
        except Exception:
            pass

        # 3. Invalidate SSE cache + clear all route-level TTL caches
        try:
            from backend.blueprints.bandwidth_bp import invalidate_sse_cache
            invalidate_sse_cache()
        except ImportError:
            pass
        try:
            from backend.helpers import clear_response_cache
            clear_response_cache()
        except ImportError:
            pass

        # ── Phase 5: stop old NetworkDiscovery before creating new ──
        with _cached_discovery_lock:
            if _cached_discovery is not None:
                try:
                    _cached_discovery.stop_continuous_discovery()
                    logger.debug("Old NetworkDiscovery stopped")
                except Exception:
                    pass
                _cached_discovery = None

        # Update subnet cache and mode for device filtering
        try:
            from database.queries.device_queries import (
                set_subnet_from_ip, set_current_mode, reset_subnet_cache,
                set_gateway_ip, set_capture_interface, scope_devices_to_mode,
            )
            # Reset first so _detect_subnet() picks up the new interface
            reset_subnet_cache()
            if new_mode.interface.name:
                set_capture_interface(new_mode.interface.name)
            if new_mode.interface.ip_address:
                set_subnet_from_ip(new_mode.interface.ip_address)
                # Scope devices to the new mode so only matching devices
                # appear in the dashboard (fixes ghost / cross-mode devices).
                new_parts = new_mode.interface.ip_address.split('.')
                if len(new_parts) == 4:
                    new_prefix = f"{new_parts[0]}.{new_parts[1]}.{new_parts[2]}"
                    # Pass our MAC and gateway MAC so restrictive modes
                    # (wifi_client, public_network) only tag self + gateway.
                    our_mac = getattr(new_mode.interface, 'mac_address', None) or ''
                    gw_mac = _resolve_gateway_mac(
                        getattr(new_mode.interface, 'gateway', None) or ''
                    )
                    scope_devices_to_mode(
                        new_name, new_prefix,
                        our_mac=our_mac,
                        gateway_mac=gw_mac,
                    )
            # Pass gateway IP from mode detector — avoids re-parsing ipconfig
            gw = getattr(new_mode.interface, "gateway", None)
            set_gateway_ip(gw or "")
            set_current_mode(new_name)
            logger.info(
                "Device discovery updated for mode '%s' on %s (gw=%s)",
                new_name, new_mode.interface.ip_address, gw,
            )
        except Exception as e:
            logger.warning("Could not update subnet for new mode: %s", e)

        # Register the new interface's MAC and IP as "known" so the alert
        # engine does not fire a "new device" alert for our own machine
        # when it appears on the new subnet/interface.
        try:
            from alerts import get_shared_engine as _get_shared_engine
            ae = _get_shared_engine()
            if ae:
                new_mac = getattr(new_mode.interface, 'mac_address', None)
                if new_mac:
                    ae.add_known_mac(new_mac)
                new_ip_addr = new_mode.interface.ip_address
                if new_ip_addr:
                    ae.add_known_ip(new_ip_addr)
        except Exception:
            pass

        # Stop the old engine
        if _capture_engine and _capture_engine.is_running:
            try:
                _capture_engine.stop()
            except Exception as e:
                logger.error("Error stopping old capture engine: %s", e)

        # Wait briefly for the interface to be ready (avoids "interface not found" errors)
        iface_name = new_mode.interface.name
        for attempt in range(3):
            try:
                import psutil
                if any(iface_name.lower() in name.lower() for name in psutil.net_if_addrs()):
                    break
            except ImportError:
                break  # psutil not available — skip check
            except Exception:
                pass
            logger.debug("Waiting for interface '%s' to be ready (%d/3)…", iface_name, attempt + 1)
            time.sleep(1)

        # Start a new engine with the new mode
        try:
            _capture_engine = _create_capture_engine(new_mode)
            _capture_engine.start()
            # Expose the new engine to Flask routes
            _expose_engine_to_routes()
            logger.info("Capture engine restarted for mode '%s' on interface '%s'",
                        new_name, new_mode.interface.name)
        except Exception as e:
            logger.error("Failed to restart capture engine: %s", e)
    finally:
        _mode_transition_lock.release()

    # Send mode_changed SSE event so the frontend can show transition indicator
    _send_mode_changed_sse(new_name, is_disconnected=False)


def _send_mode_changed_sse(mode_name, is_disconnected=False):
    """Push a ``mode_changed`` SSE event to connected frontends."""
    try:
        import json
        from backend.blueprints.bandwidth_bp import _sse_push_event
        payload = json.dumps({
            'event': 'mode_changed',
            'mode': mode_name,
            'disconnected': is_disconnected,
        })
        _sse_push_event(payload)
    except Exception:
        pass  # SSE push is best-effort


def _expose_engine_to_routes():
    """Make the current engine, interface manager, detector, and health monitor accessible to Flask routes."""
    if _app:
        _app.config['CAPTURE_ENGINE'] = _capture_engine
        _app.config['INTERFACE_MANAGER'] = _interface_manager
        _app.config['ANOMALY_DETECTOR'] = _detector
        _app.config['HEALTH_MONITOR'] = _health_monitor
        # Clear the discovery singleton so it is re-created for the new interface
        _app.config.pop('_DISCOVERY_SINGLETON', None)


def start_packet_capture():
    """Start InterfaceManager + CaptureEngine."""
    global _interface_manager, _capture_engine

    try:
        # 1. Create InterfaceManager and do initial detection
        _interface_manager = InterfaceManager()
        _interface_manager.start_monitoring()

        # 2. Get the initial mode
        mode = _interface_manager.get_current_mode()
        _logger.info("Detected mode: %s on interface '%s'",
                     mode.get_mode_name().value, mode.interface.name)

        # 3. Create and start CaptureEngine (Scapy + Npcap)
        _capture_engine = _create_capture_engine(mode)
        _capture_engine.start()

        # 4. Register mode-change callback so the engine is recreated automatically
        _interface_manager.on_mode_change(_on_mode_change)

        return True
    except PermissionError:
        _logger.error("Permission denied for packet capture. Run as Administrator/root.")
        return False
    except Exception as e:
        _logger.error("Failed to start packet capture: %s", e)
        return False


def start_anomaly_detector(alert_engine: AlertEngine):
    """Start ML anomaly detector in background thread."""
    global _detector, _detector_thread

    try:
        _detector = AnomalyDetector(alert_engine=alert_engine, shutdown_event=shutdown_event)

        _detector_thread = threading.Thread(
            target=_detector.run,
            daemon=True,
            name="AnomalyDetector"
        )
        _detector_thread.start()
        return True
    except Exception as e:
        _logger.error("Failed to start anomaly detector: %s", e)
        return False


def start_cleanup_task():
    """Start periodic cleanup task for 24/7 operation."""
    global _cleanup_thread

    def cleanup_loop():
        from database.queries.maintenance import get_database_size_mb

        last_cleanup = datetime.now()
        last_full_cleanup_date = None

        while not shutdown_event.is_set():
            try:
                now = datetime.now()

                # Every 15 minutes: rollup traffic data (Phase 4: increased frequency)
                if now - last_cleanup >= timedelta(minutes=15):
                    # Aggregate raw traffic into hourly rollup, keep last 24h raw
                    try:
                        result = rollup_traffic(raw_retention_hours=24)
                        if result["deleted"] > 0:
                            _logger.info("Traffic rollup: %d raw rows archived", result["deleted"])
                    except Exception as e:
                        _logger.error("Traffic rollup error: %s", e)

                    # Clean up old rollup data (>90 days)
                    try:
                        cleanup_old_rollups(days_to_keep=90)
                    except Exception as e:
                        _logger.error("Rollup cleanup error: %s", e)

                    # Hourly lightweight cleanup via canonical maintenance module
                    try:
                        result = run_full_cleanup(
                            traffic_retention_days=7,
                            alert_retention_days=30,
                            stats_retention_days=30,
                            daily_usage_retention_days=90,
                        )
                        total_deleted = sum(v for k, v in result.items() if k.endswith('_deleted'))
                        if total_deleted > 0:
                            _logger.info("Hourly cleanup: removed %s records, freed %.1f MB",
                                         f"{total_deleted:,}", result.get('freed_mb', 0))
                    except Exception as e:
                        _logger.error("Hourly cleanup error: %s", e)

                    last_cleanup = now

                # Daily at 3 AM: full comprehensive cleanup
                if now.hour >= 3 and last_full_cleanup_date != now.date():
                    _logger.info("🧹 Daily cleanup starting...")
                    try:
                        result = run_full_cleanup(
                            traffic_retention_days=7,
                            alert_retention_days=30,
                            stats_retention_days=30,
                            daily_usage_retention_days=90,
                        )
                        _logger.info(
                            "✅ Daily cleanup complete: deleted %s records, freed %.1f MB",
                            f"{sum(v for k, v in result.items() if k.endswith('_deleted')):,}",
                            result.get('freed_mb', 0),
                        )
                    except Exception as e:
                        _logger.error("Daily cleanup error: %s", e)

                    # Always VACUUM daily to reclaim space from accumulated deletions
                    try:
                        from database.queries.maintenance import vacuum_database
                        vacuum_database()
                    except Exception as e:
                        _logger.error("Daily VACUUM error: %s", e)

                    last_full_cleanup_date = now.date()

                shutdown_event.wait(300)
            except Exception as e:
                _logger.error("Cleanup task error: %s", e)
                shutdown_event.wait(60)

    _cleanup_thread = threading.Thread(
        target=cleanup_loop,
        daemon=True,
        name="CleanupTask"
    )
    _cleanup_thread.start()
    return True


def start_discovery_task():
    """Periodically run NetworkDiscovery.scan() and upsert device names into DB."""
    global _discovery_thread

    def _upsert_devices(devices, current_mode_name):
        """Upsert discovered devices into the devices table.

        Filters out our own machine's IP before alerting so we don't
        create a spurious "new device" alert for ourselves when the
        capture interface changes (e.g. Wi-Fi → hotspot).

        Also enqueues newly-discovered devices for background hostname
        resolution so hostnames are resolved without waiting for the
        next API request.
        """
        if not devices:
            return

        # Determine our own IP so we can skip alerting for it
        own_ip = None
        if _interface_manager:
            try:
                cur_mode = _interface_manager.get_current_mode()
                if cur_mode:
                    own_ip = cur_mode.interface.ip_address
            except Exception:
                pass

        with get_connection() as conn:
            cursor = conn.cursor()
            for dev in devices:
                hostname = dev.get('hostname') or ''
                mac = dev.get('mac', '')
                ip = dev.get('ip', '')
                vendor = dev.get('vendor', '')

                # Security: alert on new/unknown devices
                # Skip alerting for our own device (IP match)
                if _detector and hasattr(_detector, 'alert_engine'):
                    if ip and ip != own_ip:
                        try:
                            _detector.alert_engine.check_new_device(
                                mac=mac, ip=ip,
                                hostname=hostname,
                                vendor=vendor,
                                mode_name=current_mode_name,
                            )
                        except Exception:
                            pass

                if hostname and ip:
                    cursor.execute("""
                        UPDATE devices
                        SET hostname = CASE WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address) THEN ? ELSE hostname END,
                            vendor = CASE WHEN (vendor IS NULL OR vendor = '') THEN ? ELSE vendor END,
                            last_seen = datetime('now')
                        WHERE ip_address = ? OR mac_address = ?
                    """, (hostname, vendor, ip, mac))

                # ARP-based hostname learning: enqueue every discovered
                # device for background hostname resolution immediately
                # instead of waiting for the next API request.
                if ip:
                    _enqueue_resolution(ip, mac or None)
            conn.commit()

    def _upsert_arp_cache_devices(devices, current_mode_name, set_active_mode=False):
        """Upsert ARP-cache-discovered devices with active_mode=NULL.

        These devices are visible on the Devices page (detected_mode is set)
        but do NOT count as "active" for the dashboard card because
        active_mode stays NULL — only traffic-producing devices get
        active_mode set via ``save_packet()``.

        When *set_active_mode* is True (e.g. wifi_client mode ARP scans),
        active_mode is set to *current_mode_name* so that discovered
        devices appear in the dashboard device list immediately.
        """
        if not devices:
            return

        own_ip = None
        own_subnet = None
        if _interface_manager:
            try:
                cur_mode = _interface_manager.get_current_mode()
                if cur_mode:
                    own_ip = cur_mode.interface.ip_address
                    # Derive subnet prefix for filtering out cross-adapter devices
                    if own_ip:
                        parts = own_ip.split('.')
                        if len(parts) == 4:
                            own_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}."
            except Exception:
                pass

        active_mode_val = current_mode_name if set_active_mode else None

        with get_connection() as conn:
            cursor = conn.cursor()
            for dev in devices:
                hostname = dev.get('hostname') or ''
                mac = dev.get('mac', '')
                ip = dev.get('ip', '')
                vendor = dev.get('vendor', '')

                if not mac or mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                    continue

                # Skip our own device
                if ip and ip == own_ip:
                    continue

                # Skip devices outside the current subnet (prevents
                # cross-adapter leakage, e.g. VirtualBox adapter IPs)
                if own_subnet and ip and not ip.startswith(own_subnet):
                    continue

                # INSERT with detected_mode set, active_mode conditionally set.
                # ON CONFLICT: only update fields that are still empty
                # and refresh last_seen.  When set_active_mode is True,
                # also update active_mode so newly discovered devices
                # appear in dashboard queries.
                cursor.execute("""
                    INSERT INTO devices
                        (mac_address, ip_address, ipv4_address,
                         hostname, vendor,
                         first_seen, last_seen,
                         detected_mode, active_mode)
                    VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'),
                            ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ip_address   = COALESCE(NULLIF(ip_address, ''), excluded.ip_address),
                        ipv4_address = COALESCE(NULLIF(ipv4_address, ''), excluded.ipv4_address),
                        hostname     = CASE
                            WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                            THEN COALESCE(NULLIF(excluded.hostname, ''), hostname)
                            ELSE hostname END,
                        vendor       = CASE
                            WHEN (vendor IS NULL OR vendor = '')
                            THEN COALESCE(NULLIF(excluded.vendor, ''), vendor)
                            ELSE vendor END,
                        last_seen    = datetime('now'),
                        detected_mode = COALESCE(detected_mode, excluded.detected_mode),
                        active_mode  = CASE
                            WHEN excluded.active_mode IS NOT NULL
                            THEN COALESCE(active_mode, excluded.active_mode)
                            ELSE active_mode END
                """, (mac, ip, ip, hostname, vendor, current_mode_name, active_mode_val))

                if ip:
                    _enqueue_resolution(ip, mac or None)
            conn.commit()

    def discovery_loop():
        global _cached_discovery
        _cached_iface = None
        _cached_network = None
        _iteration = 0               # counter for periodic ping sweep

        while not shutdown_event.is_set():
            try:
                # Only run if we have an interface manager with a valid mode
                if _interface_manager:
                    mode = _interface_manager.get_current_mode()
                    iface_name = mode.interface.name if mode else None
                    ip_addr = mode.interface.ip_address if mode else None

                    # ── Mode-aware discovery gating ──────────────────────
                    # In wifi_client / public_network modes we must NOT
                    # probe or scan the network — only our own traffic is
                    # relevant.  However, if the mode allows ARP cache
                    # scanning (passive, no packets sent), we can still
                    # discover neighbours from the OS ARP table.
                    can_arp = mode.capabilities.can_arp_scan if mode else False
                    can_passive = mode.capabilities.can_do_passive_discovery if mode else False
                    can_arp_cache = mode.capabilities.can_arp_cache_scan if mode else False

                    if not can_arp and not can_passive and not can_arp_cache:
                        # Nothing to discover in this mode — sleep and retry
                        # Phase 5: stop any running discovery thread
                        with _cached_discovery_lock:
                            if _cached_discovery is not None:
                                try:
                                    _cached_discovery.stop_continuous_discovery()
                                except Exception:
                                    pass
                                _cached_discovery = None
                                _cached_iface = None
                                _cached_network = None
                        shutdown_event.wait(60)
                        continue

                    # ── ARP-cache-only path (wifi_client / public_network) ─
                    # When active scanning is disabled but ARP cache is
                    # allowed, read the OS ARP table every 30 seconds.
                    # Devices found this way get detected_mode set but
                    # active_mode=NULL so they appear on the Devices page
                    # without inflating the "Active Devices" dashboard count.
                    if not can_arp and not can_passive and can_arp_cache:
                        if iface_name and ip_addr:
                            try:
                                prefix_len = 24
                                try:
                                    import netifaces
                                    addrs = netifaces.ifaddresses(iface_name)
                                    ipv4_list = addrs.get(netifaces.AF_INET, [])
                                    for entry in ipv4_list:
                                        if entry.get('addr') == ip_addr:
                                            netmask = entry.get('netmask', '255.255.255.0')
                                            prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                                            break
                                except Exception:
                                    pass
                                network = str(ipaddress.IPv4Network(f"{ip_addr}/{prefix_len}", strict=False))

                                # Ensure a NetworkDiscovery instance exists
                                need_new = (
                                    _cached_discovery is None
                                    or iface_name != _cached_iface
                                    or network != _cached_network
                                )
                                if need_new:
                                    with _cached_discovery_lock:
                                        if _cached_discovery is not None:
                                            try:
                                                _cached_discovery.stop_continuous_discovery()
                                            except Exception:
                                                pass
                                        _cached_discovery = NetworkDiscovery(interface=iface_name, subnet=network)
                                    _cached_iface = iface_name
                                    _cached_network = network

                                current_mode_name = mode.get_mode_name().value if mode else ""
                                # Phase D: use local-copy pattern to avoid race
                                with _cached_discovery_lock:
                                    disc = _cached_discovery
                                if disc is not None:
                                    cache_devices = disc.arp_cache_scan()
                                    _upsert_arp_cache_devices(cache_devices, current_mode_name)
                                else:
                                    cache_devices = []
                                _logger.debug(
                                    "ARP cache scan (%s): %d device(s) found",
                                    current_mode_name, len(cache_devices),
                                )
                            except Exception as e:
                                _logger.debug("ARP cache discovery error: %s", e)
                        # 30-second interval for passive cache scanning
                        shutdown_event.wait(30)
                        continue

                    if iface_name and ip_addr:
                        try:
                            # Use actual subnet mask from netifaces instead of hardcoded /24
                            prefix_len = 24
                            try:
                                import netifaces
                                addrs = netifaces.ifaddresses(iface_name)
                                ipv4_list = addrs.get(netifaces.AF_INET, [])
                                for entry in ipv4_list:
                                    if entry.get('addr') == ip_addr:
                                        netmask = entry.get('netmask', '255.255.255.0')
                                        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                                        break
                            except Exception:
                                pass
                            network = str(ipaddress.IPv4Network(f"{ip_addr}/{prefix_len}", strict=False))

                            # Only create a new NetworkDiscovery when interface or subnet changed.
                            # scan() is called on the existing singleton — never re-instantiate.
                            need_new = (
                                _cached_discovery is None
                                or iface_name != _cached_iface
                                or network != _cached_network
                            )
                            if need_new:
                                # Phase 5: stop old discovery before creating new
                                with _cached_discovery_lock:
                                    if _cached_discovery is not None:
                                        _logger.info(
                                            "Interface/subnet changed (%s/%s → %s/%s) — creating new NetworkDiscovery",
                                            _cached_iface, _cached_network, iface_name, network,
                                        )
                                        try:
                                            _cached_discovery.stop_continuous_discovery()
                                        except Exception:
                                            pass
                                    _cached_discovery = NetworkDiscovery(interface=iface_name, subnet=network)
                                _cached_iface = iface_name
                                _cached_network = network
                                _iteration = 0  # reset on interface change

                            # Always call scan() on the EXISTING instance
                            # Phase D: use local-copy pattern with lock
                            with _cached_discovery_lock:
                                discovery = _cached_discovery
                            if discovery is None:
                                shutdown_event.wait(10)
                                continue
                            current_mode_name = mode.get_mode_name().value if mode else ""
                            # wifi_client uses ARP scan for DISCOVERY (listing
                            # devices on the LAN) but only captures own traffic.
                            # _upsert_devices only UPDATEs existing rows, so we
                            # must also call _upsert_arp_cache_devices to INSERT
                            # new entries with active_mode set.
                            is_discovery_only = (
                                mode and mode.get_scope().name == "OWN_TRAFFIC_ONLY"
                            )

                            # 1. ARP scan (primary — fast, L2)
                            devices = discovery.arp_scan(timeout=3)
                            _upsert_devices(devices, current_mode_name)
                            if is_discovery_only and devices:
                                _upsert_arp_cache_devices(
                                    devices, current_mode_name, set_active_mode=True,
                                )

                            # 2. ARP cache scan (supplement — catches devices
                            #    that don't respond to our ARP broadcast, e.g.
                            #    on WiFi hotspots with client isolation)
                            try:
                                cache_devices = discovery.arp_cache_scan()
                                _upsert_devices(cache_devices, current_mode_name)
                                if is_discovery_only and cache_devices:
                                    _upsert_arp_cache_devices(
                                        cache_devices, current_mode_name,
                                        set_active_mode=True,
                                    )
                            except Exception:
                                pass

                            # 3. Ping sweep — run on first iteration and then
                            #    every 5th cycle (~5 min) to find devices behind
                            #    L2 client isolation on mobile hotspots.  Ping is
                            #    routed at L3 so the hotspot will forward it.
                            if _iteration == 0 or _iteration % 5 == 0:
                                try:
                                    ping_devices = discovery.ping_sweep(
                                        max_workers=20,
                                    )
                                    _upsert_devices(ping_devices, current_mode_name)
                                    if is_discovery_only and ping_devices:
                                        _upsert_arp_cache_devices(
                                            ping_devices, current_mode_name,
                                            set_active_mode=True,
                                        )
                                    # Re-check ARP cache after pinging — new
                                    # entries may have been created by the OS
                                    if ping_devices:
                                        try:
                                            cache2 = discovery.arp_cache_scan()
                                            _upsert_devices(cache2, current_mode_name)
                                            if is_discovery_only and cache2:
                                                _upsert_arp_cache_devices(
                                                    cache2, current_mode_name,
                                                    set_active_mode=True,
                                                )
                                        except Exception:
                                            pass
                                except Exception as e:
                                    _logger.debug("Ping sweep error: %s", e)

                            _iteration += 1

                            total = len(discovery.get_all_devices()) if hasattr(discovery, 'get_all_devices') else len(devices)
                            _logger.debug("Discovery scan: %d device(s) known", total)
                        except ImportError:
                            pass
                        except Exception as e:
                            _logger.debug("Discovery scan error: %s", e)
            except Exception as e:
                _logger.debug("Discovery loop error: %s", e)

            shutdown_event.wait(60)

    _discovery_thread = threading.Thread(
        target=discovery_loop,
        daemon=True,
        name="DiscoveryTask"
    )
    _discovery_thread.start()
    return True


def start_health_monitor(alert_engine: AlertEngine):
    """Start system health monitoring in background thread."""
    global _health_monitor

    try:
        _health_monitor = HealthMonitor(
            check_interval=60,
            alert_engine=alert_engine,
        )
        _health_monitor.start()
        return True
    except Exception as e:
        _logger.error("Failed to start health monitor: %s", e)
        return False


# ---------------------------------------------------------------------------
# Thread watchdog — detects silently dead daemon threads
# ---------------------------------------------------------------------------

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

    Runs every 30 s.  If a watched thread has disappeared, logs a
    warning so operators can detect silent crashes.
    """
    logger = _logger or logging.getLogger(__name__)
    start = time.time()
    while not shutdown_event.is_set():
        # Give threads a short grace period to start before warning
        if time.time() - start < 30:
            shutdown_event.wait(5)
            continue
        alive_names = {t.name for t in threading.enumerate() if t.is_alive()}
        for label, patterns in _WATCHED_THREAD_PATTERNS.items():
            present = any(
                any(name.startswith(pat) for pat in patterns)
                for name in alive_names
            )
            if not present:
                logger.warning(
                    "Thread watchdog: '%s' is not alive — it may have crashed silently",
                    label,
                )
        shutdown_event.wait(30)


def start_thread_watchdog():
    """Start the thread watchdog in a daemon thread."""
    t = threading.Thread(target=_thread_watchdog, daemon=True, name="ThreadWatchdog")
    t.start()
    return True


def print_banner():
    """Print the NetWatch startup banner."""
    print(f"""
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                                                                          ║
    ║  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗  ║
    ║  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║  ║
    ║  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║  ║
    ║  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║  ║
    ║  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║  ║
    ║  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝  ║
    ║                                                                          ║
    ║   v{APP_VERSION}  |  {APP_ENV}                                                  ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """)


def main():
    """Main application entry point."""
    args = parse_args()

    # Setup logging
    logger = setup_logging(log_level=args.log_level, log_file=args.log_file)

    print_banner()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Check admin privileges — packet capture requires elevated privileges
    is_admin = check_admin_privileges()
    if not is_admin:
        logger.error(
            "NetWatch requires administrator/root privileges for packet capture."
        )
        print("ERROR: NetWatch requires administrator/root privileges.")
        if IS_WINDOWS:
            print("  Windows: Right-click → 'Run as administrator'")
        else:
            print("  Linux/macOS: sudo python main.py")
        sys.exit(1)

    # Ensure database directory exists (production)
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except PermissionError:
            logger.error("Cannot create database directory: %s", db_dir)
            sys.exit(1)

    # Initialize database
    try:
        initialize_database(force_reset=args.reset_db)
        logger.info("Database initialized")
    except Exception as e:
        logger.error("Database initialization failed: %s", e)
        sys.exit(1)

    # Note: startup migrations (cleanup_invalid_devices, etc.) are applied
    # automatically by initialize_database() → _run_migrations() and tracked
    # in system_config.applied_migrations.  No separate call needed.

    # Initialize connection pool
    try:
        init_pool(DATABASE_PATH, pool_size=DB_CONNECTION_POOL_SIZE)
        logger.info("Connection pool ready (size=%d)", DB_CONNECTION_POOL_SIZE)
    except Exception as e:
        logger.error("Connection pool initialization failed: %s", e)
        sys.exit(1)

    # Start packet capture (unless --no-capture)
    if args.no_capture:
        logger.info("Packet capture skipped (--no-capture)")
        capture_started = False
    else:
        logger.info("Capture backend: Scapy + Npcap")
        capture_started = start_packet_capture()
        if capture_started:
            logger.info("Packet capture started")

            # LOCK SUBNET TO CAPTURE INTERFACE (fixes device count issue)
            # The default socket-based detection may pick a Docker/VPN IP
            # instead of the actual capture interface IP.
            try:
                mode = _interface_manager.get_current_mode()
                if mode and mode.interface.ip_address:
                    set_capture_interface(mode.interface.name)
                    set_subnet_from_ip(mode.interface.ip_address)
                    # Pass gateway IP from mode detection for accurate exclusion
                    gw = getattr(mode.interface, "gateway", None)
                    set_gateway_ip(gw or "")
                    set_current_mode(mode.get_mode_name().value)
                    logger.info(
                        "Device discovery locked to capture interface: %s (mode=%s, gw=%s)",
                        mode.interface.ip_address,
                        mode.get_mode_name().value,
                        gw,
                    )
                    # Register our own MAC as known (deferred until AlertEngine created)
                    _own_mac = getattr(mode.interface, 'mac_address', None)
            except Exception as e:
                logger.warning("Could not lock subnet to capture interface: %s", e)
        else:
            logger.warning("Packet capture unavailable — dashboard only mode")

    # Create a SINGLE AlertEngine shared by all subsystems (DI)
    alert_engine = AlertEngine()
    logger.info("AlertEngine created (shared instance)")

    # Register our own MAC as known so it won't trigger security alerts
    if '_own_mac' in dir() and _own_mac:  # noqa: F821 – set earlier in capture block
        alert_engine.add_known_mac(_own_mac)
    # Also register our own IP so discovery won't alert on self
    try:
        mode = _interface_manager.get_current_mode() if _interface_manager else None
        if mode and mode.interface.ip_address:
            alert_engine.add_known_ip(mode.interface.ip_address)
    except Exception:
        pass

    # Wire the shared engine into the alerts package for backward-compat shims
    set_shared_engine(alert_engine)

    # Start anomaly detector
    detector_started = start_anomaly_detector(alert_engine)
    if detector_started:
        logger.info("Anomaly detector started")

    # Start system health monitor
    health_started = start_health_monitor(alert_engine)
    if health_started:
        logger.info("System health monitor started")

    # Start thread watchdog (detect silently dead daemon threads)
    start_thread_watchdog()
    logger.info("Thread watchdog started")

    # Start periodic cleanup
    start_cleanup_task()
    logger.info("Periodic cleanup task started (daily at 3 AM)")

    # Start periodic device discovery (ARP + hostname resolution)
    if capture_started:
        start_discovery_task()

    # Start background hostname resolver and mDNS browser
    # (runs independently, periodically resolving devices with hostname IS NULL)
    try:
        _start_bg_resolver()
        logger.info("Background hostname resolver started")
        if capture_started:
            _start_mdns_browser()
            logger.info("mDNS browser started for proactive device discovery")
    except Exception as e:
        logger.warning("Could not start background hostname resolver: %s", e)

    # Start Flask server
    host = args.host or FLASK_HOST
    port = args.port or FLASK_PORT
    debug = FLASK_DEBUG and not IS_PRODUCTION

    logger.info("Dashboard: http://%s:%d  — Press Ctrl+C to stop", host, port)

    global _app
    _app = create_app()

    # Expose InterfaceManager & CaptureEngine to Flask routes
    _expose_engine_to_routes()

    try:
        if debug:
            # Development: use Flask's built-in server with debugger
            logger.info("Starting Flask dev server (debug mode)")
            _app.run(
                host=host,
                port=port,
                debug=True,
                use_reloader=False,
                threaded=True
            )
        else:
            # Production: use waitress (Windows-compatible, threaded WSGI)
            try:
                from waitress import serve as waitress_serve
                logger.info("Starting Waitress production server")
                waitress_serve(
                    _app,
                    host=host,
                    port=port,
                    threads=WAITRESS_THREADS,
                    channel_timeout=120,
                    cleanup_interval=30,
                    _quiet=True,
                )
            except ImportError:
                logger.warning(
                    "waitress not installed — falling back to Flask dev server. "
                    "Install with: pip install waitress"
                )
                _app.run(
                    host=host,
                    port=port,
                    debug=False,
                    use_reloader=False,
                    threaded=True
                )
    except Exception as e:
        logger.error("Flask server error: %s", e)
    finally:
        shutdown_event.set()
        shutdown()


# ── atexit guard (Phase D) ─────────────────────────────────────────
# Ensures shutdown() runs exactly once regardless of how the process
# exits (signal, exception, normal return).  The _shutdown_lock inside
# shutdown() prevents duplicate work if the finally block already ran.
import atexit
atexit.register(shutdown)


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("ERROR: NetWatch requires administrator privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        shutdown()
    except Exception as e:
        if _logger:
            _logger.error("Fatal error: %s", e, exc_info=True)
        else:
            print(f"Fatal error: {e}")
        sys.exit(1)