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
_detector = None
_detector_thread = None
_cleanup_thread = None
_discovery_thread = None
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
    """Handle shutdown signals gracefully."""
    shutdown_event.set()
    shutdown()
    sys.exit(0)


def shutdown():
    """Graceful shutdown of all services."""
    global _shutting_down
    with _shutdown_lock:
        if _shutting_down:
            return
        _shutting_down = True

    logger = _logger or logging.getLogger(__name__)
    logger.info("Shutting down...")

    if _capture_engine:
        try:
            _capture_engine.stop()
            logger.info("Capture engine stopped")
        except Exception as e:
            logger.error("Error stopping capture engine: %s", e)

    if _interface_manager:
        try:
            _interface_manager.stop_monitoring()
            logger.info("Interface manager stopped")
        except Exception as e:
            logger.error("Error stopping interface manager: %s", e)

    if _detector:
        try:
            _detector.stop()
            logger.info("Anomaly detector stopped")
        except Exception as e:
            logger.error("Error stopping anomaly detector: %s", e)
    if _health_monitor:
        try:
            _health_monitor.stop()
            _logger.info("Health monitor stopped")
        except Exception as e:
            _logger.error("Error stopping health monitor: %s", e)
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
    return CaptureEngine(mode, interface=iface, strategy=strategy)


def _on_mode_change(old_mode, new_mode):
    """Callback fired by InterfaceManager when the network mode changes."""
    global _capture_engine
    logger = _logger or logging.getLogger(__name__)

    with _engine_lock:
        _on_mode_change_locked(old_mode, new_mode, logger)


def _on_mode_change_locked(old_mode, new_mode, logger):
    """Inner implementation — must be called while holding *_engine_lock*."""
    global _capture_engine
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
        return

    # Update subnet cache and mode for device filtering
    try:
        from database.queries.device_queries import (
            set_subnet_from_ip, set_current_mode, reset_subnet_cache,
            set_gateway_ip, set_capture_interface, deactivate_stale_devices,
        )
        # Reset first so _detect_subnet() picks up the new interface
        reset_subnet_cache()
        if new_mode.interface.name:
            set_capture_interface(new_mode.interface.name)
        if new_mode.interface.ip_address:
            set_subnet_from_ip(new_mode.interface.ip_address)
            # Deactivate devices from the old subnet so they stop
            # appearing as "active" in the dashboard (fixes ghost devices).
            new_parts = new_mode.interface.ip_address.split('.')
            if len(new_parts) == 4:
                new_prefix = f"{new_parts[0]}.{new_parts[1]}.{new_parts[2]}"
                deactivate_stale_devices(new_prefix)
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

                # Hourly: rollup traffic data
                if now - last_cleanup >= timedelta(hours=1):
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

    def discovery_loop():
        _cached_discovery = None     # reuse across iterations
        _cached_iface = None
        _cached_network = None

        while not shutdown_event.is_set():
            try:
                # Only run if we have an interface manager with a valid mode
                if _interface_manager:
                    mode = _interface_manager.get_current_mode()
                    iface_name = mode.interface.name if mode else None
                    ip_addr = mode.interface.ip_address if mode else None

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
                                if _cached_discovery is not None:
                                    _logger.info(
                                        "Interface/subnet changed (%s/%s → %s/%s) — creating new NetworkDiscovery",
                                        _cached_iface, _cached_network, iface_name, network,
                                    )
                                _cached_discovery = NetworkDiscovery(interface=iface_name, subnet=network)
                                _cached_iface = iface_name
                                _cached_network = network

                            # Always call scan() on the EXISTING instance
                            discovery = _cached_discovery
                            devices = discovery.arp_scan(timeout=3)

                            # Get current mode name for security alerting
                            current_mode_name = mode.get_mode_name().value if mode else ""

                            # Upsert discovered hostnames into the devices table
                            if devices:
                                with get_connection() as conn:
                                    cursor = conn.cursor()
                                    for dev in devices:
                                        hostname = dev.get('hostname') or ''
                                        mac = dev.get('mac', '')
                                        ip = dev.get('ip', '')
                                        vendor = dev.get('vendor', '')

                                        # Security: alert on new/unknown devices
                                        if _detector and hasattr(_detector, 'alert_engine'):
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
                                    conn.commit()
                                _logger.debug("Discovery scan: upserted %d device(s)", len(devices))
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


def print_banner():
    """Print the NetWatch startup banner."""
    print(f"""
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗║
    ║  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║║
    ║  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║║
    ║  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║║
    ║  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║║
    ║  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝║
    ║                                                                        ║
    ║   v{APP_VERSION}  |  {APP_ENV}                                               ║
    ╚════════════════════════════════════════════════════════════════════════╝
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

    # Start periodic cleanup
    start_cleanup_task()
    logger.info("Periodic cleanup task started (daily at 3 AM)")

    # Start periodic device discovery (ARP + hostname resolution)
    if capture_started:
        start_discovery_task()

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