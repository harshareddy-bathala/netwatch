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

# Hard guard: NetWatch requires Python 3.11+
if sys.version_info < (3, 11):
    _ver = sys.version.split()[0]
    msg = (
        f"Unsupported Python version {_ver}. NetWatch requires Python 3.11 or later. "
        "Please run with Python 3.11+ to continue."
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
from database.connection import init_pool, get_connection
from backend.app import create_app
from alerts.alert_engine import AlertEngine
from alerts import set_shared_engine

# Orchestration modules
from orchestration import state
from orchestration.shutdown import shutdown
from orchestration.mode_handler import (
    start_packet_capture, expose_engine_to_routes, resolve_gateway_mac,
)
from orchestration.discovery_manager import (
    start_discovery_task, get_all_local_ips, get_all_local_macs,
)
from orchestration.background_tasks import (
    start_anomaly_detector, start_cleanup_task,
    start_health_monitor, start_thread_watchdog,
)

# Hostname resolver functions
from packet_capture.hostname_resolver import (
    start_background_resolver as _start_bg_resolver,
    start_mdns_browser as _start_mdns_browser,
)

# Database setup helpers
from database.queries.device_queries import (
    set_subnet_from_ip, set_current_mode, set_gateway_ip,
    set_capture_interface, set_gateway_mac,
)

# Production logging / metrics
try:
    from utils.logger import setup_logging as _production_setup_logging
    from utils.metrics import metrics_collector
    _HAS_PRODUCTION_LOGGING = True
except ImportError:
    _HAS_PRODUCTION_LOGGING = False

# Re-export shutdown_event from state for backward compatibility.
# bandwidth_bp.py, capture_engine.py, and tests import it from main.
shutdown_event = state.shutdown_event


def __getattr__(name):
    """Module-level __getattr__ for backward compatibility.

    External modules (capture_engine.py, interface_manager.py, tests)
    do lazy imports like ``from main import _capture_engine``.
    This handler proxies those lookups to ``orchestration.state``.
    """
    _ATTR_MAP = {
        '_capture_engine': 'capture_engine',
        '_interface_manager': 'interface_manager',
        '_mode_transition_lock': 'mode_transition_lock',
        '_engine_lock': 'engine_lock',
        '_detector': 'detector',
        '_health_monitor': 'health_monitor',
        '_app': 'app',
        '_logger': 'logger',
        '_shutting_down': 'shutting_down',
        '_shutdown_lock': 'shutdown_lock',
        '_cached_discovery': 'cached_discovery',
        '_cached_discovery_lock': 'cached_discovery_lock',
    }
    if name in _ATTR_MAP:
        return getattr(state, _ATTR_MAP[name])
    raise AttributeError(f"module 'main' has no attribute {name}")


def setup_logging(log_level=None, log_file=None):
    """Configure application logging with rotation support.

    Uses the production structured-logging module (utils.logger) when
    available, falling back to basic stdlib logging otherwise.
    """
    level = log_level or LOG_LEVEL

    if _HAS_PRODUCTION_LOGGING:
        root = _production_setup_logging(
            log_dir=os.path.join(PROJECT_ROOT, 'logs'),
            log_level=level,
            enable_console=True,
            enable_json_file=True,
            enable_error_file=True,
        )
    else:
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

    state.logger = logging.getLogger(__name__)
    return state.logger


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
    state.shutdown_event.set()
    raise KeyboardInterrupt


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

    # Check admin privileges
    is_admin = check_admin_privileges()
    if not is_admin:
        logger.error(
            "NetWatch requires administrator/root privileges for packet capture."
        )
        print("ERROR: NetWatch requires administrator/root privileges.")
        if IS_WINDOWS:
            print("  Windows: Right-click -> 'Run as administrator'")
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

    # --reset-db: full cleanup of in-memory state and model artefacts
    if args.reset_db:
        # Clean log files FIRST (before DB init so we start fresh)
        _logs_dir = os.path.join(PROJECT_ROOT, 'logs')
        if os.path.isdir(_logs_dir):
            import shutil
            try:
                shutil.rmtree(_logs_dir)
                os.makedirs(_logs_dir, exist_ok=True)
                logger.info("Cleared logs directory: %s", _logs_dir)
            except OSError as e:
                logger.warning("Could not clear logs directory: %s", e)
        try:
            from utils.realtime_state import dashboard_state
            dashboard_state.clear()
            logger.info("In-memory dashboard state cleared")
        except Exception:
            pass
        for model_file in ('models/anomaly_model.joblib', 'models/anomaly_scaler.joblib'):
            fp = os.path.join(PROJECT_ROOT, model_file)
            if os.path.isfile(fp):
                try:
                    os.remove(fp)
                    logger.info("Removed stale model: %s", model_file)
                except OSError as e:
                    logger.warning("Could not remove %s: %s", model_file, e)
        try:
            from database.queries.stats_queries import (
                _stats_cache, _today_totals_cache, _hourly_traffic_cache,
            )
            _stats_cache.clear()
            _today_totals_cache.clear()
            _hourly_traffic_cache.clear()
            logger.info("Query caches flushed")
        except Exception:
            pass

    # Initialize connection pool
    try:
        init_pool(DATABASE_PATH, pool_size=DB_CONNECTION_POOL_SIZE)
        logger.info("Connection pool ready (size=%d)", DB_CONNECTION_POOL_SIZE)
    except Exception as e:
        logger.error("Connection pool initialization failed: %s", e)
        sys.exit(1)

    # Start packet capture (unless --no-capture)
    _own_mac = None
    if args.no_capture:
        logger.info("Packet capture skipped (--no-capture)")
        capture_started = False
    else:
        logger.info("Capture backend: Scapy + Npcap")
        capture_started = start_packet_capture()
        if capture_started:
            logger.info("Packet capture started")

            # Lock subnet to capture interface
            try:
                mode = state.interface_manager.get_current_mode()
                if mode and mode.interface.ip_address:
                    set_capture_interface(mode.interface.name)
                    set_subnet_from_ip(mode.interface.ip_address)
                    gw = getattr(mode.interface, "gateway", None)
                    set_gateway_ip(gw or "")
                    set_current_mode(mode.get_mode_name().value)
                    if gw:
                        _init_gw_mac = resolve_gateway_mac(gw)
                        if _init_gw_mac:
                            set_gateway_mac(_init_gw_mac)
                    logger.info(
                        "Device discovery locked to capture interface: %s (mode=%s, gw=%s)",
                        mode.interface.ip_address,
                        mode.get_mode_name().value,
                        gw,
                    )
                    _own_mac = getattr(mode.interface, 'mac_address', None)

                    # Set initial mode context on in-memory state
                    try:
                        from utils.realtime_state import dashboard_state
                        own_traffic = (mode.get_scope().name == "OWN_TRAFFIC_ONLY")
                        _is_hotspot_init = (mode.get_mode_name().value == "hotspot")
                        _init_gw_mac_ctx = resolve_gateway_mac(gw) if gw else ''
                        _all_host = get_all_local_macs()
                        if own_traffic and _own_mac:
                            _all_host.discard(_own_mac.upper().replace('-', ':'))
                            _all_host.discard(_own_mac.lower())
                        dashboard_state.set_mode_context(
                            our_mac=_own_mac or '',
                            gateway_mac=_init_gw_mac_ctx,
                            own_traffic_only=own_traffic,
                            host_macs=_all_host,
                            gateway_mac_exclude=own_traffic or _is_hotspot_init,
                            our_ip=mode.interface.ip_address or '',
                        )
                    except Exception:
                        pass
            except Exception as e:
                logger.warning("Could not lock subnet to capture interface: %s", e)
        else:
            logger.warning("Packet capture unavailable -- dashboard only mode")

    # Create a SINGLE AlertEngine shared by all subsystems (DI)
    alert_engine = AlertEngine()
    logger.info("AlertEngine created (shared instance)")

    # Register our own MAC as known so it won't trigger security alerts
    if _own_mac:
        alert_engine.add_known_mac(_own_mac)
    try:
        mode = state.interface_manager.get_current_mode() if state.interface_manager else None
        if mode and mode.interface.ip_address:
            alert_engine.add_known_ip(mode.interface.ip_address)
        for _lip in get_all_local_ips():
            alert_engine.add_known_ip(_lip)
        if mode:
            gw_ip = getattr(mode.interface, 'gateway', None)
            if gw_ip:
                alert_engine.add_known_ip(gw_ip)
            gw_mac = resolve_gateway_mac(gw_ip) if gw_ip else ""
            if gw_mac:
                alert_engine.add_known_mac(gw_mac)
    except Exception:
        pass

    # Wire the shared engine into the alerts package
    set_shared_engine(alert_engine)

    # Start anomaly detector
    detector_started = start_anomaly_detector(alert_engine)
    if detector_started:
        logger.info("Anomaly detector started")

    # Start system health monitor
    health_started = start_health_monitor(alert_engine)
    if health_started:
        logger.info("System health monitor started")

    # Start thread watchdog
    start_thread_watchdog()
    logger.info("Thread watchdog started")

    # Start periodic cleanup
    start_cleanup_task()
    logger.info("Periodic cleanup task started (daily at 3 AM)")

    # Start periodic device discovery
    if capture_started:
        start_discovery_task()

    # Start background hostname resolver and mDNS browser
    try:
        _start_bg_resolver()
        logger.info("Background hostname resolver started")
        if capture_started:
            # Use periodic mDNS browsing for port_mirror and ethernet modes
            # (many devices, continuously joining/leaving the network)
            _is_periodic_mdns = False
            try:
                mode = state.interface_manager.get_current_mode() if state.interface_manager else None
                if mode and mode.get_mode_name().value in ("port_mirror", "ethernet"):
                    _is_periodic_mdns = True
            except Exception:
                pass
            _start_mdns_browser(periodic=_is_periodic_mdns)
            logger.info("mDNS browser started for proactive device discovery (periodic=%s)",
                        _is_periodic_mdns)
    except Exception as e:
        logger.warning("Could not start background hostname resolver: %s", e)

    # Start Flask server
    host = args.host or FLASK_HOST
    port = args.port or FLASK_PORT
    debug = FLASK_DEBUG and not IS_PRODUCTION

    logger.info("Dashboard: http://%s:%d  -- Press Ctrl+C to stop", host, port)

    state.app = create_app()

    # Expose InterfaceManager & CaptureEngine to Flask routes
    expose_engine_to_routes()

    try:
        if debug:
            logger.info("Starting Flask dev server (debug mode)")
            state.app.run(
                host=host,
                port=port,
                debug=True,
                use_reloader=False,
                threaded=True
            )
        else:
            try:
                from waitress import serve as waitress_serve
                logger.info("Starting Waitress production server")
                waitress_serve(
                    state.app,
                    host=host,
                    port=port,
                    threads=WAITRESS_THREADS,
                    channel_timeout=120,
                    cleanup_interval=30,
                    _quiet=True,
                )
            except ImportError:
                logger.warning(
                    "waitress not installed -- falling back to Flask dev server. "
                    "Install with: pip install waitress"
                )
                state.app.run(
                    host=host,
                    port=port,
                    debug=False,
                    use_reloader=False,
                    threaded=True
                )
    except Exception as e:
        logger.error("Flask server error: %s", e)
    finally:
        state.shutdown_event.set()
        shutdown()


# atexit guard -- ensures shutdown() runs exactly once regardless of how
# the process exits.  The shutdown_lock inside shutdown() prevents
# duplicate work if the finally block already ran.
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
        if state.logger:
            state.logger.error("Fatal error: %s", e, exc_info=True)
        else:
            print(f"Fatal error: {e}")
        sys.exit(1)
