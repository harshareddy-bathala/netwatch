"""
orchestration/shutdown.py - Graceful Shutdown Sequence
=======================================================

Protected by ``state.shutdown_lock`` so only the first caller runs the
teardown sequence.  A 30-second watchdog forces ``os._exit(1)`` if any
step hangs (e.g. a blocking ``join()`` on a stuck thread).
"""

import logging
import os
import threading
import time

from orchestration import state


def shutdown():
    """Graceful shutdown of all services."""
    with state.shutdown_lock:
        if state.shutting_down:
            return
        state.shutting_down = True

    logger = state.logger or logging.getLogger(__name__)
    logger.info("Shutting down...")

    # Only spawn the watchdog if there's actually something to shut down.
    # During tests, shutdown() is called at atexit with nothing initialised,
    # and the watchdog's os._exit(1) would kill the pytest process.
    _has_work = any([
        state.capture_engine, state.interface_manager,
        state.detector, state.health_monitor,
    ])
    if _has_work:
        def _watchdog():
            """Force-exit if shutdown hangs for longer than 30 seconds."""
            time.sleep(30)
            # Log which threads are still alive before forcing exit
            alive = [t.name for t in threading.enumerate() if t.is_alive()]
            logger.error("Shutdown watchdog triggered -- hanging threads: %s", alive)
            try:
                logging.shutdown()  # flush log handlers
            except Exception:
                pass
            os._exit(1)

        wd = threading.Thread(target=_watchdog, name="ShutdownWatchdog", daemon=True)
        wd.start()

    if state.capture_engine:
        try:
            state.capture_engine.stop()
            logger.info("Capture engine stopped")
        except Exception as e:
            logger.error("Error stopping capture engine: %s", e)

    # Shut down hostname resolver (ThreadPoolExecutor + background thread)
    try:
        from packet_capture.hostname_resolver import close_resolver
        close_resolver()
        logger.info("Hostname resolver stopped")
    except Exception as e:
        logger.error("Error stopping hostname resolver: %s", e)

    if state.interface_manager:
        try:
            state.interface_manager.stop_monitoring()
            logger.info("Interface manager stopped")
        except Exception as e:
            logger.error("Error stopping interface manager: %s", e)

    # Stop any running NetworkDiscovery
    with state.cached_discovery_lock:
        disc = state.cached_discovery
        state.cached_discovery = None
    if disc is not None:
        try:
            disc.stop_continuous_discovery()
        except Exception:
            pass

    if state.detector:
        try:
            state.detector.stop()
            logger.info("Anomaly detector stopped")
        except Exception as e:
            logger.error("Error stopping anomaly detector: %s", e)

    if state.health_monitor:
        try:
            state.health_monitor.stop()
            logger.info("Health monitor stopped")
        except Exception as e:
            logger.error("Error stopping health monitor: %s", e)

    try:
        from database.connection import shutdown_pool
        shutdown_pool()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error("Error closing database pool: %s", e)

    logger.info("Shutdown complete")

    # Force-exit immediately if all components are stopped.  Waitress may
    # have lingering worker threads that keep the process alive.
    if _has_work:
        os._exit(0)
