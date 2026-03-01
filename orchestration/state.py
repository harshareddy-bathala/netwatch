"""
orchestration/state.py - Shared Application State Registry
============================================================

Central registry for all runtime singletons and synchronization primitives.
Other orchestration modules access state via::

    from orchestration import state

    state.capture_engine = new_engine

This module intentionally has NO imports from other project modules
to avoid circular dependencies.
"""

import threading

# Global shutdown event -- checked by all background threads and SSE loops
shutdown_event = threading.Event()

# ---- Core singletons --------------------------------------------------------

interface_manager = None     # InterfaceManager instance
capture_engine = None        # CaptureEngine instance
detector = None              # AnomalyDetector instance
health_monitor = None        # HealthMonitor instance

app = None                   # Flask application instance
logger = None                # Root application logger

# ---- Synchronization --------------------------------------------------------

engine_lock = threading.Lock()          # protects capture_engine mutations
mode_transition_lock = threading.Lock() # held during mode transitions;
                                        # DB writer skips writes while held

# ---- Background thread references -------------------------------------------

detector_thread = None
cleanup_thread = None
discovery_thread = None

# ---- Discovery singleton -----------------------------------------------------

cached_discovery = None
cached_discovery_lock = threading.Lock()

# ---- Shutdown guard ----------------------------------------------------------

shutting_down = False
shutdown_lock = threading.Lock()
