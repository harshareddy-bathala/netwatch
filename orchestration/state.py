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
from collections import deque

# Global shutdown event -- checked by all background threads and SSE loops
shutdown_event = threading.Event()

# ---- Core singletons --------------------------------------------------------

interface_manager = None     # InterfaceManager instance
capture_engine = None        # CaptureEngine instance
detector = None              # AnomalyDetector instance
health_monitor = None        # HealthMonitor instance
flow_normalizer = None       # intelligence.flow_normalizer.FlowNormalizer
twin_builder = None          # intelligence.twin.TwinBuilder
behavior_analyzer = None     # intelligence.behavior.BehaviorAnalyzer
threat_detector = None       # intelligence.threats.ThreatDetector
vpn_detector = None          # intelligence.vpn_detector.VpnDetector
incident_manager = None      # intelligence.incidents.IncidentManager
dns_blocker = None           # packet_capture.dns_blocker.DNSBlocker

app = None                   # Flask application instance
logger = None                # Root application logger

# ---- Synchronization --------------------------------------------------------

engine_lock = threading.Lock()          # protects capture_engine mutations
mode_transition_lock = threading.Lock() # held during mode transitions;
                                        # DB writer skips writes while held

# Human-readable transition phase for packet-path tagging.
# Values are short labels like "STABLE", "EXITING_HOTSPOT",
# "ENTERING_PUBLIC_NETWORK".
mode_transition_phase = "STABLE"
mode_transition_phase_lock = threading.Lock()

# Monotonic generation id for accepted mode transitions.
# Background workers can drop stale writes when the generation changes
# mid-iteration (e.g. discovery still scanning old mode/subnet).
mode_generation = 0
mode_generation_lock = threading.Lock()

# Recent mode transition events for runtime health/baseline diagnostics.
# Items: {"timestamp": float, "old_mode": str, "new_mode": str}
mode_transition_events = deque(maxlen=4096)
mode_transition_events_lock = threading.Lock()

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
