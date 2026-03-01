"""
interface_manager.py - Background Mode Monitoring Manager
==========================================================

Replaces the old ``InterfaceDetector`` class.  Runs a background daemon
thread that calls ``ModeDetector.detect()`` every ``MODE_REFRESH_INTERVAL``
seconds and fires registered callbacks whenever the active mode changes.

Public API:
    - ``start_monitoring()``  — launch the background thread
    - ``stop_monitoring()``   — cleanly shut down
    - ``get_current_mode()``  — return the active ``BaseMode`` instance
    - ``on_mode_change(cb)``  — register ``cb(old_mode, new_mode)``
    - ``refresh_now()``       — force an immediate re-detection

Thread safety:
    All public methods are safe to call from any thread.  Internal state
    is protected by a ``threading.Lock``.

**How do you detect when the network mode changes?**
The manager compares the ``ModeName`` returned by successive ``detect()``
calls.  If the name differs, or if the underlying interface/IP changed,
it fires every registered callback with ``(old_mode, new_mode)``.
"""

import logging
import sys
import threading
import time
from typing import Callable, List, Optional

# Import config — safe defaults if config isn't available
try:
    # Allow running from project root or from within the package
    import os
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)
    from config import (
        MODE_REFRESH_INTERVAL,
        ENABLE_AUTO_MODE_DETECTION,
        FORCE_SAFE_MODE,
    )
except ImportError:
    MODE_REFRESH_INTERVAL = 30
    ENABLE_AUTO_MODE_DETECTION = True
    FORCE_SAFE_MODE = False

from .mode_detector import ModeDetector
from .modes.base_mode import BaseMode, InterfaceInfo, ModeName
from .modes.public_network_mode import PublicNetworkMode

# Capture strategy stubs — maps each ModeName to a strategy class
from .strategies.ethernet_strategy import EthernetCaptureStrategy
from .strategies.mirror_strategy import MirrorCaptureStrategy

logger = logging.getLogger(__name__)

# Type alias for mode-change callbacks
ModeChangeCallback = Callable[[Optional[BaseMode], BaseMode], None]

# ── Mode → CaptureStrategy mapping ────────────────────────────────────────
# Each mode is associated with a capture strategy that encapsulates
# NIC setup, BPF filter compilation, and teardown logic.
# Modes without a dedicated strategy use ``None`` (default CaptureEngine
# behaviour based on the mode's own get_bpf_filter / should_use_promiscuous).

MODE_STRATEGY_MAP = {
    ModeName.ETHERNET:       EthernetCaptureStrategy,
    ModeName.PORT_MIRROR:    MirrorCaptureStrategy,
    ModeName.HOTSPOT:        None,   # uses default CaptureEngine logic
    ModeName.PUBLIC_NETWORK: None,   # uses default CaptureEngine logic
}


class InterfaceManager:
    """
    High-level manager that keeps the current network mode up-to-date.

    Usage::

        mgr = InterfaceManager()
        mgr.on_mode_change(lambda old, new: print(f"Mode changed → {new}"))
        mgr.start_monitoring()

        # … later …
        mode = mgr.get_current_mode()
        print(mode.get_bpf_filter())

        mgr.stop_monitoring()
    """

    def __init__(
        self,
        refresh_interval: Optional[int] = None,
        auto_detect: Optional[bool] = None,
        force_safe: Optional[bool] = None,
    ):
        self._detector = ModeDetector()
        self._current_mode: Optional[BaseMode] = None
        self._callbacks: List[ModeChangeCallback] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Config — allow overrides for testing
        self._refresh_interval = refresh_interval if refresh_interval is not None else MODE_REFRESH_INTERVAL
        self._auto_detect = auto_detect if auto_detect is not None else ENABLE_AUTO_MODE_DETECTION
        self._force_safe = force_safe if force_safe is not None else FORCE_SAFE_MODE

        # Stability: require the same new mode N consecutive detections
        # before actually switching.  Prevents rapid flip-flopping.
        self._stability_threshold = 2  # consecutive detections required
        self._pending_mode: Optional[BaseMode] = None
        self._pending_count = 0

        # Adaptive detection interval (Phase 4):
        # Start fast (15s) to converge quickly on the correct mode, then
        # progressively back off: 30s → 60s → 120s as the mode stays stable.
        self._startup_interval = 15
        self._stable_intervals = [30, 60, 120]  # progressive backoff
        self._stable_index = 0
        self._refresh_interval = self._startup_interval
        self._is_stable = False
        self._consecutive_stable = 0  # count of consecutive stable detections

        # Phase 4: Mode transition cooldown — prevents rapid mode flaps
        # (e.g. cable briefly disconnected and reconnected).
        self._transition_cooldown = 60  # seconds between allowed transitions
        self._last_transition_time = 0.0

    # ================================================================== #
    #  PUBLIC API
    # ================================================================== #

    def start_monitoring(self) -> None:
        """
        Launch the background monitoring thread.

        Does an immediate first detection before starting the loop so that
        ``get_current_mode()`` returns a valid mode right away.
        """
        if self._thread and self._thread.is_alive():
            logger.warning("Monitoring already running")
            return

        # Immediate first detection
        self._do_detect()

        if not self._auto_detect:
            logger.info("Auto mode detection disabled — using initial mode only")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="InterfaceManager-Monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"Interface monitoring started (interval={self._refresh_interval}s)"
        )

    def stop_monitoring(self) -> None:
        """Signal the background thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._refresh_interval + 5)
            logger.info("Interface monitoring stopped")
        self._thread = None

    def get_current_mode(self) -> BaseMode:
        """
        Return the currently active ``BaseMode`` instance.

        If monitoring hasn't been started, runs a one-shot detection.
        """
        with self._lock:
            if self._current_mode is None:
                self._do_detect()
            return self._current_mode  # type: ignore[return-value]

    def on_mode_change(self, callback: ModeChangeCallback) -> None:
        """
        Register a callback to be called when the mode changes.

        Signature: ``callback(old_mode: Optional[BaseMode], new_mode: BaseMode)``
        """
        with self._lock:
            self._callbacks.append(callback)

    def remove_callback(self, callback: ModeChangeCallback) -> None:
        """Remove a previously registered callback."""
        with self._lock:
            self._callbacks = [cb for cb in self._callbacks if cb is not callback]

    def refresh_now(self) -> BaseMode:
        """Force an immediate re-detection and return the new mode.

        Phase 5: Bypasses the stability threshold so that user-initiated
        refreshes (via ``/api/interface/refresh``) take effect immediately
        instead of requiring 2 consecutive matching detections.
        """
        from packet_capture.mode_detector import ModeDetector
        ModeDetector._mirror_probe_time = 0  # Allow immediate port-mirror probe
        with self._lock:
            saved_threshold = self._stability_threshold
            self._stability_threshold = 1
            self._pending_mode = None
            self._pending_count = 0
        try:
            self._do_detect()
        finally:
            with self._lock:
                self._stability_threshold = saved_threshold
        with self._lock:
            return self._current_mode  # type: ignore[return-value]

    def notify_interface_lost(self) -> None:
        """Called when the capture engine detects its interface has disappeared.

        Resets any pending stability counter and forces an immediate
        re-detection that bypasses the stability threshold and cooldown,
        so the system switches to the correct mode without delay.
        """
        logger.info("Interface lost notification — forcing immediate re-detection")
        from packet_capture.mode_detector import ModeDetector
        ModeDetector._mirror_probe_time = 0  # Allow immediate port-mirror probe
        with self._lock:
            self._pending_mode = None
            self._pending_count = 0
            self._last_transition_time = 0.0  # bypass cooldown
            # Temporarily set threshold to 1 so the FIRST detection is accepted
            saved_threshold = self._stability_threshold
            self._stability_threshold = 1
        try:
            self._do_detect()
        finally:
            with self._lock:
                self._stability_threshold = saved_threshold

    @property
    def is_monitoring(self) -> bool:
        """True if the background thread is running."""
        return self._thread is not None and self._thread.is_alive()

    def select_interface(self, interface_name: str) -> BaseMode:
        """
        Manually select a specific network interface for monitoring.

        Forces re-detection scoped to the named interface, updates the
        current mode, and fires mode-change callbacks so the capture
        engine restarts on the new interface.

        Args:
            interface_name: OS-level interface name (e.g. ``"Wi-Fi"``,
                ``"Ethernet"``, ``"eth0"``).

        Returns:
            The new :class:`BaseMode` for the selected interface.

        Raises:
            ValueError: If the interface is not found among active interfaces.
        """
        # Enumerate current interfaces and find a match
        interfaces = self._detector._enumerate_interfaces()
        target = None
        for iface in interfaces:
            if iface.name == interface_name or iface.friendly_name == interface_name:
                target = iface
                break

        if target is None:
            available = [i.name for i in interfaces]
            raise ValueError(
                f"Interface '{interface_name}' not found. Available: {available}"
            )

        # Detect mode specifically for this interface
        new_mode = self._detector.detect_for_interface(target)

        with self._lock:
            old_mode = self._current_mode
            self._current_mode = new_mode
            self._pending_mode = None
            self._pending_count = 0
            callbacks = list(self._callbacks)

        logger.info(
            "Manual interface selection: %s → mode=%s",
            interface_name, new_mode.get_mode_name().value,
        )

        # Fire callbacks so CaptureEngine restarts
        if old_mode is not None:
            for cb in callbacks:
                try:
                    cb(old_mode, new_mode)
                except Exception:
                    logger.exception("Error in mode-change callback during select_interface")

        return new_mode

    def get_capture_strategy(self):
        """
        Return the capture strategy instance for the current mode.

        Returns ``None`` if the mode has no dedicated strategy (the
        CaptureEngine should fall back to its default behaviour based on
        the mode's ``get_bpf_filter()`` and ``should_use_promiscuous()``).
        """
        mode = self.get_current_mode()
        strategy_cls = MODE_STRATEGY_MAP.get(mode.get_mode_name())
        if strategy_cls is not None:
            return strategy_cls(mode)
        return None

    def get_status(self) -> dict:
        """
        Return a status dict suitable for the REST API / frontend.

        Replaces the old ``InterfaceDetector.get_status()`` method.
        """
        with self._lock:
            mode = self._current_mode

        if mode is None:
            return {
                "mode": "unknown",
                "mode_display": "Detecting…",
                "description": "Mode detection not yet run",
                "is_active": False,
                "monitoring": self.is_monitoring,
                "refresh_interval": self._refresh_interval,
            }

        status = mode.to_dict()
        status["is_active"] = True
        status["monitoring"] = self.is_monitoring
        status["refresh_interval"] = self._refresh_interval
        status["force_safe_mode"] = self._force_safe

        # Add mode_display for the frontend sidebar badge
        mode_labels = {
            "hotspot": "Hotspot Mode",
            "ethernet": "Ethernet",
            "port_mirror": "Port Mirror",
            "public_network": "Public Network",
        }
        mode_name = mode.get_mode_name().value

        # Detect disconnected state: public_network fallback on a
        # virtual-only adapter (VirtualBox, VMware, …) with no gateway
        # means there is no real network connection.
        if mode_name == "public_network":
            iface = mode.interface
            is_virtual = getattr(iface, "interface_type", "") in (
                "virtual", "bluetooth", "unknown", "disconnected",
            )
            has_no_ip = not getattr(iface, "ip_address", None) or iface.ip_address == "0.0.0.0"
            has_no_gw = not getattr(iface, "gateway", None)
            iface_name = getattr(iface, "name", "")
            is_disconnected = iface_name in ("none", "unknown", "")
            if has_no_ip or is_disconnected or (is_virtual and has_no_gw):
                status["mode"] = "none"
                status["mode_display"] = "Disconnected"
                status["description"] = "No active network connection detected. Connect to a network to start monitoring."
                return status

        status["mode_display"] = mode_labels.get(mode_name, mode_name.replace("_", " ").title())

        # Expose ip_address / interface name at top level for convenience
        status.setdefault("ip_address", mode.interface.ip_address)
        status.setdefault("name", mode.interface.name)

        return status

    # ================================================================== #
    #  PRIVATE — background loop
    # ================================================================== #

    def _monitor_loop(self) -> None:
        """Background thread entry point — runs until ``_stop_event`` is set."""
        logger.debug("Monitor loop started")
        while not self._stop_event.is_set():
            # Wait for the refresh interval (or until stopped)
            if self._stop_event.wait(timeout=self._refresh_interval):
                break  # stop_event was set
            try:
                self._do_detect()
            except Exception:
                logger.exception("Error during mode detection — keeping previous mode")
        logger.debug("Monitor loop exited")

    def _do_detect(self) -> None:
        """
        Run detection and fire callbacks if the mode changed.

        Stability logic: a detected mode must appear for
        ``_stability_threshold`` consecutive cycles before it is accepted.
        This prevents rapid flip-flopping (e.g. public_network → ethernet → public_network).
        On the very first detection (``_current_mode is None``) the mode is
        accepted immediately so the system boots without delay.
        """
        if self._force_safe:
            new_mode = self._make_safe_mode()
        else:
            # Feed source MACs from the running capture engine (if available)
            # so the port-mirror heuristic can use live traffic data instead
            # of falling back to the expensive promiscuous Scapy probe.
            sample_macs = []
            try:
                from main import _capture_engine
                if _capture_engine and _capture_engine.is_running:
                    sample_macs = _capture_engine.get_recent_source_macs()
            except (ImportError, AttributeError):
                pass

            # Pass the current capture interface MAC so the port-mirror
            # check is scoped to the correct interface (avoids cross-
            # interface false positives, e.g. Wi-Fi MACs tested against
            # an Ethernet adapter's MAC).
            capture_iface_mac = None
            if self._current_mode and self._current_mode.interface.mac_address:
                capture_iface_mac = self._current_mode.interface.mac_address

            new_mode = self._detector.detect(
                sample_source_macs=sample_macs or None,
                capture_interface_mac=capture_iface_mac,
            )

        with self._lock:
            old_mode = self._current_mode

            # First detection — accept immediately
            if old_mode is None:
                self._current_mode = new_mode
                self._pending_mode = None
                self._pending_count = 0
                logger.info(
                    "Initial mode: %s", new_mode.get_mode_name().value
                )
                callbacks = list(self._callbacks)
                changed = True
            else:
                changed = False
                really_changed = self._has_mode_changed(old_mode, new_mode)

                if not really_changed:
                    # Same mode as current — reset any pending transition
                    self._pending_mode = None
                    self._pending_count = 0
                    self._consecutive_stable += 1

                    # Progressive backoff: as mode stays stable for longer,
                    # increase the detection interval to reduce overhead.
                    if not self._is_stable:
                        self._is_stable = True
                        self._stable_index = 0
                        self._consecutive_stable = 0
                    elif self._consecutive_stable >= 10 and self._stable_index < len(self._stable_intervals) - 1:
                        # After 10 consecutive stable detections at current
                        # interval, move to next slower interval
                        self._stable_index += 1
                        self._consecutive_stable = 0

                    new_interval = self._stable_intervals[min(self._stable_index, len(self._stable_intervals) - 1)]
                    if self._refresh_interval != new_interval:
                        self._refresh_interval = new_interval
                        logger.debug(
                            "Mode stable — detection interval: %ds",
                            new_interval,
                        )
                else:
                    # Different from current mode — count as pending
                    if (self._pending_mode is not None
                            and not self._has_mode_changed(self._pending_mode, new_mode)):
                        # Same as pending — increment
                        self._pending_count += 1
                    else:
                        # New pending mode — start counting
                        self._pending_mode = new_mode
                        self._pending_count = 1

                    if self._pending_count >= self._stability_threshold:
                        # Phase 4: transition cooldown check
                        now_ts = time.time()
                        cooldown_remaining = self._transition_cooldown - (now_ts - self._last_transition_time)
                        if cooldown_remaining > 0 and self._last_transition_time > 0:
                            logger.debug(
                                "Mode change suppressed by cooldown (%.0fs remaining)",
                                cooldown_remaining,
                            )
                        else:
                            # Stable: accept the new mode
                            self._current_mode = new_mode
                            self._pending_mode = None
                            self._pending_count = 0
                            self._last_transition_time = now_ts
                            changed = True
                            # Mode just changed — revert to fast detection interval
                            self._is_stable = False
                            self._stable_index = 0
                            self._consecutive_stable = 0
                            self._refresh_interval = self._startup_interval
                            logger.info(
                                "Mode change (stable): %s -> %s — detection interval reset to %ds",
                                old_mode.get_mode_name().value,
                                new_mode.get_mode_name().value,
                                self._startup_interval,
                            )
                    else:
                        logger.debug(
                            "Pending mode %s (%d/%d)",
                            new_mode.get_mode_name().value,
                            self._pending_count,
                            self._stability_threshold,
                        )
                        # Fast re-check: shorten interval to 3s so the
                        # confirmation detection happens quickly instead
                        # of waiting the full 15-30s refresh interval.
                        self._refresh_interval = 3

                callbacks = list(self._callbacks) if changed else []

        if changed and old_mode is not None:
            for cb in callbacks:
                try:
                    cb(old_mode, new_mode)
                except Exception:
                    logger.exception(f"Error in mode-change callback {cb}")

    @staticmethod
    def _has_mode_changed(old: Optional[BaseMode], new: BaseMode) -> bool:
        """Determine whether the mode has meaningfully changed."""
        if old is None:
            return True
        if old.get_mode_name() != new.get_mode_name():
            return True
        # Same mode name but different interface or IP → still a change
        if old.interface.ip_address != new.interface.ip_address:
            return True
        if old.interface.name != new.interface.name:
            return True
        # Same mode but different SSID → network changed (e.g. switched
        # from one hotspot to another).  Must reset devices/state.
        if old.interface.ssid != new.interface.ssid:
            return True
        # Same mode but gateway changed → different network segment
        if old.interface.gateway != new.interface.gateway:
            return True
        return False

    def _make_safe_mode(self) -> PublicNetworkMode:
        """Create a PublicNetworkMode for FORCE_SAFE_MODE."""
        interfaces = self._detector._enumerate_interfaces()
        for iface in interfaces:
            if iface.ip_address:
                return PublicNetworkMode(iface)
        return PublicNetworkMode(InterfaceInfo(
            name="unknown", friendly_name="No Interface",
            ip_address="0.0.0.0", is_active=False,
        ))
