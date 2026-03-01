"""
capture_engine.py - Core Packet Capture Engine (Phase 2)
=========================================================

Replaces the monolithic ``monitor.py`` (1,418 lines).  This module is the
central coordinator that ties together **mode-aware BPF filtering**,
**real-time bandwidth tracking**, **batch database writes**, and **graceful
multi-threaded lifecycle management**.

Architecture overview::

    ┌──────────────┐   raw pkts    ┌───────────────┐  PacketData[]  ┌──────────┐
    │ _capture_loop│  ──────────►  │   Queue(10k)  │  ──────────►   │_process_ │
    │ (Scapy sniff)│               │               │                │  loop    │
    └──────────────┘               └───────────────┘                └──────────┘
          │                                                              │
          │  BPF filter ← FilterManager                                  │
          │  promisc   ← mode.should_use_promiscuous()                   ├─► BandwidthCalculator
          │                                                              ├─► save_packets_batch()
          │                                                              └─► callbacks
          │
          └─── runs in its own daemon thread

Thread model:
    * **Capture thread** — calls ``scapy.sniff()`` in a tight loop.  Puts
      every packet into a bounded queue.  If the queue is full (back-
      pressure), the oldest packet is silently dropped and a warning is
      logged.
    * **Processor thread** — drains the queue, builds batches of
      ``BATCH_SIZE`` (default 100), processes them through
      ``PacketProcessor``, feeds the ``BandwidthCalculator``, and writes
      to the database via ``save_packets_batch()``.

Lifecycle:
    ``start()`` → launches both threads.
    ``stop()``  → signals threads to exit, joins them with a timeout.

Integration with Phase 1:
    The engine accepts a ``BaseMode`` from the mode detector.  When the
    mode changes (via ``InterfaceManager.on_mode_change``), the caller
    should ``stop()`` the current engine and ``start()`` a new one with
    the new mode.
"""

import logging
import queue
import threading
import time
from typing import Callable, List, Optional, Any

logger = logging.getLogger(__name__)

# Scapy import
try:
    from scapy.all import sniff as scapy_sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy_sniff = None

# Project imports
import os, sys
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from config import (
        PACKET_QUEUE_SIZE,
        BATCH_SIZE,
        BATCH_TIMEOUT,
        BANDWIDTH_WINDOW_SECONDS,
        SCAPY_VERBOSE,
        MAX_PACKETS_PER_SECOND,
        PACKET_SAMPLE_RATE,
    )
except ImportError:
    PACKET_QUEUE_SIZE = 10000
    BATCH_SIZE = 100
    BATCH_TIMEOUT = 1.0
    BANDWIDTH_WINDOW_SECONDS = 10
    SCAPY_VERBOSE = 0
    MAX_PACKETS_PER_SECOND = 200
    PACKET_SAMPLE_RATE = 1

from .modes.base_mode import BaseMode
from .filter_manager import FilterManager
from .packet_processor import PacketProcessor, PacketData
from .bandwidth_calculator import BandwidthCalculator
from .capture_base import CaptureProcessorMixin, PacketCallback
from .database_writer import DatabaseWriter

# Database batch write
try:
    from database.db_handler import save_packets_batch
except ImportError:
    save_packets_batch = None  # type: ignore[assignment]


class CaptureEngine(CaptureProcessorMixin):
    """
    Mode-aware packet capture engine.

    Usage::

        from packet_capture.modes import PublicNetworkMode, InterfaceInfo

        mode = PublicNetworkMode(InterfaceInfo(name="Wi-Fi", ip_address="192.168.1.42", ...))
        engine = CaptureEngine(mode, interface="Wi-Fi")
        engine.start()

        # … later …
        print(engine.bandwidth.get_current_mbps())  # real-time Mbps

        engine.stop()
    """

    def __init__(
        self,
        mode: BaseMode,
        interface: Optional[str] = None,
        queue_size: Optional[int] = None,
        batch_size: Optional[int] = None,
        batch_timeout: Optional[float] = None,
        bandwidth_window: Optional[int] = None,
        strategy=None,
    ):
        # Mode & interface
        self._mode = mode
        self._interface = interface or mode.interface.name
        self._strategy = strategy  # optional CaptureStrategy (setup/teardown NIC)

        # Components
        self._filter_mgr = FilterManager(mode)
        self._processor = PacketProcessor(mode)
        self.bandwidth = BandwidthCalculator(
            window_seconds=bandwidth_window or BANDWIDTH_WINDOW_SECONDS,
        )

        # Configuration
        self._queue_size = queue_size or PACKET_QUEUE_SIZE
        self._batch_size = batch_size or BATCH_SIZE
        self._batch_timeout = batch_timeout or BATCH_TIMEOUT

        # Queue & threads
        self._packet_queue: queue.Queue = queue.Queue(maxsize=self._queue_size)
        self._capture_thread: Optional[threading.Thread] = None
        self._process_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Callbacks (external consumers can register to receive processed packets)
        self._callbacks: List[PacketCallback] = []

        # Statistics
        self._stats_lock = threading.Lock()
        self._packets_captured = 0
        self._packets_processed = 0
        self._packets_dropped = 0
        self._batches_written = 0
        self._db_errors = 0
        self._start_time: Optional[float] = None

        # Rate limiting — prevents NetWatch from degrading network performance
        self._max_pps = MAX_PACKETS_PER_SECOND   # 0 = unlimited
        self._sample_rate = max(1, PACKET_SAMPLE_RATE)
        self._pps_counter = 0          # packets accepted in the current second
        self._pps_second = 0           # which second we're in (int epoch)
        self._sample_counter = 0       # running counter for sampling

        # Phase 3: DatabaseWriter — async DB writes so processor never blocks
        # Phase 5: pass mode_transition_lock so writer can skip writes during
        # mode transitions.  Import from orchestration.state (clean, non-circular).
        _mtl = None
        try:
            from orchestration.state import mode_transition_lock
            _mtl = mode_transition_lock
        except (ImportError, AttributeError):
            pass

        # DB writer queue size — configurable for high-traffic modes (port_mirror)
        _db_queue_size = 200
        try:
            from config import DB_WRITER_QUEUE_SIZE
            _db_queue_size = DB_WRITER_QUEUE_SIZE
        except (ImportError, AttributeError):
            pass

        self._db_writer = DatabaseWriter(
            max_queue_size=_db_queue_size,
            stats_lock=self._stats_lock,
            mode_transition_lock=_mtl,
        )

        # Interface-loss detection — consecutive OS errors trigger callbacks
        self._consecutive_os_errors = 0
        self._MAX_CONSECUTIVE_OS_ERRORS = 5
        self._interface_lost = False
        self._interface_lost_callbacks: List[Callable] = []

        # Source MAC sampling — used by InterfaceManager to feed the mode
        # detector for port-mirror heuristic (avoids expensive Scapy probe).
        self._recent_src_macs: list = []
        self._recent_src_macs_lock = threading.Lock()
        self._MAX_RECENT_MACS = 100

    # ================================================================== #
    #  PUBLIC API
    # ================================================================== #

    def start(self) -> None:
        """Launch capture and processor threads."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed — cannot start capture")

        if self._capture_thread and self._capture_thread.is_alive():
            logger.warning("CaptureEngine already running")
            return

        # Run capture strategy setup (e.g. enable promiscuous mode at OS level)
        if self._strategy:
            try:
                self._strategy.setup()
            except Exception as exc:
                logger.warning("Strategy setup failed (continuing anyway): %s", exc)

        # Validate filter before starting
        bpf = self._filter_mgr.get_validated_filter()
        promisc = self._filter_mgr.get_promiscuous_setting()
        logger.info(
            "Starting CaptureEngine on '%s' | mode=%s | filter='%s' | promisc=%s",
            self._interface, self._mode.get_mode_name().value, bpf, promisc
        )

        self._stop_event.clear()
        self._start_time = time.monotonic()

        # Start the async DB writer thread (Phase 3)
        self._db_writer.start()

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(bpf, promisc),
            name="CaptureEngine-Capture",
            daemon=True,
        )
        self._process_thread = threading.Thread(
            target=self._process_loop,
            name="CaptureEngine-Process",
            daemon=True,
        )

        self._capture_thread.start()
        self._process_thread.start()
        logger.info("CaptureEngine threads started")

    def stop(self, timeout: float = 5.0) -> None:
        """Signal threads to stop and wait for them to finish."""
        logger.info("Stopping CaptureEngine…")
        self._stop_event.set()

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=timeout)
        if self._process_thread and self._process_thread.is_alive():
            self._process_thread.join(timeout=timeout)

        # Stop the DB writer thread (drains remaining batches)
        self._db_writer.stop(timeout=timeout)

        # Run capture strategy teardown (e.g. disable promiscuous mode)
        if self._strategy:
            try:
                self._strategy.teardown()
            except Exception as exc:
                logger.warning("Strategy teardown failed: %s", exc)

        logger.info(
            "CaptureEngine stopped — captured=%s processed=%s dropped=%s batches=%s",
            self._packets_captured, self._packets_processed,
            self._packets_dropped, self._batches_written
        )

    @property
    def is_running(self) -> bool:
        return (
            self._capture_thread is not None
            and self._capture_thread.is_alive()
        )

    def on_packet(self, callback: PacketCallback) -> None:
        """Register a callback invoked for every processed ``PacketData``."""
        self._callbacks.append(callback)

    def on_interface_lost(self, callback: Callable[[], Any]) -> None:
        """Register a callback invoked when the capture interface disappears.

        The callback is fired from the capture thread after
        ``_MAX_CONSECUTIVE_OS_ERRORS`` consecutive failures.  It should
        trigger an immediate mode re-detection (e.g. via
        ``InterfaceManager.notify_interface_lost()``).
        """
        self._interface_lost_callbacks.append(callback)

    def get_stats(self) -> dict:
        """Return engine statistics for the REST API."""
        return self._build_stats_dict(
            queue_capacity=self._queue_size,
        )

    def get_filter_summary(self) -> dict:
        """Delegate to FilterManager for filter diagnostics."""
        return self._filter_mgr.get_filter_summary()

    def get_recent_source_macs(self) -> list:
        """Return recently seen source MAC addresses for mode detection.

        Used by InterfaceManager to feed the port-mirror detection
        heuristic without requiring an expensive Scapy probe.
        """
        with self._recent_src_macs_lock:
            return list(self._recent_src_macs)

    # ================================================================== #
    #  CAPTURE THREAD
    # ================================================================== #

    def _capture_loop(self, bpf_filter: str, promisc: bool) -> None:
        """
        Run ``scapy.sniff()`` with the mode's BPF filter and promiscuous
        setting.  Each captured packet is placed into the bounded queue.

        **Critical:** The ``filter`` argument MUST come from
        ``FilterManager.get_validated_filter()``, which guarantees it is
        never empty for non-mirror modes.

        Args:
            bpf_filter: Validated BPF filter string (from start()).
            promisc: Promiscuous mode setting (from start()).
        """

        logger.info(
            "Capture thread started — iface='%s', filter='%s', promisc=%s",
            self._interface, bpf_filter, promisc
        )

        def _enqueue(pkt):
            """Put packet into queue; drop if full (back-pressure) or rate-limited.

            **Performance note:** The captured-packets counter is incremented
            without holding ``_stats_lock``.  On CPython the GIL makes simple
            integer increments thread-safe (the stat is advisory anyway), and
            removing the lock avoids contention that was throttling capture
            throughput on high-bandwidth connections (e.g. HD video streaming
            at 1000+ pps).  The lock is still used for *reads* in
            ``_build_stats_dict`` and for the rare ``_packets_dropped``
            increment where accuracy matters more than speed.
            """
            # Lock-free increment — safe under CPython GIL, advisory stat only
            self._packets_captured += 1

            # Rate limiting via shared mixin
            if not self._should_accept_packet():
                return

            # Phase 3: stamp capture time onto the packet so the processor
            # thread uses the real capture instant, not processing time.
            # Prefer Scapy's pkt.time (set by libpcap) when available;
            # fall back to time.time().
            try:
                pkt._capture_ts = float(pkt.time) if hasattr(pkt, 'time') and pkt.time else time.time()
            except Exception:
                pkt._capture_ts = time.time()

            try:
                self._packet_queue.put_nowait(pkt)
            except queue.Full:
                self._packets_dropped += 1
                # Log once per 5000 drops to avoid log flooding
                if self._packets_dropped % 5000 == 1:
                    logger.error(
                        "Packet queue full (%s) — dropped %s packets total",
                        self._queue_size, self._packets_dropped
                    )

        while not self._stop_event.is_set():
            try:
                # sniff for short bursts so we can check the stop event
                scapy_sniff(
                    iface=self._interface,
                    filter=bpf_filter if bpf_filter else None,
                    promisc=promisc,
                    store=False,
                    prn=_enqueue,
                    timeout=2,                    # yield every 2 seconds
                    count=0,                      # unlimited within burst
                )
                # Successful sniff resets the error counter
                self._consecutive_os_errors = 0
            except PermissionError:
                logger.error(
                    "Permission denied — packet capture requires admin/root privileges"
                )
                self._stop_event.set()
                break
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                self._consecutive_os_errors += 1
                logger.error("OS error in capture loop: %s", exc)
                # If the interface has been gone for several consecutive
                # attempts, stop the capture and notify listeners so the
                # InterfaceManager can switch to the correct mode.
                if self._consecutive_os_errors >= self._MAX_CONSECUTIVE_OS_ERRORS:
                    logger.error(
                        "Interface '%s' appears gone after %d consecutive errors "
                        "— stopping capture and requesting mode re-detection",
                        self._interface, self._consecutive_os_errors,
                    )
                    self._interface_lost = True
                    self._stop_event.set()
                    for cb in self._interface_lost_callbacks:
                        try:
                            cb()
                        except Exception:
                            logger.exception("Error in interface-lost callback")
                    break
                time.sleep(1)  # back off before retrying
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                logger.exception("Unexpected error in capture loop: %s", exc)
                time.sleep(1)

        logger.info("Capture thread exited")

    # ================================================================== #
    #  PROCESSOR THREAD (delegated to CaptureProcessorMixin)
    # ================================================================== #

    def _process_loop(self) -> None:
        """Delegate to shared mixin with pre_process=True for Scapy raw packets."""
        self._run_process_loop(pre_process=True)
