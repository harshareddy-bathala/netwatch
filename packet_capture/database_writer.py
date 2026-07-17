"""
database_writer.py - Async Database Writer Thread (Phase 3)
=============================================================

Decouples DB writes from the packet-processing hot path.  The processor
thread feeds ``BandwidthCalculator`` and enqueues batches to
``DatabaseWriter``, which drains them in its own thread using bulk
``executemany`` transactions instead of per-packet INSERT loops.

This eliminates the "DB write blocks processor" root cause of bandwidth
spikes: while the writer thread is committing to SQLite, the processor
thread continues to parse packets and feed the bandwidth calculator
without stalling.

Thread model::

    Processor thread          DatabaseWriter thread
    ────────────────          ─────────────────────
      ┌─ feed bandwidth ─┐
      ├─ fire callbacks   │     ┌─ dequeue batch ─┐
      └─ enqueue(batch) ──┼───► ├─ bulk INSERT    │
                           │     ├─ device UPSERT  │
                           │     └─ commit         │
                           │
"""

import logging
import queue
import threading
import time
from typing import Optional, List

from utils.realtime_state import dashboard_state

# Phase 0 (AI-first): event bus — publish normalized packet batches so
# intelligence consumers (flow normalizer, twin, detectors) can subscribe
# without polling SQLite.  The bus never blocks the writer thread.
try:
    from intelligence.event_bus import event_bus
except ImportError:
    event_bus = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _is_transition_packet(packet: dict) -> bool:
    """Return True when packet was captured during mode transition."""
    if not packet:
        return False
    phase = str(packet.get("transition_phase") or "").strip().upper()
    return bool(packet.get("is_transition_packet") or (phase not in ("", "STABLE")))


class DatabaseWriter:
    """
    Background writer thread that drains a packet-batch queue and writes
    to the database using ``save_packets_batch()``.

    Usage::

        writer = DatabaseWriter()
        writer.start()

        # From the processor thread:
        writer.enqueue(list_of_packet_dicts)

        # On shutdown:
        writer.stop()
    """

    def __init__(
        self,
        max_queue_size: int = 200,
        stats_lock: Optional[threading.Lock] = None,
        mode_transition_lock: Optional[threading.Lock] = None,
    ):
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._max_queue_size = max_queue_size
        self._stop_event = threading.Event()
        self._stopped = False  # idempotent stop guard
        self._thread: Optional[threading.Thread] = None

        # Phase 5: mode-transition lock — when held, DB writes pause until
        # shared mode/subnet state is stable.
        self._mode_transition_lock = mode_transition_lock

        # Shared stats counters (caller provides references)
        self._stats_lock = stats_lock or threading.Lock()
        self.packets_written = 0
        self.batches_written = 0
        self.db_errors = 0
        self.batches_dropped = 0

        # Phase 3: write queue overflow thresholds
        try:
            from config import WRITE_QUEUE_WARNING_PERCENT, WRITE_QUEUE_CRITICAL_PERCENT
            self._warning_threshold = max_queue_size * WRITE_QUEUE_WARNING_PERCENT / 100
            self._critical_threshold = max_queue_size * WRITE_QUEUE_CRITICAL_PERCENT / 100
        except ImportError:
            self._warning_threshold = max_queue_size * 0.8
            self._critical_threshold = max_queue_size * 0.95
        self._last_warning_time = 0.0

        # Import save_packets_batch lazily to avoid circular imports
        self._save_fn = None

    def _get_save_fn(self):
        if self._save_fn is None:
            try:
                from database.db_handler import save_packets_batch
                self._save_fn = save_packets_batch
            except ImportError:
                self._save_fn = None
        return self._save_fn

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Launch the writer thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"DatabaseWriter-{id(self):x}",
            daemon=True,
        )
        self._thread.start()
        logger.info("DatabaseWriter thread started (%s)", self._thread.name)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the writer to finish pending work and exit.

        Idempotent — safe to call multiple times (e.g. from both
        CaptureEngine.stop() and the shutdown sequence).
        """
        if self._stopped:
            return
        self._stopped = True
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info(
            "DatabaseWriter stopped — written=%d batches=%d errors=%d",
            self.packets_written, self.batches_written, self.db_errors,
        )

    def enqueue(self, packet_dicts: List[dict]) -> None:
        """
        Add a batch of packet dicts to the write queue.

        If the queue is full the batch is dropped and a warning logged.
        This ensures the processor thread is never blocked by DB I/O.

        Phase 3: monitors queue fill level and logs warnings at 80%/95%.
        """
        if not packet_dicts:
            return

        # Phase 3: queue fill monitoring
        current_size = self._queue.qsize()
        now = time.time()
        if current_size >= self._critical_threshold:
            if now - self._last_warning_time > 30:  # throttle: once per 30s
                logger.warning(
                    "DatabaseWriter queue at %d%% (%d/%d) — "
                    "DB writes cannot keep up with packet rate",
                    int(current_size / self._max_queue_size * 100),
                    current_size, self._max_queue_size,
                )
                self._last_warning_time = now
        elif current_size >= self._warning_threshold:
            if now - self._last_warning_time > 60:  # throttle: once per 60s
                logger.info(
                    "DatabaseWriter queue at %d%% (%d/%d)",
                    int(current_size / self._max_queue_size * 100),
                    current_size, self._max_queue_size,
                )
                self._last_warning_time = now

        try:
            self._queue.put_nowait(packet_dicts)
        except queue.Full:
            self.batches_dropped += 1
            logger.warning(
                "DatabaseWriter queue full — dropping batch of %d packets "
                "(total dropped: %d)",
                len(packet_dicts), self.batches_dropped,
            )

    @property
    def pending(self) -> int:
        """Number of batches waiting to be written."""
        return self._queue.qsize()

    # ------------------------------------------------------------------ #
    #  Writer thread
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        """Drain the queue and write batches to the database."""
        save_fn = self._get_save_fn()
        if save_fn is None:
            logger.warning("DatabaseWriter: save_packets_batch not available — exiting")
            return

        _MAX_RETRIES = 3
        _RETRY_DELAYS = (0.1, 0.3, 0.8)  # seconds — escalating back-off

        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                batch = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            # Phase 5: pause DB writes while mode transition mutation is in
            # progress.  Do not re-queue the batch (which can reorder work
            # and cause old-mode writes after transition); keep ownership of
            # this batch until lock release or shutdown.
            if self._mode_transition_lock is not None:
                while self._mode_transition_lock.locked():
                    if self._stop_event.is_set():
                        logger.debug(
                            "DatabaseWriter: dropping batch of %d packets "
                            "during shutdown while mode transition is locked",
                            len(batch),
                        )
                        batch = None
                        break
                    time.sleep(0.05)

            if batch is None:
                continue

            # Attempt the write with retry-on-lock for transient contention.
            written = False
            for attempt in range(_MAX_RETRIES):
                try:
                    count = save_fn(batch)
                    if count is None or count < 0:
                        raise RuntimeError("save_packets_batch reported failure")
                    with self._stats_lock:
                        self.packets_written += count
                        self.batches_written += 1
                    # Feed in-memory realtime state only when rows were
                    # actually persisted. This prevents dashboard/device
                    # drift when DB writes fail under lock contention.
                    if count > 0:
                        try:
                            dashboard_batch = [p for p in batch if not _is_transition_packet(p)]
                            # Dashboard/usage counters must exclude transition
                            # traffic. The event bus must NOT: the flow
                            # normalizer derives DNS/SNI activity from it, and
                            # dropping transition packets meant the first
                            # seconds after a hotspot switch produced no
                            # activity rows. The twin has its own mode-reset +
                            # subnet guard, so publishing the full batch is safe.
                            if dashboard_batch:
                                dashboard_state.update_from_batch(dashboard_batch)
                            if event_bus is not None and batch:
                                event_bus.publish("packet.batch", batch)
                        except Exception as exc2:
                            logger.debug("DatabaseWriter: state update error: %s", exc2)
                    else:
                        logger.debug(
                            "DatabaseWriter: save_packets_batch wrote 0/%d rows; "
                            "skipping realtime state update",
                            len(batch),
                        )
                    transition_count = sum(1 for p in batch if _is_transition_packet(p))
                    logger.debug(
                        "DatabaseWriter: wrote %d/%d packets%s",
                        count,
                        len(batch),
                        (
                            f" (transition={transition_count})"
                            if transition_count
                            else ""
                        ),
                    )
                    written = True
                    break  # success — exit retry loop
                except Exception as exc:
                    import sqlite3 as _sqlite3
                    is_lock_error = isinstance(exc, _sqlite3.OperationalError) and "locked" in str(exc).lower()
                    if is_lock_error and attempt < _MAX_RETRIES - 1:
                        delay = _RETRY_DELAYS[attempt]
                        logger.debug(
                            "DatabaseWriter: DB locked (attempt %d/%d), retrying in %.1fs",
                            attempt + 1, _MAX_RETRIES, delay,
                        )
                        time.sleep(delay)
                        continue  # retry
                    # Non-lock error or final attempt — give up on this batch
                    with self._stats_lock:
                        self.db_errors += 1
                    logger.error("DatabaseWriter batch write failed: %s", exc)
                    break

        logger.info("DatabaseWriter thread exited (%s)", threading.current_thread().name)
