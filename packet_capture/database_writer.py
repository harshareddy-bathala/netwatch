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

logger = logging.getLogger(__name__)


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

        # Phase 5: mode-transition lock — when held, DB writes are skipped
        # and the batch is re-queued to avoid writing against the wrong subnet.
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
            name="DatabaseWriter",
            daemon=True,
        )
        self._thread.start()
        logger.info("DatabaseWriter thread started")

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

            # Phase 5: if mode transition is in progress, skip the DB write
            # and re-queue the batch so it isn't written against the stale
            # subnet.  The batch will be retried on the next iteration
            # (after the lock is released and new subnet is configured).
            if self._mode_transition_lock is not None:
                if self._mode_transition_lock.locked():
                    try:
                        self._queue.put_nowait(batch)
                    except queue.Full:
                        logger.warning(
                            "DatabaseWriter: dropping batch of %d packets "
                            "during mode transition (queue full)",
                            len(batch),
                        )
                    continue

            # Attempt the write with retry-on-lock for transient contention.
            written = False
            for attempt in range(_MAX_RETRIES):
                try:
                    count = save_fn(batch)
                    with self._stats_lock:
                        self.packets_written += count
                        self.batches_written += 1
                    # Phase 4: feed in-memory dashboard state after successful write
                    try:
                        dashboard_state.update_from_batch(batch)
                    except Exception as exc2:
                        logger.debug("DatabaseWriter: state update error: %s", exc2)
                    logger.debug(
                        "DatabaseWriter: wrote %d/%d packets", count, len(batch),
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

        logger.info("DatabaseWriter thread exited")
