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
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Phase 5: mode-transition lock — when held, DB writes are skipped
        # and the batch is re-queued to avoid writing against the wrong subnet.
        self._mode_transition_lock = mode_transition_lock

        # Shared stats counters (caller provides references)
        self._stats_lock = stats_lock or threading.Lock()
        self.packets_written = 0
        self.batches_written = 0
        self.db_errors = 0

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
        """Signal the writer to finish pending work and exit."""
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
        """
        if not packet_dicts:
            return
        try:
            self._queue.put_nowait(packet_dicts)
        except queue.Full:
            logger.warning(
                "DatabaseWriter queue full — dropping batch of %d packets",
                len(packet_dicts),
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
            except Exception as exc:
                with self._stats_lock:
                    self.db_errors += 1
                logger.error("DatabaseWriter batch write failed: %s", exc)

        logger.info("DatabaseWriter thread exited")
