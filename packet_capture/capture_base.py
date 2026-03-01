"""
capture_base.py - Shared Capture Engine Infrastructure
=======================================================

Provides the processor-thread, batch-flushing, rate-limiting,
stats-tracking, and callback-dispatching logic for the
Scapy-based ``CaptureEngine``.
"""

import logging
import queue
import threading
import time
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

# Project imports
import os, sys
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from config import (
        BATCH_SIZE,
        BATCH_TIMEOUT,
        MAX_PACKETS_PER_SECOND,
        PACKET_SAMPLE_RATE,
    )
except ImportError:
    # Fallbacks MUST match the values in config.py to avoid silent misbehaviour
    BATCH_SIZE = 1000              # config.py default: 1000
    BATCH_TIMEOUT = 0.5            # config.py default: 0.5
    MAX_PACKETS_PER_SECOND = 0     # config.py default: 0 (unlimited)
    PACKET_SAMPLE_RATE = 1         # config.py default: 1 (every packet)

from .packet_processor import PacketData

try:
    from database.db_handler import save_packets_batch
except ImportError:
    save_packets_batch = None  # type: ignore[assignment]

# Type alias for packet callbacks
PacketCallback = Callable[[PacketData], None]


class CaptureProcessorMixin:
    """
    Mixin providing the shared processor-thread logic for capture engines.

    Subclasses must set the following attributes before calling any mixin
    method:

    * ``self._packet_queue``  — ``queue.Queue``
    * ``self._stop_event``    — ``threading.Event``
    * ``self.bandwidth``      — ``BandwidthCalculator``
    * ``self._callbacks``     — ``List[PacketCallback]``
    * ``self._batch_size``    — ``int``
    * ``self._batch_timeout`` — ``float``
    * ``self._stats_lock``    — ``threading.Lock``
    * ``self._packets_processed`` — ``int``
    * ``self._batches_written``   — ``int``
    * ``self._db_errors``         — ``int``
    * ``self._max_pps``           — ``int``
    * ``self._sample_rate``       — ``int``
    """

    # -- Rate-limiting state (initialized by subclass __init__) --
    _pps_counter: int = 0
    _pps_second: int = 0
    _sample_counter: int = 0
    _packets_captured: int = 0
    _packets_dropped: int = 0

    # ------------------------------------------------------------------ #
    #  Rate limiting  (used by both capture-thread enqueue paths)
    # ------------------------------------------------------------------ #

    def _should_accept_packet(self) -> bool:
        """
        Apply sampling and per-second rate limiting.

        Returns ``True`` if the packet should be enqueued for processing,
        ``False`` if it should be silently dropped.
        """
        # Sampling: only process 1 in every N packets
        self._sample_counter += 1
        if self._sample_rate > 1 and (self._sample_counter % self._sample_rate) != 0:
            return False

        # Per-second rate limit
        if self._max_pps > 0:
            now_sec = int(time.monotonic())
            if now_sec != self._pps_second:
                self._pps_second = now_sec
                self._pps_counter = 0
            if self._pps_counter >= self._max_pps:
                return False
            self._pps_counter += 1

        return True

    # ------------------------------------------------------------------ #
    #  Stats helper
    # ------------------------------------------------------------------ #

    def _build_stats_dict(self, **extra) -> dict:
        """Build the standard stats dict shared by both engines."""
        uptime = time.monotonic() - self._start_time if self._start_time else 0
        with self._stats_lock:
            stats = {
                "running": self.is_running,
                "uptime_seconds": round(uptime, 1),
                "interface": self._interface,
                "mode": self._mode.get_mode_name().value,
                "bpf_filter": self._filter_mgr.get_validated_filter(),
                "promiscuous": self._mode.should_use_promiscuous(),
                "packets_captured": self._packets_captured,
                "packets_processed": self._packets_processed,
                "packets_dropped": self._packets_dropped,
                "batches_written": self._batches_written,
                "db_errors": self._db_errors,
                "queue_size": self._packet_queue.qsize(),
                "bandwidth": self.bandwidth.get_stats(),
            }
            stats.update(extra)
            return stats

    # ------------------------------------------------------------------ #
    #  Processor thread
    # ------------------------------------------------------------------ #

    def _run_process_loop(self, *, pre_process: bool = True) -> None:
        """
        Drain the packet queue in batches, optionally process through
        ``PacketProcessor``, feed ``BandwidthCalculator``, fire callbacks,
        and write to the database.

        Args:
            pre_process: If ``True``, raw packets are first
                run through ``self._processor.process_batch()``.
                If ``False``, items in the queue are already
                ``PacketData`` objects.
        """
        logger.info("Processor thread started")
        batch: list = []
        last_flush = time.monotonic()
        _stats_log_interval = 30  # seconds between stats log
        _last_stats_log = time.monotonic()
        _batches_since_log = 0

        while not self._stop_event.is_set() or not self._packet_queue.empty():
            # Bulk-drain queue into batch
            drained = 0
            while drained < self._batch_size:
                try:
                    pkt = self._packet_queue.get_nowait()
                    batch.append(pkt)
                    drained += 1
                except queue.Empty:
                    break

            # If empty, wait briefly to avoid busy-spinning
            if drained == 0:
                try:
                    pkt = self._packet_queue.get(timeout=0.05)
                    batch.append(pkt)
                except queue.Empty:
                    pass

            # Flush when batch is full or timeout reached
            now = time.monotonic()
            should_flush = (
                len(batch) >= self._batch_size
                or (batch and (now - last_flush) >= self._batch_timeout)
            )

            if should_flush:
                if pre_process and hasattr(self, '_processor'):
                    processed = self._processor.process_batch(batch)
                else:
                    processed = batch
                self._flush_processed_batch(processed)
                batch = []
                last_flush = now
                _batches_since_log += 1

                # Periodic capture stats logging for bandwidth diagnostics
                if (now - _last_stats_log) >= _stats_log_interval:
                    with self._stats_lock:
                        cap = self._packets_captured
                        proc = self._packets_processed
                        dropped = self._packets_dropped
                    elapsed = now - (self._start_time or now)
                    pps = cap / elapsed if elapsed > 0 else 0
                    # Include live bandwidth for hotspot debugging
                    bw_info = ""
                    try:
                        bw = self.bandwidth.get_stats()
                        bw_info = (
                            f", bw={bw.get('total_mbps', 0):.3f} Mbps "
                            f"(↓{bw.get('download_mbps', 0):.3f} "
                            f"↑{bw.get('upload_mbps', 0):.3f})"
                        )
                    except Exception:
                        pass
                    logger.info(
                        "Capture stats: %d captured, %d processed, "
                        "%d dropped, %.1f pps, %d batches%s",
                        cap, proc, dropped, pps, _batches_since_log,
                        bw_info,
                    )
                    _last_stats_log = now
                    _batches_since_log = 0

        # Final flush on shutdown
        if batch:
            if pre_process and hasattr(self, '_processor'):
                processed = self._processor.process_batch(batch)
            else:
                processed = batch
            self._flush_processed_batch(processed)

        logger.info("Processor thread exited")

    def _flush_processed_batch(self, processed: list) -> None:
        """
        Shared flush: feed bandwidth, fire callbacks, write to DB.

        ``processed`` is a list of ``PacketData`` objects.

        Phase 3 change: DB writes are now enqueued to the ``DatabaseWriter``
        background thread instead of running synchronously.  This ensures
        the processor thread is never blocked by SQLite I/O.
        """
        if not processed:
            return

        # Feed BandwidthCalculator
        for pd in processed:
            self.bandwidth.add_bytes(pd.bytes, pd.direction)

        # Record source MACs for port-mirror detection heuristic
        if hasattr(self, '_recent_src_macs_lock'):
            macs = [pd.source_mac for pd in processed if pd.source_mac]
            if macs:
                with self._recent_src_macs_lock:
                    self._recent_src_macs.extend(macs)
                    if len(self._recent_src_macs) > self._MAX_RECENT_MACS:
                        self._recent_src_macs = self._recent_src_macs[-self._MAX_RECENT_MACS:]

        # Fire registered callbacks
        for pd in processed:
            for cb in self._callbacks:
                try:
                    cb(pd)
                except Exception:
                    logger.debug("Error in packet callback", exc_info=True)

        # Phase 3: Enqueue batch to DatabaseWriter (non-blocking)
        if hasattr(self, '_db_writer') and self._db_writer is not None:
            dicts = [pd.to_dict() for pd in processed]
            self._db_writer.enqueue(dicts)
            with self._stats_lock:
                self._packets_processed += len(processed)
                self._batches_written += 1
        elif save_packets_batch is not None:
            # Fallback: synchronous write (legacy path)
            try:
                dicts = [pd.to_dict() for pd in processed]
                count = save_packets_batch(dicts)
                with self._stats_lock:
                    self._packets_processed += len(processed)
                    self._batches_written += 1
                logger.debug(
                    "Batch write: %d/%d packets saved", count, len(dicts)
                )
            except Exception as exc:
                with self._stats_lock:
                    self._db_errors += 1
                logger.error("Database batch write failed: %s", exc)
        else:
            with self._stats_lock:
                self._packets_processed += len(processed)
