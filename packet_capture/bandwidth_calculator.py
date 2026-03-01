"""
bandwidth_calculator.py - Real-Time Bandwidth Tracking
=======================================================

Tracks bytes transferred in a **sliding window** (default 30 seconds) and
calculates current upload / download rates with thread-safe access.

All public rate methods use **raw byte sums** — every byte within the window
counts equally, matching the chart bucket values exactly.

Thread safety:
    All public methods acquire ``_lock`` before touching the internal deque.
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional

logger = logging.getLogger(__name__)

# Import config with safe defaults
try:
    import os, sys
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)
    from config import BANDWIDTH_WINDOW_SECONDS
except ImportError:
    BANDWIDTH_WINDOW_SECONDS = 30

# Prune extension factor — records older than window * this factor are removed.
# Set to 1.0 so that running sums only include data within the exact window.
# Previously 1.5, which overcounted bandwidth by ~33% (15s of data / 10s window)
# and caused phantom usage when clients were idle.
_EXTENDED_FACTOR = 1.0


@dataclass(frozen=True)
class ByteRecord:
    """Single timestamped record of bytes transferred."""
    timestamp: float        # time.monotonic()
    byte_count: int
    direction: str          # 'upload', 'download', or 'other'


class BandwidthCalculator:
    """
    Sliding-window bandwidth calculator with per-direction tracking
    and smooth exponential decay (Phase 3).

    Usage::

        bw = BandwidthCalculator(window_seconds=30)

        # Called from the packet-processing thread:
        bw.add_bytes(1500, 'download')
        bw.add_bytes(64, 'upload')

        # Called from anywhere (thread-safe):
        print(bw.get_current_mbps())       # e.g. 24.3
        print(bw.get_upload_bps())         # e.g. 512000
        print(bw.get_download_bps())       # e.g. 3_000_000
    """

    def __init__(self, window_seconds: Optional[int] = None):
        self._window = window_seconds if window_seconds is not None else BANDWIDTH_WINDOW_SECONDS
        self._records: Deque[ByteRecord] = deque()
        self._lock = threading.Lock()
        # Running sums — O(1) queries instead of iterating entire deque
        self._running_total: int = 0
        self._running_upload: int = 0
        self._running_download: int = 0

    def _count_in_window(self, now: float) -> int:
        """Count records within the actual window (not the extended prune window).

        Must be called while ``_lock`` is held.
        """
        cutoff = now - self._window
        count = 0
        for rec in self._records:
            if rec.timestamp >= cutoff:
                count += 1
        return count

    # ------------------------------------------------------------------ #
    #  Public API — recording
    # ------------------------------------------------------------------ #

    def add_bytes(self, byte_count: int, direction: str = "other") -> None:
        """
        Record ``byte_count`` bytes transferred in the given ``direction``.
        """
        if byte_count <= 0:
            return

        now = time.monotonic()
        record = ByteRecord(timestamp=now, byte_count=byte_count, direction=direction)

        with self._lock:
            self._records.append(record)
            # Update running sums
            self._running_total += byte_count
            if direction == "upload":
                self._running_upload += byte_count
            elif direction == "download":
                self._running_download += byte_count
            self._prune(now)

    # ------------------------------------------------------------------ #
    #  Public API — querying
    # ------------------------------------------------------------------ #

    def _raw_sums(self, now: float):
        """Return (total, upload, download) raw byte sums from running counters.

        O(1) operation using pre-maintained running sums instead of
        iterating the entire deque.  Sums match the exact window because
        prune uses a 1.0x factor (no extended window).
        """
        return self._running_total, self._running_upload, self._running_download

    def get_current_bps(self) -> float:
        """Return total bytes per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            total, _, _ = self._raw_sums(now)
            return total / self._window if self._window else 0.0

    def get_current_mbps(self) -> float:
        """Return total megabits per second (Mbps)."""
        return (self.get_current_bps() * 8) / 1_000_000

    def get_upload_bps(self) -> float:
        """Return upload bytes per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            _, upload, _ = self._raw_sums(now)
            return upload / self._window if self._window else 0.0

    def get_download_bps(self) -> float:
        """Return download bytes per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            _, _, download = self._raw_sums(now)
            return download / self._window if self._window else 0.0

    def get_upload_mbps(self) -> float:
        """Return upload megabits per second."""
        return (self.get_upload_bps() * 8) / 1_000_000

    def get_download_mbps(self) -> float:
        """Return download megabits per second."""
        return (self.get_download_bps() * 8) / 1_000_000

    def get_packet_rate(self) -> float:
        """Return packets per second over the sliding window.

        Counts records within the actual window (not the extended prune
        window) so that PPS matches the user-visible time range.
        """
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            return self._count_in_window(now) / self._window if self._window else 0.0

    def get_recent_rate(self, seconds: int = 5) -> dict:
        """Return upload/download/total rates for only the last *seconds*.

        Unlike ``get_stats()`` which averages over the full 30 s window,
        this method only considers bytes in the most recent *seconds* and
        divides by that interval.  This produces a rate that matches the
        latest chart bucket — eliminating the card-vs-chart mismatch
        where the card showed 2 Mbps while the chart peak showed 6 Mbps.

        Thread-safe: acquires ``_lock``.
        """
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            cutoff = now - seconds
            total = upload = download = 0
            for rec in reversed(self._records):
                if rec.timestamp < cutoff:
                    break
                total += rec.byte_count
                if rec.direction == "upload":
                    upload += rec.byte_count
                elif rec.direction == "download":
                    download += rec.byte_count
            divisor = seconds if seconds else 1
            total_bps = total / divisor
            upload_bps = upload / divisor
            download_bps = download / divisor
        return {
            "total_bps": round(total_bps, 2),
            "total_mbps": round((total_bps * 8) / 1_000_000, 4),
            "upload_bps": round(upload_bps, 2),
            "upload_mbps": round((upload_bps * 8) / 1_000_000, 4),
            "download_bps": round(download_bps, 2),
            "download_mbps": round((download_bps * 8) / 1_000_000, 4),
        }

    def get_stats(self) -> dict:
        """
        Return a snapshot of current bandwidth statistics.

        Useful for the REST API and the frontend dashboard.
        """
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            total, upload, download = self._raw_sums(now)
            total_bps = total / self._window if self._window else 0.0
            upload_bps = upload / self._window if self._window else 0.0
            download_bps = download / self._window if self._window else 0.0
            pps = self._count_in_window(now) / self._window if self._window else 0.0

        return {
            "total_bps": round(total_bps, 2),
            "total_mbps": round((total_bps * 8) / 1_000_000, 4),
            "upload_bps": round(upload_bps, 2),
            "upload_mbps": round((upload_bps * 8) / 1_000_000, 4),
            "download_bps": round(download_bps, 2),
            "download_mbps": round((download_bps * 8) / 1_000_000, 4),
            "packets_per_second": round(pps, 2),
            "window_seconds": self._window,
            "records_in_window": len(self._records),
        }

    def reset(self) -> None:
        """Clear all recorded data."""
        with self._lock:
            self._records.clear()
            self._running_total = 0
            self._running_upload = 0
            self._running_download = 0

    def get_recent_history(self, bucket_seconds: int = 2, max_points: int = 30) -> list:
        """
        Return per-bucket bandwidth data points from the sliding window.

        This provides **real-time chart data** directly from in-memory
        records, without touching the database.  The frontend can merge
        these data points with the DB-fetched history for a seamless
        real-time chart experience.

        Args:
            bucket_seconds: Size of each time bucket (default 2s).
            max_points:     Maximum number of data points to return.

        Returns:
            List of dicts with ``timestamp``, ``download_mbps``,
            ``upload_mbps``, ``total_mbps`` fields — same shape as
            ``get_bandwidth_history_dual()`` output.
        """
        from datetime import datetime as _dt, timedelta

        now = time.monotonic()
        wall_now = _dt.now()

        with self._lock:
            self._prune(now)
            if not self._records:
                return []

            # Build buckets from the sliding window records.
            # Use RAW byte counts (no decay weighting) so that each
            # bucket accurately represents the bytes transferred in its
            # fixed time interval.  Decay is appropriate for the
            # instantaneous-rate API (get_current_bps) but causes
            # "wave" artefacts in the chart when the same bucket shrinks
            # on subsequent SSE pushes as records age.
            buckets: dict = {}
            window_limit = self._window  # Only include records within the actual window
            for rec in self._records:
                age = now - rec.timestamp
                if age > window_limit:
                    continue  # Skip records outside the measurement window
                bucket_idx = int(age / bucket_seconds)
                if bucket_idx not in buckets:
                    buckets[bucket_idx] = {"dl": 0.0, "ul": 0.0, "total": 0.0}
                buckets[bucket_idx]["total"] += rec.byte_count
                if rec.direction == "download":
                    buckets[bucket_idx]["dl"] += rec.byte_count
                elif rec.direction == "upload":
                    buckets[bucket_idx]["ul"] += rec.byte_count

        if not buckets:
            return []

        # Convert to list, sorted newest-first then reversed
        mbps_mult = 8 / bucket_seconds / 1_000_000
        result = []
        for idx in sorted(buckets.keys()):
            if len(result) >= max_points:
                break
            b = buckets[idx]
            # Wall-clock time for this bucket
            secs_ago = idx * bucket_seconds
            ts = wall_now - timedelta(seconds=secs_ago)
            result.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "download_mbps": round(b["dl"] * mbps_mult, 3),
                "upload_mbps": round(b["ul"] * mbps_mult, 3),
                "total_mbps": round(b["total"] * mbps_mult, 3),
                "bytes_download": round(b["dl"]),
                "bytes_upload": round(b["ul"]),
                "total_bytes": round(b["total"]),
                "live": True,  # marker so frontend knows this is live data
            })

        # Sort chronologically (oldest first)
        result.sort(key=lambda d: d["timestamp"])
        return result

    # ------------------------------------------------------------------ #
    #  Private — pruning
    # ------------------------------------------------------------------ #

    def _prune(self, now: float) -> None:
        """Remove records older than the window and update running sums.

        Must be called while ``_lock`` is held.
        """
        cutoff = now - self._window * _EXTENDED_FACTOR
        while self._records and self._records[0].timestamp < cutoff:
            old = self._records.popleft()
            # Decrement running sums
            self._running_total -= old.byte_count
            if old.direction == "upload":
                self._running_upload -= old.byte_count
            elif old.direction == "download":
                self._running_download -= old.byte_count
