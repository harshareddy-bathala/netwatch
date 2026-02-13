"""
bandwidth_calculator.py - Real-Time Bandwidth Tracking
========================================================

Tracks bytes transferred in a **sliding window** (default 10 seconds) and
calculates current upload / download rates with thread-safe access.

**Why a 10-second window instead of 60-second averaging?**

The old code averaged traffic over 60-second buckets.  A 3-second spike
of 25 Mbps (4K video buffering) appears as only ~1.25 Mbps when divided
by 60 seconds.  A 10-second sliding window retains the peaks while still
smoothing out single-packet jitter.

Thread safety:
    All public methods acquire ``_lock`` before touching the internal deque.
    The lock is a standard ``threading.Lock`` (non-reentrant) to keep
    overhead minimal — contention is very low because each operation is O(n)
    only during the periodic ``_prune()`` call.
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
    BANDWIDTH_WINDOW_SECONDS = 10


@dataclass(frozen=True)
class ByteRecord:
    """Single timestamped record of bytes transferred."""
    timestamp: float        # time.monotonic()
    byte_count: int
    direction: str          # 'upload', 'download', or 'other'


class BandwidthCalculator:
    """
    Sliding-window bandwidth calculator with per-direction tracking.

    Usage::

        bw = BandwidthCalculator(window_seconds=10)

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

        # Running totals (avoid re-scanning the deque on every query)
        self._total_bytes = 0
        self._upload_bytes = 0
        self._download_bytes = 0
        self._packet_count = 0

    # ------------------------------------------------------------------ #
    #  Public API — recording
    # ------------------------------------------------------------------ #

    def add_bytes(self, byte_count: int, direction: str = "other") -> None:
        """
        Record ``byte_count`` bytes transferred in the given ``direction``.

        Args:
            byte_count:  Number of bytes (IP-layer size, NOT Ethernet).
            direction:   ``'upload'``, ``'download'``, or ``'other'``.
        """
        if byte_count <= 0:
            return

        now = time.monotonic()
        record = ByteRecord(timestamp=now, byte_count=byte_count, direction=direction)

        with self._lock:
            self._records.append(record)
            self._total_bytes += byte_count
            self._packet_count += 1
            if direction == "upload":
                self._upload_bytes += byte_count
            elif direction == "download":
                self._download_bytes += byte_count

            # Prune expired records from the front
            self._prune(now)

    # ------------------------------------------------------------------ #
    #  Public API — querying
    # ------------------------------------------------------------------ #

    def get_current_bps(self) -> float:
        """Return total bytes per second over the sliding window."""
        with self._lock:
            self._prune(time.monotonic())
            return self._total_bytes / self._window if self._window else 0.0

    def get_current_mbps(self) -> float:
        """Return total megabits per second (Mbps)."""
        return (self.get_current_bps() * 8) / 1_000_000

    def get_upload_bps(self) -> float:
        """Return upload bytes per second over the sliding window."""
        with self._lock:
            self._prune(time.monotonic())
            return self._upload_bytes / self._window if self._window else 0.0

    def get_download_bps(self) -> float:
        """Return download bytes per second over the sliding window."""
        with self._lock:
            self._prune(time.monotonic())
            return self._download_bytes / self._window if self._window else 0.0

    def get_upload_mbps(self) -> float:
        """Return upload megabits per second."""
        return (self.get_upload_bps() * 8) / 1_000_000

    def get_download_mbps(self) -> float:
        """Return download megabits per second."""
        return (self.get_download_bps() * 8) / 1_000_000

    def get_packet_rate(self) -> float:
        """Return packets per second over the sliding window."""
        with self._lock:
            self._prune(time.monotonic())
            return self._packet_count / self._window if self._window else 0.0

    def get_stats(self) -> dict:
        """
        Return a snapshot of current bandwidth statistics.

        Useful for the REST API and the frontend dashboard.
        """
        with self._lock:
            self._prune(time.monotonic())
            total_bps = self._total_bytes / self._window if self._window else 0.0
            upload_bps = self._upload_bytes / self._window if self._window else 0.0
            download_bps = self._download_bytes / self._window if self._window else 0.0
            pps = self._packet_count / self._window if self._window else 0.0

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
            self._total_bytes = 0
            self._upload_bytes = 0
            self._download_bytes = 0
            self._packet_count = 0

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
        from datetime import datetime as _dt

        now = time.monotonic()
        wall_now = _dt.now()

        with self._lock:
            self._prune(now)
            if not self._records:
                return []

            # Build buckets from the sliding window records
            buckets: dict = {}
            for rec in self._records:
                # How many seconds ago was this record?
                age = now - rec.timestamp
                bucket_idx = int(age / bucket_seconds)
                if bucket_idx not in buckets:
                    buckets[bucket_idx] = {"dl": 0, "ul": 0, "total": 0}
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
            ts = wall_now - __import__("datetime").timedelta(seconds=secs_ago)
            result.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "download_mbps": round(b["dl"] * mbps_mult, 3),
                "upload_mbps": round(b["ul"] * mbps_mult, 3),
                "total_mbps": round(b["total"] * mbps_mult, 3),
                "bytes_download": b["dl"],
                "bytes_upload": b["ul"],
                "total_bytes": b["total"],
                "live": True,  # marker so frontend knows this is live data
            })

        # Sort chronologically (oldest first)
        result.sort(key=lambda d: d["timestamp"])
        return result

    # ------------------------------------------------------------------ #
    #  Private — pruning
    # ------------------------------------------------------------------ #

    def _prune(self, now: float) -> None:
        """
        Remove records older than the window.

        Must be called while ``_lock`` is held.  Subtracts pruned bytes
        from the running totals so that ``get_*_bps()`` stays O(1).
        """
        cutoff = now - self._window
        while self._records and self._records[0].timestamp < cutoff:
            old = self._records.popleft()
            self._total_bytes -= old.byte_count
            self._packet_count -= 1
            if old.direction == "upload":
                self._upload_bytes -= old.byte_count
            elif old.direction == "download":
                self._download_bytes -= old.byte_count

        # Guard against negative drift from floating-point rounding
        self._total_bytes = max(0, self._total_bytes)
        self._upload_bytes = max(0, self._upload_bytes)
        self._download_bytes = max(0, self._download_bytes)
        self._packet_count = max(0, self._packet_count)
