"""
bandwidth_calculator.py - Real-Time Bandwidth Tracking (Phase 3)
===================================================================

Tracks bytes transferred in a **sliding window** (default 10 seconds) and
calculates current upload / download rates with thread-safe access.

Phase 3 improvements — smooth decay instead of cliff-drops:

* Records are kept in a deque as before, but the **effective byte count**
  of each record is weighted by an exponential decay factor based on its
  age within the window.  A record that is 0 seconds old has weight 1.0;
  a record at the window edge has weight ``EMA_FLOOR`` (default 0.1).
  This means bytes "fade out" gradually rather than vanishing all at once.

* The hard-cutoff prune is retained (records older than
  ``window * EMA_EXTENDED_FACTOR`` are removed) but the cutoff is extended
  to 1.5× the window so the tail end of the decay curve is represented.

* ``get_current_bps()`` etc. now return the **decay-weighted** byte sum
  divided by the window, producing smooth curves that match intuition.

Thread safety:
    All public methods acquire ``_lock`` before touching the internal deque.
"""

import logging
import math
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

# EMA tuning constants
_EMA_FLOOR = 0.1          # weight of a record at exactly the window boundary
_EMA_EXTENDED_FACTOR = 1.5  # prune records older than window * this factor


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

        # Decay constant: -ln(EMA_FLOOR) / window  so that at age == window
        # the weight equals EMA_FLOOR.
        self._decay_k = -math.log(_EMA_FLOOR) / self._window if self._window else 0.0

        # Running totals (raw, un-weighted — used only for packet_count)
        self._packet_count = 0

    # ------------------------------------------------------------------ #
    #  Decay helper
    # ------------------------------------------------------------------ #

    def _weight(self, age: float) -> float:
        """Return the exponential decay weight for a record of the given age."""
        if age <= 0:
            return 1.0
        return math.exp(-self._decay_k * age)

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
            self._packet_count += 1
            self._prune(now)

    # ------------------------------------------------------------------ #
    #  Public API — querying
    # ------------------------------------------------------------------ #

    def _weighted_sums(self, now: float):
        """Return (total, upload, download) decay-weighted byte sums."""
        total = 0.0
        upload = 0.0
        download = 0.0
        for rec in self._records:
            age = now - rec.timestamp
            w = self._weight(age)
            weighted = rec.byte_count * w
            total += weighted
            if rec.direction == "upload":
                upload += weighted
            elif rec.direction == "download":
                download += weighted
        return total, upload, download

    def get_current_bps(self) -> float:
        """Return total bytes per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            total, _, _ = self._weighted_sums(now)
            return total / self._window if self._window else 0.0

    def get_current_mbps(self) -> float:
        """Return total megabits per second (Mbps)."""
        return (self.get_current_bps() * 8) / 1_000_000

    def get_upload_bps(self) -> float:
        """Return upload bytes per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            _, upload, _ = self._weighted_sums(now)
            return upload / self._window if self._window else 0.0

    def get_download_bps(self) -> float:
        """Return download bytes per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            _, _, download = self._weighted_sums(now)
            return download / self._window if self._window else 0.0

    def get_upload_mbps(self) -> float:
        """Return upload megabits per second."""
        return (self.get_upload_bps() * 8) / 1_000_000

    def get_download_mbps(self) -> float:
        """Return download megabits per second."""
        return (self.get_download_bps() * 8) / 1_000_000

    def get_packet_rate(self) -> float:
        """Return packets per second over the sliding window."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            return self._packet_count / self._window if self._window else 0.0

    def get_stats(self) -> dict:
        """
        Return a snapshot of current bandwidth statistics.

        Useful for the REST API and the frontend dashboard.
        """
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            total, upload, download = self._weighted_sums(now)
            total_bps = total / self._window if self._window else 0.0
            upload_bps = upload / self._window if self._window else 0.0
            download_bps = download / self._window if self._window else 0.0
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
                w = self._weight(age)
                bucket_idx = int(age / bucket_seconds)
                if bucket_idx not in buckets:
                    buckets[bucket_idx] = {"dl": 0.0, "ul": 0.0, "total": 0.0}
                weighted = rec.byte_count * w
                buckets[bucket_idx]["total"] += weighted
                if rec.direction == "download":
                    buckets[bucket_idx]["dl"] += weighted
                elif rec.direction == "upload":
                    buckets[bucket_idx]["ul"] += weighted

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
        """
        Remove records older than the extended window.

        Phase 3: the cutoff is window * EMA_EXTENDED_FACTOR (1.5×) so that
        records in the tail of the decay curve are still represented.
        Records beyond this extended cutoff have negligible weight and
        are safely discarded.

        Must be called while ``_lock`` is held.
        """
        cutoff = now - self._window * _EMA_EXTENDED_FACTOR
        while self._records and self._records[0].timestamp < cutoff:
            self._records.popleft()
            self._packet_count -= 1

        # Guard against negative drift from floating-point rounding
        self._packet_count = max(0, self._packet_count)
