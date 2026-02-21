"""
metrics.py - Application Metrics Collection
==============================================

Collects request-level and system-level metrics for the ``/api/metrics``
endpoint. Thread-safe, in-memory — resets on restart by design.

Usage::

    from utils.metrics import metrics_collector

    # In Flask middleware:
    metrics_collector.record_request('/api/stats', 42.5, 200)

    # In packet capture loop:
    metrics_collector.record_packets(captured=100, dropped=2)

    # Expose:
    data = metrics_collector.get_metrics()
"""

import re
import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Strip variable path segments (UUIDs, IDs) so endpoint keys stay bounded
_ENDPOINT_NORMALIZER = re.compile(
    r'/[0-9a-f]{8,}|/\d+',
    re.IGNORECASE,
)
_MAX_ENDPOINTS = 500


class MetricsCollector:
    """
    Collect and expose system metrics.

    All counters are thread-safe (protected by a lock).
    """

    def __init__(self, max_response_times: int = 1000):
        self._lock = threading.Lock()
        self._max_response_times = max_response_times
        self._start_time = time.time()

        # Request metrics
        self._requests_total: int = 0
        self._errors_total: int = 0
        self._by_endpoint: Dict[str, Dict] = defaultdict(
            lambda: {"count": 0, "total_time_ms": 0.0, "errors": 0}
        )
        self._response_times: deque = deque(maxlen=self._max_response_times)

        # Packet metrics
        self._packets_captured: int = 0
        self._packets_dropped: int = 0

    # -----------------------------------------------------------------
    # Recording
    # -----------------------------------------------------------------

    def record_request(self, endpoint: str, duration_ms: float, status_code: int) -> None:
        """Record a completed API request."""
        with self._lock:
            self._requests_total += 1

            # Normalize endpoint to avoid unbounded key growth (#41)
            norm = _ENDPOINT_NORMALIZER.sub('/:id', endpoint)

            if len(self._by_endpoint) >= _MAX_ENDPOINTS and norm not in self._by_endpoint:
                pass  # silently drop to prevent memory leak
            else:
                ep = self._by_endpoint[norm]
                ep["count"] += 1
                ep["total_time_ms"] += duration_ms

                if status_code >= 400:
                    ep["errors"] += 1

            if status_code >= 400:
                self._errors_total += 1

            # deque with maxlen auto-evicts oldest entries
            self._response_times.append(duration_ms)

    def record_packets(self, captured: int = 0, dropped: int = 0) -> None:
        """Record packet capture counts."""
        with self._lock:
            self._packets_captured += captured
            self._packets_dropped += dropped

    # -----------------------------------------------------------------
    # Retrieval
    # -----------------------------------------------------------------

    def get_metrics(self) -> dict:
        """Return a snapshot of all collected metrics."""
        with self._lock:
            rt = list(self._response_times)
            uptime = time.time() - self._start_time

            avg_rt = sum(rt) / len(rt) if rt else 0
            p95_rt = self._percentile(rt, 95) if rt else 0
            p99_rt = self._percentile(rt, 99) if rt else 0

            return {
                "uptime_seconds": round(uptime, 1),
                "requests_total": self._requests_total,
                "errors_total": self._errors_total,
                "error_rate": round(
                    self._errors_total / max(self._requests_total, 1), 4
                ),
                "avg_response_time_ms": round(avg_rt, 1),
                "p95_response_time_ms": round(p95_rt, 1),
                "p99_response_time_ms": round(p99_rt, 1),
                "packets_captured": self._packets_captured,
                "packets_dropped": self._packets_dropped,
                "endpoints": {
                    k: {
                        "count": v["count"],
                        "avg_ms": round(
                            v["total_time_ms"] / max(v["count"], 1), 1
                        ),
                        "errors": v["errors"],
                    }
                    for k, v in self._by_endpoint.items()
                },
            }

    def get_request_count(self) -> int:
        with self._lock:
            return self._requests_total

    def get_error_rate(self) -> float:
        with self._lock:
            if self._requests_total == 0:
                return 0.0
            return self._errors_total / self._requests_total

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _percentile(data: List[float], percentile: float) -> float:
        if not data:
            return 0.0
        sorted_data = sorted(data)
        idx = int(len(sorted_data) * percentile / 100)
        idx = min(idx, len(sorted_data) - 1)
        return sorted_data[idx]

    def reset(self) -> None:
        """Reset all counters (useful for testing)."""
        with self._lock:
            self._requests_total = 0
            self._errors_total = 0
            self._by_endpoint.clear()
            self._response_times.clear()
            self._packets_captured = 0
            self._packets_dropped = 0
            self._start_time = time.time()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
metrics_collector = MetricsCollector()
