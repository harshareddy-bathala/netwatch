"""
query_cache.py - Query Result Caching & Timing
================================================

Provides:
* ``TTLCache`` — time-based cache for expensive query results
* ``time_query`` — decorator that logs slow queries with categorization
  (Phase 4: 200ms for critical-path, 500ms for background queries)

Usage::

    from utils.query_cache import TTLCache, time_query

    cache = TTLCache(ttl_seconds=5)

    @time_query
    def get_realtime_stats():
        cached = cache.get('realtime_stats')
        if cached is not None:
            return cached
        result = ...
        cache.set('realtime_stats', result)
        return result
"""

import time
import logging
import threading
from functools import wraps
from typing import Any, Optional

logger = logging.getLogger(__name__)


class TTLCache:
    """
    Thread-safe time-based cache for query results.

    Entries expire after ``ttl_seconds``.  The cache is bounded to
    ``max_size`` entries; when full, expired entries are evicted first,
    then the oldest entry is dropped.

    Usage::

        cache = TTLCache(ttl_seconds=5)
        cache.set('key', expensive_result)
        val = cache.get('key')  # returns result or None if expired
    """

    def __init__(self, ttl_seconds: float = 5, max_size: int = 256):
        self._cache: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Return cached value or ``None`` if missing / expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is not None:
                value, ts = entry
                if time.time() - ts < self._ttl:
                    self._hits += 1
                    return value
                # Expired — remove
                del self._cache[key]
            self._misses += 1
            return None

    def set(self, key: str, value: Any) -> None:
        """Store *value* under *key* with current timestamp."""
        with self._lock:
            if len(self._cache) >= self._max_size:
                self._evict()
            self._cache[key] = (value, time.time())

    def invalidate(self, key: str) -> None:
        """Remove a specific key from the cache."""
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._cache.clear()

    def stats(self) -> dict:
        """Return cache hit/miss statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total, 2) if total else 0,
                "size": len(self._cache),
            }

    def _evict(self) -> None:
        """Remove expired entries, then oldest if still over capacity."""
        now = time.time()
        # Remove expired
        expired = [k for k, (_, ts) in self._cache.items()
                   if now - ts >= self._ttl]
        for k in expired:
            del self._cache[k]
        # If still at capacity, remove oldest
        if len(self._cache) >= self._max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]


# ---------------------------------------------------------------------------
# Query timing decorator
# ---------------------------------------------------------------------------

def time_query(func):
    """
    Decorator that logs a warning when a query function takes too long.

    Phase 4 categorisation:
    * **Critical-path** queries (called on every SSE cycle): 100ms threshold.
    * **Background** queries (historical, full device list, etc.): 500ms.

    Functions whose name starts with ``get_dashboard`` or ``get_top_devices``
    are classified as critical-path; all others default to background.

    Also tracks cumulative call counts and total time for monitoring.

    Usage::

        @time_query
        def get_dashboard_data():
            ...
    """
    _call_count = 0
    _total_time = 0.0

    # Phase 4: categorise queries
    _critical_names = ('get_dashboard_data', 'get_top_devices', 'get_realtime_stats')
    _is_critical = func.__name__ in _critical_names
    _threshold = 0.2 if _is_critical else 0.5  # 200ms critical, 500ms background

    @wraps(func)
    def wrapper(*args, **kwargs):
        nonlocal _call_count, _total_time
        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = time.perf_counter() - start
            _call_count += 1
            _total_time += duration
            if duration > _threshold:
                category = 'critical' if _is_critical else 'background'
                logger.warning(
                    "Slow query [%s]: %s took %.0fms (avg %.0fms over %d calls)",
                    category,
                    func.__name__,
                    duration * 1000,
                    (_total_time / _call_count) * 1000,
                    _call_count,
                )

    wrapper._call_count = lambda: _call_count
    wrapper._total_time = lambda: _total_time
    return wrapper
