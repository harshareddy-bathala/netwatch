"""
forecast.py - Bandwidth & Device-Count Forecasting (Phase 2, AI-first)
=======================================================================

Compute-on-demand forecasting over the existing telemetry tables — no
background thread, no new dependencies, fully offline.

* **Bandwidth** — Holt double-exponential smoothing (level + trend) over
  per-minute total-Mbps buckets from ``traffic_summary``.  Missing minutes
  are gap-filled with 0 (no rows means no traffic, not missing data) and
  the current in-progress minute is dropped so a partial bucket never
  drags the trend down.  The confidence band widens with the horizon:
  ``±1.96 · σ · √k`` where σ is the one-step residual deviation.
* **Saturation ETA** — first forecast minute whose point estimate crosses
  ``FORECAST_LINK_CAPACITY_MBPS`` (0 disables the check).
* **Device count** — least-squares linear trend over hourly distinct
  source MACs, horizon in hours.

Every payload carries ``model`` diagnostics so the dashboard (and later
the LLM investigator) can cite *why* the line points where it points.
"""

import logging
import math
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from config import (
    FORECAST_ALPHA, FORECAST_BETA, FORECAST_MIN_SAMPLES,
    FORECAST_HISTORY_HOURS, FORECAST_HORIZON_MINUTES,
    FORECAST_LINK_CAPACITY_MBPS, FORECAST_CACHE_TTL_SECONDS,
)
from database.queries.traffic_queries import (
    get_bandwidth_history, get_hourly_device_counts,
)

logger = logging.getLogger(__name__)

_TS_FMT = "%Y-%m-%d %H:%M:%S"


# ---------------------------------------------------------------------------
# Pure model math (unit-testable without a database)
# ---------------------------------------------------------------------------

def holt_linear(
    series: List[float],
    alpha: float = FORECAST_ALPHA,
    beta: float = FORECAST_BETA,
) -> Tuple[float, float, float]:
    """Fit Holt's linear-trend smoothing to *series*.

    Returns ``(level, trend, sigma)`` where *level* is the smoothed value
    at the end of the series, *trend* the per-step slope, and *sigma* the
    standard deviation of one-step-ahead residuals (0.0 when the series
    is too short to produce residuals).
    """
    if not series:
        return 0.0, 0.0, 0.0
    if len(series) == 1:
        return float(series[0]), 0.0, 0.0

    level = float(series[0])
    trend = float(series[1]) - float(series[0])
    residuals: List[float] = []

    for value in series[1:]:
        value = float(value)
        predicted = level + trend
        residuals.append(value - predicted)
        new_level = alpha * value + (1 - alpha) * (level + trend)
        trend = beta * (new_level - level) + (1 - beta) * trend
        level = new_level

    if len(residuals) >= 2:
        mean = sum(residuals) / len(residuals)
        variance = sum((r - mean) ** 2 for r in residuals) / (len(residuals) - 1)
        sigma = math.sqrt(variance)
    else:
        sigma = 0.0
    return level, trend, sigma


def linear_fit(series: List[float]) -> Tuple[float, float, float]:
    """Least-squares line over index → value.

    Returns ``(intercept, slope, sigma)`` with *sigma* the residual
    standard deviation.  Falls back to a flat line for short series.
    """
    n = len(series)
    if n == 0:
        return 0.0, 0.0, 0.0
    if n == 1:
        return float(series[0]), 0.0, 0.0

    xs = list(range(n))
    mean_x = sum(xs) / n
    mean_y = sum(series) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    slope = (
        sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, series)) / denom
        if denom else 0.0
    )
    intercept = mean_y - slope * mean_x
    residuals = [y - (intercept + slope * x) for x, y in zip(xs, series)]
    if n > 2:
        sigma = math.sqrt(sum(r * r for r in residuals) / (n - 2))
    else:
        sigma = 0.0
    return intercept, slope, sigma


def gap_fill_minutes(buckets: List[dict]) -> List[Tuple[datetime, float]]:
    """Expand sparse per-minute buckets into a contiguous minute series.

    ``get_bandwidth_history`` only emits buckets that had rows; a silent
    minute is real data (0 traffic) and must appear in the series, or the
    model would learn from a time axis with holes in it.
    """
    if not buckets:
        return []

    parsed: Dict[datetime, float] = {}
    for bucket in buckets:
        try:
            ts = datetime.strptime(bucket["timestamp"], _TS_FMT)
        except (KeyError, ValueError):
            continue
        bps = float(bucket.get("bytes_per_second") or 0.0)
        parsed[ts] = bps * 8 / 1_000_000  # bytes/s → Mbps

    if not parsed:
        return []

    start, end = min(parsed), max(parsed)
    series: List[Tuple[datetime, float]] = []
    current = start
    while current <= end:
        series.append((current, parsed.get(current, 0.0)))
        current += timedelta(minutes=1)
    return series


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class ForecastService:
    """On-demand forecasts with a small TTL cache.

    Stateless between calls apart from the cache — safe to instantiate
    per-process and share across request threads.
    """

    def __init__(self, cache_ttl: int = FORECAST_CACHE_TTL_SECONDS):
        self._cache: Dict[str, Tuple[float, dict]] = {}
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()

    # -- caching ----------------------------------------------------------

    def _cached(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and time.time() - entry[0] < self._cache_ttl:
                return entry[1]
        return None

    def _store(self, key: str, payload: dict) -> dict:
        with self._lock:
            self._cache[key] = (time.time(), payload)
        return payload

    # -- bandwidth ---------------------------------------------------------

    def forecast_bandwidth(
        self,
        horizon_minutes: int = FORECAST_HORIZON_MINUTES,
        history_hours: int = FORECAST_HISTORY_HOURS,
    ) -> dict:
        """Total-bandwidth forecast: history tail + horizon with band."""
        horizon_minutes = max(1, min(int(horizon_minutes), 240))
        key = f"bw_{horizon_minutes}_{history_hours}"
        cached = self._cached(key)
        if cached is not None:
            return cached

        buckets = get_bandwidth_history(hours=history_hours, interval="minute")
        series = gap_fill_minutes(buckets)

        # Drop the in-progress minute — a partial bucket reads artificially
        # low and would bend the trend toward zero on every request.
        now_minute = datetime.now().replace(second=0, microsecond=0)
        if series and series[-1][0] >= now_minute:
            series = series[:-1]

        if len(series) < FORECAST_MIN_SAMPLES:
            return self._store(key, {
                "available": False,
                "reason": (
                    f"insufficient history: {len(series)} of "
                    f"{FORECAST_MIN_SAMPLES} minute samples"
                ),
                "points": [],
                "saturation": None,
                "model": {"samples": len(series)},
            })

        values = [v for _, v in series]
        level, trend, sigma = holt_linear(values)

        last_ts = series[-1][0]
        points = []
        saturation_eta: Optional[int] = None
        capacity = FORECAST_LINK_CAPACITY_MBPS

        for k in range(1, horizon_minutes + 1):
            estimate = max(0.0, level + k * trend)
            band = 1.96 * sigma * math.sqrt(k)
            ts = last_ts + timedelta(minutes=k)
            points.append({
                "timestamp": ts.strftime(_TS_FMT),
                "mbps": round(estimate, 4),
                "lower": round(max(0.0, estimate - band), 4),
                "upper": round(estimate + band, 4),
            })
            if capacity > 0 and saturation_eta is None and estimate >= capacity:
                saturation_eta = k

        payload = {
            "available": True,
            "generated_at": datetime.now().strftime(_TS_FMT),
            "history_minutes": len(series),
            "horizon_minutes": horizon_minutes,
            "points": points,
            "saturation": {
                "capacity_mbps": capacity,
                "eta_minutes": saturation_eta,
            } if capacity > 0 else None,
            "model": {
                "type": "holt_linear",
                "alpha": FORECAST_ALPHA,
                "beta": FORECAST_BETA,
                "level_mbps": round(level, 4),
                "trend_mbps_per_min": round(trend, 6),
                "residual_sigma": round(sigma, 4),
                "samples": len(series),
            },
        }
        return self._store(key, payload)

    # -- device count --------------------------------------------------------

    def forecast_devices(
        self,
        horizon_hours: int = 6,
        history_hours: int = 24,
    ) -> dict:
        """Hourly active-device-count trend via least-squares line."""
        horizon_hours = max(1, min(int(horizon_hours), 72))
        key = f"dev_{horizon_hours}_{history_hours}"
        cached = self._cached(key)
        if cached is not None:
            return cached

        buckets = get_hourly_device_counts(hours=history_hours)
        # Hour buckets are sparse the same way minute buckets are, but a
        # missing hour genuinely means zero active devices.
        counts: List[float] = []
        timestamps: List[datetime] = []
        parsed: Dict[datetime, int] = {}
        for bucket in buckets:
            try:
                ts = datetime.strptime(bucket["timestamp"], _TS_FMT)
                parsed[ts] = int(bucket.get("device_count") or 0)
            except (KeyError, ValueError):
                continue
        if parsed:
            current, end = min(parsed), max(parsed)
            while current <= end:
                timestamps.append(current)
                counts.append(float(parsed.get(current, 0)))
                current += timedelta(hours=1)

        if len(counts) < 3:
            return self._store(key, {
                "available": False,
                "reason": f"insufficient history: {len(counts)} of 3 hour samples",
                "points": [],
                "model": {"samples": len(counts)},
            })

        intercept, slope, sigma = linear_fit(counts)
        last_ts = timestamps[-1]
        n = len(counts)
        points = []
        for k in range(1, horizon_hours + 1):
            estimate = max(0.0, intercept + slope * (n - 1 + k))
            band = 1.96 * sigma
            points.append({
                "timestamp": (last_ts + timedelta(hours=k)).strftime(_TS_FMT),
                "count": round(estimate, 2),
                "lower": round(max(0.0, estimate - band), 2),
                "upper": round(estimate + band, 2),
            })

        payload = {
            "available": True,
            "generated_at": datetime.now().strftime(_TS_FMT),
            "history_hours": n,
            "horizon_hours": horizon_hours,
            "current_count": counts[-1],
            "points": points,
            "model": {
                "type": "linear",
                "trend_per_hour": round(slope, 4),
                "residual_sigma": round(sigma, 4),
                "samples": n,
            },
        }
        return self._store(key, payload)


# Module-level singleton — blueprints import this; nothing to start/stop.
forecast_service = ForecastService()
