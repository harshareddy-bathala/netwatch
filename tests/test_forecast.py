"""
test_forecast.py - Forecasting Service Tests (Phase 2)
=======================================================

Covers intelligence/forecast.py (Holt smoothing, linear fit, gap
filling, saturation ETA) and backend/blueprints/forecast_bp.py.
"""

import sys
import os
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.forecast import (
    ForecastService, holt_linear, linear_fit, gap_fill_minutes,
)

_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _minute_buckets(values, end=None):
    """Build get_bandwidth_history-shaped buckets ending *end* (exclusive
    of the current minute so the partial-bucket guard never trims them)."""
    end = end or (datetime.now().replace(second=0, microsecond=0)
                  - timedelta(minutes=1))
    start = end - timedelta(minutes=len(values) - 1)
    return [
        {
            "timestamp": (start + timedelta(minutes=i)).strftime(_TS_FMT),
            # Mbps → bytes/s so gap_fill_minutes converts back exactly
            "bytes_per_second": v * 1_000_000 / 8,
        }
        for i, v in enumerate(values)
    ]


# ===================================================================
# Pure model math
# ===================================================================

class TestHoltLinear:

    def test_empty_series(self):
        assert holt_linear([]) == (0.0, 0.0, 0.0)

    def test_single_point(self):
        level, trend, sigma = holt_linear([5.0])
        assert level == 5.0
        assert trend == 0.0

    def test_constant_series_is_flat(self):
        level, trend, sigma = holt_linear([10.0] * 30)
        assert level == pytest.approx(10.0)
        assert trend == pytest.approx(0.0, abs=1e-9)
        assert sigma == pytest.approx(0.0, abs=1e-9)

    def test_linear_ramp_recovers_slope(self):
        series = [2.0 * i for i in range(40)]  # slope 2/step
        level, trend, sigma = holt_linear(series)
        assert trend == pytest.approx(2.0, rel=0.05)
        assert level == pytest.approx(series[-1], rel=0.05)
        assert sigma == pytest.approx(0.0, abs=1e-6)

    def test_negative_trend_recovered(self):
        series = [100.0 - 1.5 * i for i in range(40)]
        _, trend, _ = holt_linear(series)
        assert trend == pytest.approx(-1.5, rel=0.05)


class TestLinearFit:

    def test_flat(self):
        intercept, slope, sigma = linear_fit([4.0, 4.0, 4.0, 4.0])
        assert intercept == pytest.approx(4.0)
        assert slope == pytest.approx(0.0)

    def test_slope(self):
        intercept, slope, sigma = linear_fit([1.0, 3.0, 5.0, 7.0])
        assert slope == pytest.approx(2.0)
        assert intercept == pytest.approx(1.0)
        assert sigma == pytest.approx(0.0, abs=1e-9)


class TestGapFill:

    def test_empty(self):
        assert gap_fill_minutes([]) == []

    def test_contiguous_passthrough(self):
        buckets = _minute_buckets([1.0, 2.0, 3.0])
        series = gap_fill_minutes(buckets)
        assert [v for _, v in series] == pytest.approx([1.0, 2.0, 3.0])

    def test_missing_minute_filled_with_zero(self):
        buckets = _minute_buckets([1.0, 2.0, 3.0])
        del buckets[1]  # hole in the middle
        series = gap_fill_minutes(buckets)
        assert len(series) == 3
        assert series[1][1] == 0.0

    def test_bytes_to_mbps_conversion(self):
        buckets = [{
            "timestamp": "2026-07-15 10:00:00",
            "bytes_per_second": 1_250_000,  # 10 Mbps
        }]
        series = gap_fill_minutes(buckets)
        assert series[0][1] == pytest.approx(10.0)


# ===================================================================
# Bandwidth forecast service
# ===================================================================

class TestForecastBandwidth:

    def _service(self):
        return ForecastService(cache_ttl=0)  # disable caching in tests

    def test_insufficient_history(self):
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets([5.0] * 5)):
            result = self._service().forecast_bandwidth()
        assert result["available"] is False
        assert "insufficient history" in result["reason"]
        assert result["points"] == []

    def test_flat_history_forecasts_flat(self):
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets([8.0] * 60)):
            result = self._service().forecast_bandwidth(horizon_minutes=10)
        assert result["available"] is True
        assert len(result["points"]) == 10
        for point in result["points"]:
            assert point["mbps"] == pytest.approx(8.0, rel=0.01)

    def test_rising_history_forecasts_rise(self):
        series = [1.0 + 0.5 * i for i in range(60)]
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets(series)):
            result = self._service().forecast_bandwidth(horizon_minutes=10)
        points = result["points"]
        assert points[-1]["mbps"] > points[0]["mbps"]
        assert result["model"]["trend_mbps_per_min"] == pytest.approx(0.5, rel=0.1)

    def test_forecast_never_negative(self):
        series = [30.0 - 1.0 * i for i in range(40)]  # crosses zero
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets(series)):
            result = self._service().forecast_bandwidth(horizon_minutes=30)
        assert all(p["mbps"] >= 0.0 for p in result["points"])
        assert all(p["lower"] >= 0.0 for p in result["points"])

    def test_band_widens_with_horizon(self):
        # Noisy series → nonzero sigma → widening band
        series = [10.0 + (3.0 if i % 2 else -3.0) for i in range(60)]
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets(series)):
            result = self._service().forecast_bandwidth(horizon_minutes=20)
        points = result["points"]
        first_width = points[0]["upper"] - points[0]["lower"]
        last_width = points[-1]["upper"] - points[-1]["lower"]
        assert last_width > first_width

    def test_saturation_eta(self):
        series = [10.0 + 2.0 * i for i in range(40)]  # rising 2 Mbps/min
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets(series)), \
             patch('intelligence.forecast.FORECAST_LINK_CAPACITY_MBPS', 100.0):
            result = self._service().forecast_bandwidth(horizon_minutes=30)
        assert result["saturation"] is not None
        eta = result["saturation"]["eta_minutes"]
        assert eta is not None
        # level ~88, trend ~2 → capacity 100 hit in ~6 minutes
        assert 1 <= eta <= 12

    def test_saturation_disabled_when_capacity_zero(self):
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets([5.0] * 40)):
            result = self._service().forecast_bandwidth()
        assert result["saturation"] is None

    def test_partial_current_minute_dropped(self):
        now_minute = datetime.now().replace(second=0, microsecond=0)
        buckets = _minute_buckets([10.0] * 40, end=now_minute)
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=buckets):
            result = self._service().forecast_bandwidth()
        assert result["model"]["samples"] == 39

    def test_cache_returns_same_payload(self):
        service = ForecastService(cache_ttl=60)
        with patch('intelligence.forecast.get_bandwidth_history',
                   return_value=_minute_buckets([5.0] * 40)) as mock_hist:
            first = service.forecast_bandwidth()
            second = service.forecast_bandwidth()
        assert first is second
        assert mock_hist.call_count == 1


# ===================================================================
# Device-count forecast service
# ===================================================================

class TestForecastDevices:

    def _hour_buckets(self, counts):
        end = datetime.now().replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(hours=len(counts) - 1)
        return [
            {"timestamp": (start + timedelta(hours=i)).strftime(_TS_FMT),
             "device_count": c}
            for i, c in enumerate(counts)
        ]

    def test_insufficient_history(self):
        with patch('intelligence.forecast.get_hourly_device_counts',
                   return_value=self._hour_buckets([3])):
            result = ForecastService(cache_ttl=0).forecast_devices()
        assert result["available"] is False

    def test_growing_trend(self):
        counts = [2, 3, 4, 5, 6, 7, 8, 9]
        with patch('intelligence.forecast.get_hourly_device_counts',
                   return_value=self._hour_buckets(counts)):
            result = ForecastService(cache_ttl=0).forecast_devices(horizon_hours=4)
        assert result["available"] is True
        assert result["model"]["trend_per_hour"] == pytest.approx(1.0)
        assert len(result["points"]) == 4
        assert result["points"][0]["count"] > counts[-1] - 1

    def test_forecast_never_negative(self):
        counts = [10, 8, 6, 4, 2, 0]
        with patch('intelligence.forecast.get_hourly_device_counts',
                   return_value=self._hour_buckets(counts)):
            result = ForecastService(cache_ttl=0).forecast_devices(horizon_hours=8)
        assert all(p["count"] >= 0.0 for p in result["points"])


# ===================================================================
# API endpoints
# ===================================================================

class TestForecastAPI:

    def test_bandwidth_endpoint_shape(self, client):
        resp = client.get('/api/forecast/bandwidth')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert 'available' in data
        assert 'points' in data

    def test_bandwidth_endpoint_with_horizon(self, client):
        resp = client.get('/api/forecast/bandwidth?horizon=5')
        assert resp.status_code == 200

    def test_devices_endpoint_shape(self, client):
        resp = client.get('/api/forecast/devices')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert 'available' in data
        assert 'points' in data

    def test_horizon_clamped(self, client):
        resp = client.get('/api/forecast/bandwidth?horizon=99999')
        assert resp.status_code == 200
