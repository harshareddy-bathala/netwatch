"""
test_frontend_charts.py - Frontend Chart Component Smoke Tests
================================================================

Verifies that ``BandwidthChart.update()`` and ``ProtocolChart.update()``
handle every possible data format without errors:

- Dual format: ``{history: [{timestamp, download_mbps, upload_mbps}, ...]}``
- Dual+control format: ``{history: [{..., control_download_mbps, control_upload_mbps}, ...]}``
- SSE live format: ``{stats: {upload_mbps, download_mbps}, history: [...]}``
- Non-dual legacy: ``{data: [{timestamp, bytes_per_second}, ...]}``
- Empty / null / missing data
- Protocol data with varying field names (name vs protocol, bytes vs count)

These tests validate the **data parsing logic** in each component's
``update(raw)`` method by simulating the JavaScript logic in Python.
Since Chart.js can't run in pytest, we replicate the JS data transforms
to verify correctness.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# BandwidthChart data-path logic replicated from BandwidthChart.js
# =============================================================================

def _bw_extract_data(raw):
    """
    Replicate the BandwidthChart.update(raw) data extraction from JS:

        const history = (raw && (raw.history || raw.data || raw)) || [];
        download = history.map(d => d.download_mbps ?? d.bytes_per_second ?? 0);
        upload = history.map(d => d.upload_mbps ?? 0);
    """
    if not raw:
        return [], []

    if isinstance(raw, dict):
        history = raw.get('history') or raw.get('data') or []
    elif isinstance(raw, list):
        history = raw
    else:
        history = []

    if not isinstance(history, list):
        return [], []

    downloads = []
    uploads = []
    for d in history:
        dl = d.get('download_mbps') if d.get('download_mbps') is not None else d.get('bytes_per_second', 0)
        if dl is None:
            dl = 0
        uploads.append(d.get('upload_mbps', 0) or 0)
        downloads.append(dl)
    return downloads, uploads


def _bw_extract_control_data(raw):
    """Extract app/control split series used by Phase 3 chart mode."""
    if not raw:
        return [], [], [], []

    if isinstance(raw, dict):
        history = raw.get('history') or raw.get('data') or []
    elif isinstance(raw, list):
        history = raw
    else:
        history = []

    if not isinstance(history, list):
        return [], [], [], []

    app_dl, app_ul, ctrl_dl, ctrl_ul = [], [], [], []
    for d in history:
        app_dl.append(d.get('download_mbps', 0) or 0)
        app_ul.append(d.get('upload_mbps', 0) or 0)
        ctrl_dl.append(d.get('control_download_mbps', 0) or 0)
        ctrl_ul.append(d.get('control_upload_mbps', 0) or 0)
    return app_dl, app_ul, ctrl_dl, ctrl_ul


def _causal_smooth(data):
    """Mirror BandwidthChart causal trailing smoothing."""
    if not data or len(data) < 3:
        return data
    out = []
    for i in range(len(data)):
        x0 = data[i] if data[i] is not None else 0
        x1 = data[i - 1] if i - 1 >= 0 else x0
        x2 = data[i - 2] if i - 2 >= 0 else x1
        x3 = data[i - 3] if i - 3 >= 0 else x2
        x4 = data[i - 4] if i - 4 >= 0 else x3
        out.append(x0 * 0.40 + x1 * 0.30 + x2 * 0.15 + x3 * 0.10 + x4 * 0.05)
    return out


class TestBandwidthChartDataPaths:
    """Smoke tests for BandwidthChart data extraction logic."""

    def test_dual_format(self):
        """Standard dual format from /api/bandwidth/dual."""
        raw = {
            'history': [
                {'timestamp': '12:00', 'download_mbps': 5.0, 'upload_mbps': 2.0},
                {'timestamp': '12:01', 'download_mbps': 6.5, 'upload_mbps': 3.1},
            ]
        }
        dl, ul = _bw_extract_data(raw)
        assert dl == [5.0, 6.5]
        assert ul == [2.0, 3.1]

    def test_sse_live_format(self):
        """SSE push format includes a top-level stats + history."""
        raw = {
            'stats': {'upload_mbps': 4.0, 'download_mbps': 6.0},
            'history': [
                {'timestamp': '12:00', 'download_mbps': 6.0, 'upload_mbps': 4.0},
            ]
        }
        dl, ul = _bw_extract_data(raw)
        assert dl == [6.0]
        assert ul == [4.0]

    def test_legacy_data_key(self):
        """Legacy format uses 'data' key with bytes_per_second."""
        raw = {
            'data': [
                {'timestamp': '12:00', 'bytes_per_second': 1250000},
                {'timestamp': '12:01', 'bytes_per_second': 900000},
            ]
        }
        dl, ul = _bw_extract_data(raw)
        assert dl == [1250000, 900000]  # falls back to bytes_per_second
        assert ul == [0, 0]  # no upload in legacy

    def test_plain_list(self):
        """Raw list without wrapper dict."""
        raw = [
            {'timestamp': '12:00', 'download_mbps': 1.0, 'upload_mbps': 0.5},
        ]
        dl, ul = _bw_extract_data(raw)
        assert dl == [1.0]
        assert ul == [0.5]

    def test_empty_dict(self):
        """Empty dict → no data."""
        dl, ul = _bw_extract_data({})
        assert dl == []
        assert ul == []

    def test_none(self):
        """None → no data."""
        dl, ul = _bw_extract_data(None)
        assert dl == []
        assert ul == []

    def test_empty_list(self):
        """Empty list → no data."""
        dl, ul = _bw_extract_data([])
        assert dl == []
        assert ul == []

    def test_history_with_missing_fields(self):
        """Entries missing download_mbps should default to 0."""
        raw = {
            'history': [
                {'timestamp': '12:00'},  # no bandwidth fields
            ]
        }
        dl, ul = _bw_extract_data(raw)
        assert dl == [0]
        assert ul == [0]

    def test_mixed_format_entries(self):
        """Mix of dual and legacy entries."""
        raw = {
            'history': [
                {'timestamp': '12:00', 'download_mbps': 5.0, 'upload_mbps': 2.0},
                {'timestamp': '12:01', 'bytes_per_second': 100000},  # legacy fallback
            ]
        }
        dl, ul = _bw_extract_data(raw)
        assert dl == [5.0, 100000]
        assert ul == [2.0, 0]

    def test_control_overlay_fields(self):
        """Phase 3: chart can consume separate control-traffic series."""
        raw = {
            'history': [
                {
                    'timestamp': '12:00',
                    'download_mbps': 4.0,
                    'upload_mbps': 1.5,
                    'control_download_mbps': 0.4,
                    'control_upload_mbps': 0.1,
                },
                {
                    'timestamp': '12:01',
                    'download_mbps': 3.5,
                    'upload_mbps': 1.2,
                    'control_download_mbps': 0.3,
                    'control_upload_mbps': 0.2,
                },
            ]
        }

        app_dl, app_ul, ctrl_dl, ctrl_ul = _bw_extract_control_data(raw)
        assert app_dl == [4.0, 3.5]
        assert app_ul == [1.5, 1.2]
        assert ctrl_dl == [0.4, 0.3]
        assert ctrl_ul == [0.1, 0.2]

    def test_control_overlay_defaults_to_zero(self):
        """Missing control fields should not break the app/control chart mode."""
        raw = {
            'history': [
                {'timestamp': '12:00', 'download_mbps': 2.0, 'upload_mbps': 0.8},
            ]
        }

        app_dl, app_ul, ctrl_dl, ctrl_ul = _bw_extract_control_data(raw)
        assert app_dl == [2.0]
        assert app_ul == [0.8]
        assert ctrl_dl == [0]
        assert ctrl_ul == [0]

    def test_causal_smoothing_keeps_completed_points_stable(self):
        """Appending new data should not rewrite already completed points."""
        base = [0.1, 0.3, 2.0, 1.2, 0.4]
        extended = base + [3.5]

        first = _causal_smooth(base)
        second = _causal_smooth(extended)

        assert second[:len(first)] == first


# =============================================================================
# ProtocolChart data-path logic replicated from ProtocolChart.js
# =============================================================================

def _proto_extract_data(raw):
    """
    Replicate ProtocolChart.update(raw):

        protocols = (raw && (raw.protocols || raw.data || raw)) || [];
        labels = protocols.map(p => p.name || p.protocol || 'Unknown');
        data = protocols.map(p => p.bytes || p.total_bytes || p.count ||
                                  p.packet_count || p.percentage || 0);
    """
    if not raw:
        return [], []

    if isinstance(raw, dict):
        protocols = raw.get('protocols') or raw.get('data') or []
    elif isinstance(raw, list):
        protocols = raw
    else:
        protocols = []

    if not isinstance(protocols, list):
        return [], []

    labels = []
    values = []
    for p in protocols:
        label = p.get('name') or p.get('protocol') or 'Unknown'
        value = (p.get('bytes') or p.get('total_bytes') or p.get('count')
                 or p.get('packet_count') or p.get('percentage') or 0)
        labels.append(label)
        values.append(value)
    return labels, values


class TestProtocolChartDataPaths:
    """Smoke tests for ProtocolChart data extraction logic."""

    def test_dashboard_format(self):
        """Dashboard format uses 'name' and 'bytes'."""
        raw = [
            {'name': 'HTTPS', 'bytes': 50000},
            {'name': 'DNS', 'bytes': 8000},
        ]
        labels, values = _proto_extract_data(raw)
        assert labels == ['HTTPS', 'DNS']
        assert values == [50000, 8000]

    def test_protocols_endpoint_format(self):
        """Standalone /api/protocols uses 'protocol' and 'packet_count'."""
        raw = {
            'data': [
                {'protocol': 'TCP', 'packet_count': 1200},
                {'protocol': 'UDP', 'packet_count': 300},
            ]
        }
        labels, values = _proto_extract_data(raw)
        assert labels == ['TCP', 'UDP']
        assert values == [1200, 300]

    def test_sse_format(self):
        """SSE push nests under 'protocols' key."""
        raw = {
            'protocols': [
                {'name': 'HTTP', 'bytes': 100000},
                {'name': 'SSH', 'bytes': 5000},
            ]
        }
        labels, values = _proto_extract_data(raw)
        assert labels == ['HTTP', 'SSH']
        assert values == [100000, 5000]

    def test_empty_list(self):
        labels, values = _proto_extract_data([])
        assert labels == []
        assert values == []

    def test_none(self):
        labels, values = _proto_extract_data(None)
        assert labels == []
        assert values == []

    def test_empty_dict(self):
        labels, values = _proto_extract_data({})
        assert labels == []
        assert values == []

    def test_percentage_field(self):
        """Some aggregations provide 'percentage' instead of bytes."""
        raw = [
            {'name': 'HTTPS', 'percentage': 65.5},
            {'name': 'Other', 'percentage': 34.5},
        ]
        labels, values = _proto_extract_data(raw)
        assert values == [65.5, 34.5]

    def test_total_bytes_field(self):
        """Alternate field name 'total_bytes'."""
        raw = [
            {'protocol': 'DNS', 'total_bytes': 42000},
        ]
        labels, values = _proto_extract_data(raw)
        assert labels == ['DNS']
        assert values == [42000]

    def test_missing_name_uses_unknown(self):
        """Entries without name/protocol should show 'Unknown'."""
        raw = [{'bytes': 100}]
        labels, values = _proto_extract_data(raw)
        assert labels == ['Unknown']
        assert values == [100]

    def test_all_zero_values(self):
        """Entries with no value fields → 0."""
        raw = [{'name': 'Empty'}]
        labels, values = _proto_extract_data(raw)
        assert labels == ['Empty']
        assert values == [0]


# =============================================================================
# Forecast overlay merge logic replicated from BandwidthChart.js (Phase 2)
# =============================================================================

def _merge_forecast(history_len, dl_last, ul_last, fc_points):
    """
    Replicate the forecast dataset construction in BandwidthChart.update():

        datasets[4] = nulls×(histLen-1) + [bridge] + points.mbps
        datasets[5] = nulls×histLen + points.upper
        datasets[6] = nulls×histLen + points.lower

    where bridge = last measured download + upload total.
    """
    if not fc_points or history_len == 0:
        return [], [], []
    bridge = (dl_last or 0) + (ul_last or 0)
    line = [None] * (history_len - 1) + [bridge] + [p['mbps'] for p in fc_points]
    upper = [None] * history_len + [p['upper'] for p in fc_points]
    lower = [None] * history_len + [p['lower'] for p in fc_points]
    return line, upper, lower


class TestForecastOverlayMerge:
    """The dashed forecast line must bridge from the last measured total
    and stay index-aligned with its confidence band."""

    def _points(self, n=5):
        return [
            {'timestamp': f'2026-07-15 12:{i:02d}:00',
             'mbps': 10.0 + i, 'upper': 12.0 + i, 'lower': 8.0 + i}
            for i in range(n)
        ]

    def test_lengths_match_extended_axis(self):
        line, upper, lower = _merge_forecast(60, 4.0, 2.0, self._points(30))
        # x-axis = 60 history labels + 30 forecast labels
        assert len(line) == 90
        assert len(upper) == 90
        assert len(lower) == 90

    def test_bridge_is_last_measured_total(self):
        line, _, _ = _merge_forecast(60, 4.0, 2.0, self._points())
        assert line[59] == 6.0          # dl + ul at the last history index
        assert all(v is None for v in line[:59])

    def test_band_starts_after_history(self):
        _, upper, lower = _merge_forecast(60, 4.0, 2.0, self._points())
        assert all(v is None for v in upper[:60])
        assert all(v is None for v in lower[:60])
        assert upper[60] == 12.0
        assert lower[60] == 8.0

    def test_band_brackets_line(self):
        line, upper, lower = _merge_forecast(10, 1.0, 1.0, self._points(8))
        for i in range(10, 18):
            assert lower[i] <= line[i] <= upper[i]

    def test_empty_forecast_clears_overlay(self):
        assert _merge_forecast(60, 4.0, 2.0, []) == ([], [], [])

    def test_no_history_no_overlay(self):
        assert _merge_forecast(0, 0, 0, self._points()) == ([], [], [])
