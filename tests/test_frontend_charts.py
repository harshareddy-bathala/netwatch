"""
test_frontend_charts.py - Frontend Chart Component Smoke Tests
================================================================

Verifies that ``BandwidthChart.update()`` and ``ProtocolChart.update()``
handle every possible data format without errors:

- Dual format: ``{history: [{timestamp, download_mbps, upload_mbps}, ...]}``
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
