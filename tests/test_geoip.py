"""
test_geoip.py - GeoIP Lookup Tests (#58)
==========================================

Coverage for ``packet_capture.geoip``: single and batch lookups,
caching, private-IP rejection, error handling.  All HTTP calls are mocked.
"""

import sys
import os
import time
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import packet_capture.geoip as geoip_mod
from packet_capture.geoip import lookup_ip, lookup_batch, clear_cache, _put_cache


# ===================================================================
# Helpers
# ===================================================================

_MOCK_RESPONSE = {
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "regionName": "California",
    "city": "Mountain View",
    "isp": "Google LLC",
    "org": "Google LLC",
    "lat": 37.386,
    "lon": -122.084,
}


@pytest.fixture(autouse=True)
def _clear_geoip_cache():
    """Ensure each test starts with an empty cache."""
    clear_cache()
    yield
    clear_cache()


# ===================================================================
# Private IP rejection
# ===================================================================

class TestPrivateIPRejection:

    def test_private_ip_returns_none(self):
        assert lookup_ip("192.168.1.1") is None

    def test_loopback_returns_none(self):
        assert lookup_ip("127.0.0.1") is None

    def test_empty_returns_none(self):
        assert lookup_ip("") is None

    def test_none_returns_none(self):
        assert lookup_ip(None) is None


# ===================================================================
# Single lookup (mocked HTTP)
# ===================================================================

class TestSingleLookup:

    @patch("requests.get")
    def test_successful_lookup(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {**_MOCK_RESPONSE, "query": "8.8.8.8"}
        mock_get.return_value = mock_resp

        info = lookup_ip("8.8.8.8")
        assert info is not None
        assert info["country"] == "United States"
        assert info["city"] == "Mountain View"
        assert info["isp"] == "Google LLC"
        assert info["ip"] == "8.8.8.8"

    @patch("requests.get")
    def test_api_failure_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "fail", "message": "invalid query"}
        mock_get.return_value = mock_resp

        assert lookup_ip("8.8.8.8") is None

    @patch("requests.get")
    def test_http_error_returns_none(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        assert lookup_ip("1.1.1.1") is None

    @patch("requests.get")
    def test_network_exception_returns_none(self, mock_get):
        mock_get.side_effect = Exception("timeout")

        assert lookup_ip("1.1.1.1") is None


# ===================================================================
# Cache behaviour
# ===================================================================

class TestCaching:

    @patch("requests.get")
    def test_second_call_hits_cache(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {**_MOCK_RESPONSE}
        mock_get.return_value = mock_resp

        lookup_ip("8.8.8.8")
        lookup_ip("8.8.8.8")
        # HTTP should be called only once
        assert mock_get.call_count == 1

    def test_clear_cache(self):
        # Manually seed cache
        _put_cache("1.2.3.4", {"ip": "1.2.3.4"}, time.monotonic())
        clear_cache()
        # Cache should be empty — next call would need HTTP
        assert geoip_mod._cache == {}


# ===================================================================
# Batch lookup (mocked HTTP)
# ===================================================================

class TestBatchLookup:

    def test_all_private_ips(self):
        result = lookup_batch(["192.168.1.1", "10.0.0.1", "172.16.0.1"])
        assert all(v is None for v in result.values())

    @patch("requests.post")
    def test_batch_with_public_ips(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"status": "success", "query": "8.8.8.8", "country": "US",
             "countryCode": "US", "regionName": "CA", "city": "MTV",
             "isp": "Google", "org": "Google", "lat": 0, "lon": 0},
            {"status": "success", "query": "1.1.1.1", "country": "AU",
             "countryCode": "AU", "regionName": "NSW", "city": "Sydney",
             "isp": "Cloudflare", "org": "Cloudflare", "lat": 0, "lon": 0},
        ]
        mock_post.return_value = mock_resp

        result = lookup_batch(["8.8.8.8", "1.1.1.1"])
        assert result["8.8.8.8"]["country"] == "US"
        assert result["1.1.1.1"]["country"] == "AU"

    @patch("requests.post")
    def test_batch_http_failure(self, mock_post):
        mock_post.side_effect = Exception("batch fail")

        result = lookup_batch(["8.8.8.8"])
        assert result.get("8.8.8.8") is None

    def test_empty_list(self):
        assert lookup_batch([]) == {}
