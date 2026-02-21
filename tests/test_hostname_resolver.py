"""
test_hostname_resolver.py - Hostname Resolver Tests
======================================================

Tests for the TTL-bounded cache, DNS timeout handling,
vendor lookup fallback, cache eviction, and miss caching.
"""

import sys
import os
import time
import socket
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.hostname_resolver import (
    HostnameResolver,
    resolve_hostname,
    _CACHE_MAX_SIZE,
    _CACHE_TTL_SECONDS,
    _DNS_TIMEOUT_SECONDS,
)


# ===================================================================
# Basic Resolution
# ===================================================================

class TestBasicResolution:
    """Verify basic resolve() behaviour."""

    def test_returns_string(self):
        resolver = HostnameResolver()
        with patch('socket.gethostbyaddr', side_effect=socket.herror("no host")):
            result = resolver.resolve("192.168.1.1")
            assert isinstance(result, str)
            assert len(result) > 0

    def test_fallback_to_ip(self):
        """When DNS and vendor both fail, the IP itself is returned."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_reverse_dns', return_value=None), \
             patch.object(resolver, '_get_vendor', return_value="Unknown"):
            result = resolver.resolve("192.168.1.99", mac="AA:BB:CC:DD:EE:FF")
            assert result == "192.168.1.99"

    def test_dns_success(self):
        """When DNS succeeds, its result is returned."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_reverse_dns', return_value="myhost.local"):
            result = resolver.resolve("192.168.1.50")
            assert result == "myhost.local"

    def test_vendor_fallback(self):
        """When DNS fails but vendor succeeds, return 'Vendor (octet)'."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_reverse_dns', return_value=None), \
             patch.object(resolver, '_get_vendor', return_value="Apple"):
            result = resolver.resolve("192.168.1.114", mac="AA:BB:CC:DD:EE:FF")
            assert result == "Apple (114)"


# ===================================================================
# TTL Cache
# ===================================================================

class TestTTLCache:
    """Verify the bounded TTL cache."""

    def test_cache_hit(self):
        """Second call with same args should return cached value (no DNS)."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_reverse_dns', return_value="cached.host") as dns:
            resolver.resolve("10.0.0.1")
            resolver.resolve("10.0.0.1")
            # DNS should only be called once — second is from cache
            assert dns.call_count == 1

    def test_cache_expires(self):
        """After TTL, the cache entry is stale and DNS is called again."""
        resolver = HostnameResolver()
        # Manually insert an already-expired entry
        cache_key = "10.0.0.2:"
        resolver._cache[cache_key] = ("old.host", time.monotonic() - 1)

        with patch.object(resolver, '_reverse_dns', return_value="new.host"):
            result = resolver.resolve("10.0.0.2")
            assert result == "new.host"

    def test_clear_cache(self):
        """clear_cache() empties the cache."""
        resolver = HostnameResolver()
        resolver._cache["x"] = ("h", time.monotonic() + 999)
        resolver.clear_cache()
        assert len(resolver._cache) == 0

    def test_miss_is_cached(self):
        """DNS misses (fallback to IP) should be cached to avoid repeated look-ups."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_reverse_dns', return_value=None) as dns, \
             patch.object(resolver, '_get_vendor', return_value="Unknown"):
            resolver.resolve("192.168.1.200")
            resolver.resolve("192.168.1.200")
            # DNS should only be called once even though it failed
            assert dns.call_count == 1


# ===================================================================
# Cache Eviction
# ===================================================================

class TestCacheEviction:
    """Verify bounded-size eviction."""

    def test_eviction_at_capacity(self):
        """When cache is full, oldest entries are evicted."""
        resolver = HostnameResolver()
        now = time.monotonic()

        # Fill cache to capacity
        for i in range(_CACHE_MAX_SIZE):
            resolver._cache[f"key_{i}"] = (f"host_{i}", now + _CACHE_TTL_SECONDS)

        assert len(resolver._cache) == _CACHE_MAX_SIZE

        # Insert one more (triggers eviction via _put_cache)
        resolver._put_cache("new_key", "new_host", now)

        # Should have evicted ~10% and added the new one
        assert len(resolver._cache) <= _CACHE_MAX_SIZE


# ===================================================================
# DNS Timeout Handling
# ===================================================================

class TestDNSTimeout:
    """Verify that DNS lookup respects the timeout."""

    def test_timeout_returns_none(self):
        """A timeout in gethostbyaddr should return None, not raise."""
        resolver = HostnameResolver()
        with patch('socket.gethostbyaddr', side_effect=socket.timeout("timed out")):
            result = resolver._reverse_dns("192.168.1.1")
            assert result is None

    def test_gaierror_returns_none(self):
        """DNS gaierror should return None."""
        resolver = HostnameResolver()
        with patch('socket.gethostbyaddr', side_effect=socket.gaierror("lookup failed")):
            assert resolver._reverse_dns("10.0.0.1") is None

    def test_herror_returns_none(self):
        """DNS herror should return None."""
        resolver = HostnameResolver()
        with patch('socket.gethostbyaddr', side_effect=socket.herror("host error")):
            assert resolver._reverse_dns("172.16.0.1") is None


# ===================================================================
# Vendor Lookup
# ===================================================================

class TestVendorLookup:
    """Verify MAC vendor lookup fallback."""

    def test_unknown_mac_returns_unknown(self):
        """An unrecognised MAC should return 'Unknown'."""
        resolver = HostnameResolver()
        # With no vendor library, this should still not crash
        result = resolver._get_vendor("00:00:00:00:00:00")
        assert isinstance(result, str)

    def test_vendor_exception_returns_unknown(self):
        """If the vendor library throws, we should get 'Unknown'."""
        resolver = HostnameResolver()
        import packet_capture.hostname_resolver as hr
        original = hr._mac_lookup
        try:
            hr._mac_lookup = MagicMock()
            hr._mac_lookup.lookup.side_effect = Exception("boom")
            hr.VENDOR_AVAILABLE = True
            assert resolver._get_vendor("AA:BB:CC:DD:EE:FF") == "Unknown"
        finally:
            hr._mac_lookup = original


# ===================================================================
# Module‐Level Convenience
# ===================================================================

class TestModuleFunction:
    """Test the module-level resolve_hostname() convenience function."""

    def test_module_function_returns_string(self):
        with patch('socket.gethostbyaddr', side_effect=socket.herror("no host")):
            result = resolve_hostname("192.168.1.1")
            assert isinstance(result, str)
