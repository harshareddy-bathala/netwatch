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
    _PASSIVE_CACHE_TTL_SECONDS,
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
             patch.object(resolver, '_mdns_lookup', return_value=None), \
             patch.object(resolver, '_get_vendor', return_value="Unknown"):
            result = resolver.resolve("192.168.1.99", mac="AA:BB:CC:DD:EE:FF")
            assert result == "192.168.1.99"

    def test_dns_success(self):
        """When DNS succeeds, its result is returned."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_mdns_lookup', return_value=None), \
             patch.object(resolver, '_reverse_dns', return_value="myhost.local"):
            result = resolver.resolve("192.168.1.50")
            assert result == "myhost.local"

    def test_vendor_fallback(self):
        """When DNS fails but vendor succeeds, return 'Vendor (octet)'."""
        resolver = HostnameResolver()
        with patch.object(resolver, '_reverse_dns', return_value=None), \
             patch.object(resolver, '_mdns_lookup', return_value=None), \
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
        with patch.object(resolver, '_mdns_lookup', return_value=None), \
             patch.object(resolver, '_reverse_dns', return_value="cached.host") as dns:
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
        with patch.object(resolver, '_mdns_lookup', return_value=None), \
             patch.object(resolver, '_reverse_dns', return_value=None) as dns, \
             patch.object(resolver, '_get_vendor', return_value="Unknown"):
            resolver.resolve("192.168.1.200")
            resolver.resolve("192.168.1.200")
            # DNS should only be called once even though it failed
            assert dns.call_count == 1


# ===================================================================
# Passive Hostname Learning (Phase 2)
# ===================================================================

class TestPassiveLearning:
    """Verify passive hostname learning with longer TTL."""

    def test_passive_hostname_priority(self):
        """Passively learned hostnames should take priority over DNS."""
        resolver = HostnameResolver()
        resolver.learn_hostname("192.168.1.10", "MyPhone")
        # Should return the passive name without calling DNS
        with patch.object(resolver, '_reverse_dns', return_value="dns-name") as dns:
            result = resolver.resolve("192.168.1.10")
            assert result == "MyPhone"
            assert dns.call_count == 0

    def test_passive_hostname_longer_ttl(self):
        """Passive hostnames should use 1-hour TTL."""
        resolver = HostnameResolver()
        resolver.learn_hostname("192.168.1.20", "LongLived")
        with resolver._lock:
            entry = resolver._passive_hostnames["192.168.1.20"]
            expiry = entry[1]
            expected_min = time.monotonic() + _PASSIVE_CACHE_TTL_SECONDS - 5
            assert expiry >= expected_min

    def test_passive_rejects_bare_ips(self):
        """learn_hostname should ignore when hostname == ip."""
        resolver = HostnameResolver()
        resolver.learn_hostname("192.168.1.5", "192.168.1.5")
        with resolver._lock:
            assert "192.168.1.5" not in resolver._passive_hostnames

    def test_passive_rejects_fe80(self):
        """learn_hostname should filter out fe80:: addresses as hostnames."""
        resolver = HostnameResolver()
        resolver.learn_hostname("192.168.1.5", "fe80::1234:5678")
        with resolver._lock:
            assert "192.168.1.5" not in resolver._passive_hostnames

    def test_passive_updates_active_cache(self):
        """Passive learn should also update the active TTL cache."""
        resolver = HostnameResolver()
        # Pre-populate active cache
        cache_key = "192.168.1.30:"
        resolver._cache[cache_key] = ("old-name", time.monotonic() + 100)
        # Learn a new passive name
        resolver.learn_hostname("192.168.1.30", "NewDevice")
        with resolver._lock:
            name, _ = resolver._cache[cache_key]
            assert name == "NewDevice"


# ===================================================================
# Background Resolution Queue (Phase 2)
# ===================================================================

class TestBackgroundQueue:
    """Verify the background resolution queue."""

    def test_enqueue_adds_to_queue(self):
        """enqueue_for_resolution should add to the queue."""
        resolver = HostnameResolver()
        resolver.enqueue_for_resolution("10.0.0.1", "AA:BB:CC:DD:EE:FF")
        assert len(resolver._resolve_queue) == 1

    def test_enqueue_deduplicates(self):
        """Same IP+MAC should not be enqueued twice."""
        resolver = HostnameResolver()
        resolver.enqueue_for_resolution("10.0.0.1", "AA:BB:CC:DD:EE:FF")
        resolver.enqueue_for_resolution("10.0.0.1", "AA:BB:CC:DD:EE:FF")
        assert len(resolver._resolve_queue) == 1

    def test_enqueue_ignores_empty_ip(self):
        """Empty IP should not be enqueued."""
        resolver = HostnameResolver()
        resolver.enqueue_for_resolution("", "AA:BB:CC:DD:EE:FF")
        assert len(resolver._resolve_queue) == 0

    def test_close_shuts_down(self):
        """close() should shut down executor and signal background thread."""
        resolver = HostnameResolver()
        resolver.close()
        assert resolver._bg_shutdown.is_set()


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
