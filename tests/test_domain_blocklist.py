"""
test_domain_blocklist.py - Domain → IP resolution for packet-level blocking
===========================================================================

DNS sinkholing cannot stop a DoH/QUIC app, so blocked domains are also
resolved to server IPs and dropped by WinDivert. These tests cover the pure
caching/TTL logic with a stub resolver — no network.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.domain_blocklist import DomainBlocklist, MAX_IPS


class _StubResolver:
    """Records calls so we can assert the TTL cache actually caches."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, domain):
        self.calls.append(domain)
        return set(self.mapping.get(domain, set()))


class TestDomainBlocklist:

    def test_resolves_and_unions(self):
        r = _StubResolver({"a.com": {"1.1.1.1"}, "b.com": {"2.2.2.2", "3.3.3.3"}})
        bl = DomainBlocklist(resolver=r)
        assert bl.ips_for(["a.com", "b.com"]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    def test_cache_prevents_repeat_resolution(self):
        r = _StubResolver({"a.com": {"1.1.1.1"}})
        bl = DomainBlocklist(ttl_seconds=300, resolver=r)
        bl.ips_for(["a.com"], now=1000.0)
        bl.ips_for(["a.com"], now=1100.0)      # inside TTL
        assert r.calls == ["a.com"]

    def test_expired_entry_is_refreshed(self):
        r = _StubResolver({"a.com": {"1.1.1.1"}})
        bl = DomainBlocklist(ttl_seconds=60, resolver=r)
        bl.ips_for(["a.com"], now=1000.0)
        bl.ips_for(["a.com"], now=1100.0)      # past TTL
        assert r.calls == ["a.com", "a.com"]

    def test_failed_refresh_keeps_previous_ips(self):
        """A transient DNS failure must not silently unblock a domain."""
        r = _StubResolver({"a.com": {"1.1.1.1"}})
        bl = DomainBlocklist(ttl_seconds=60, resolver=r)
        assert bl.ips_for(["a.com"], now=1000.0) == {"1.1.1.1"}
        r.mapping["a.com"] = set()             # resolution now fails
        assert bl.ips_for(["a.com"], now=1100.0) == {"1.1.1.1"}

    def test_resolver_exception_is_contained(self):
        def boom(domain):
            raise RuntimeError("resolver down")
        bl = DomainBlocklist(resolver=boom)
        assert bl.ips_for(["a.com"]) == set()

    def test_unblocked_domain_drops_out(self):
        r = _StubResolver({"a.com": {"1.1.1.1"}, "b.com": {"2.2.2.2"}})
        bl = DomainBlocklist(resolver=r)
        bl.ips_for(["a.com", "b.com"])
        assert bl.ips_for(["a.com"]) == {"1.1.1.1"}

    def test_empty_input(self):
        bl = DomainBlocklist(resolver=_StubResolver({}))
        assert bl.ips_for([]) == set()
        assert bl.ips_for(["", "  "]) == set()

    def test_ip_count_is_capped(self):
        many = {f"10.0.{i // 256}.{i % 256}" for i in range(MAX_IPS + 50)}
        bl = DomainBlocklist(resolver=_StubResolver({"big.com": many}))
        assert len(bl.ips_for(["big.com"])) == MAX_IPS
