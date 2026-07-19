"""
test_sni_ip_learner.py - Learning a blocked app's real IPs from observed SNI
============================================================================

Resolving instagram.com ourselves returns one address; the app talks to
scontent.cdninstagram.com at a different one. These tests cover learning the
addresses the client actually reaches, which is what makes blocking bite.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.sni_ip_learner import SniIpLearner, MAX_LEARNED
from intelligence.app_catalog import domain_family


class TestDomainFamily:

    def test_instagram_expands_to_cdn(self):
        fam = domain_family("instagram.com")
        assert "instagram.com" in fam
        assert "cdninstagram.com" in fam

    def test_youtube_expands_to_googlevideo(self):
        fam = domain_family("youtube.com")
        assert "googlevideo.com" in fam

    def test_subdomain_resolves_to_family(self):
        assert "cdninstagram.com" in domain_family("i.instagram.com")

    def test_unknown_domain_is_itself(self):
        assert domain_family("example.com") == {"example.com"}

    def test_family_does_not_leak_across_apps(self):
        # Instagram and YouTube are different apps — blocking one must not
        # silently block the other.
        assert "youtube.com" not in domain_family("instagram.com")


class TestSniIpLearner:

    def test_dormant_until_domains_set(self):
        l = SniIpLearner()
        assert l.active is False
        assert l.observe("i.instagram.com", "1.2.3.4") is False
        assert l.learned_ips() == set()

    def test_learns_ip_for_blocked_domain(self):
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com", "cdninstagram.com"})
        assert l.observe("scontent.cdninstagram.com", "57.144.52.192") is True
        assert l.learned_ips() == {"57.144.52.192"}

    def test_ignores_unrelated_domain(self):
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com"})
        assert l.observe("news.bbc.co.uk", "9.9.9.9") is False
        assert l.learned_ips() == set()

    def test_suffix_match_is_label_safe(self):
        """'notinstagram.com' must NOT match a block on 'instagram.com'."""
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com"})
        assert l.observe("notinstagram.com", "9.9.9.9") is False

    def test_repeat_sighting_is_not_new(self):
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com"})
        assert l.observe("i.instagram.com", "1.1.1.1") is True
        assert l.observe("i.instagram.com", "1.1.1.1") is False
        assert l.learned_ips() == {"1.1.1.1"}

    def test_learns_multiple_cdn_ips(self):
        l = SniIpLearner()
        l.set_blocked_domains({"cdninstagram.com"})
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            l.observe("scontent.cdninstagram.com", ip)
        assert l.learned_ips() == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    def test_ipv6_ignored(self):
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com"})
        assert l.observe("i.instagram.com", "2001:db8::1") is False

    def test_clearing_domains_forgets_learned(self):
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com"})
        l.observe("i.instagram.com", "1.1.1.1")
        l.set_blocked_domains(set())
        assert l.learned_ips() == set()
        assert l.active is False

    def test_ttl_expires_learned_ip(self):
        l = SniIpLearner(ttl_seconds=1)
        l.set_blocked_domains({"instagram.com"})
        l.observe("i.instagram.com", "1.1.1.1")
        import time
        time.sleep(1.1)
        assert l.learned_ips() == set()

    def test_learned_set_is_bounded(self):
        l = SniIpLearner()
        l.set_blocked_domains({"instagram.com"})
        for i in range(MAX_LEARNED + 100):
            l.observe("i.instagram.com", f"10.0.{i // 256}.{i % 256}")
        assert len(l.learned_ips()) <= MAX_LEARNED
