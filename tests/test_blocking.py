"""
test_blocking.py - Client Blocking Policy & DNS Sinkhole
========================================================

Covers the three pieces of the blocking feature:

* ``database.queries.blocking_queries`` — rule CRUD + input normalisation
* ``packet_capture.dns_blocker``        — matching and the forged NXDOMAIN
* ``backend.blueprints.blocking_bp``    — the admin API

The blocker is exercised with an injected sender, so no packets ever leave
the test process.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.queries.blocking_queries import (
    add_rule, delete_rule, get_rules, normalize_domain, normalize_mac,
    record_hits, set_rule_enabled,
)
from packet_capture.dns_blocker import DNSBlocker


class TestDomainNormalization:

    @pytest.mark.parametrize("raw,expected", [
        ("instagram.com", "instagram.com"),
        ("  Instagram.COM  ", "instagram.com"),
        ("https://instagram.com/explore", "instagram.com"),
        ("http://www.instagram.com:443/x?y=1", "www.instagram.com"),
        ("instagram.com.", "instagram.com"),          # root label stripped
        ("sub.domain.co.uk", "sub.domain.co.uk"),
    ])
    def test_accepts_realistic_admin_input(self, raw, expected):
        assert normalize_domain(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", "   ", None,
        "not a domain",
        "com",                 # bare TLD
        "192.168.1.1",         # an IP is not a DNS name
        "-bad.com",
    ])
    def test_rejects_non_domains(self, raw):
        assert normalize_domain(raw) is None

    def test_mac_normalization(self):
        assert normalize_mac("AA-BB-CC-00-00-01") == "aa:bb:cc:00:00:01"
        assert normalize_mac("aa:bb:cc:00:00:01") == "aa:bb:cc:00:00:01"
        assert normalize_mac(None) is None       # network-wide rule
        assert normalize_mac("nonsense") is None


class TestRuleCrud:

    def test_add_and_list(self, initialized_db):
        rule = add_rule("https://Instagram.com/", device_mac="AA-BB-CC-00-00-01")
        assert rule["domain"] == "instagram.com"
        assert rule["device_mac"] == "aa:bb:cc:00:00:01"
        assert rule["enabled"] == 1
        assert [r["domain"] for r in get_rules()] == ["instagram.com"]

    def test_add_rejects_invalid_domain(self, initialized_db):
        assert add_rule("not a domain") is None
        assert get_rules() == []

    def test_readding_reenables_rather_than_duplicating(self, initialized_db):
        first = add_rule("instagram.com")
        set_rule_enabled(first["id"], False)

        again = add_rule("instagram.com")

        assert again["id"] == first["id"], "should reuse the rule, not duplicate it"
        assert again["enabled"] == 1
        assert len(get_rules()) == 1

    def test_network_wide_and_per_device_rules_coexist(self, initialized_db):
        """COALESCE in the unique index keeps a NULL scope distinct from a
        device scope — NULLs never compare equal, so this needs checking."""
        add_rule("instagram.com")
        add_rule("instagram.com", device_mac="aa:bb:cc:00:00:01")
        assert len(get_rules()) == 2

    def test_enabled_only_filter(self, initialized_db):
        keep = add_rule("instagram.com")
        drop = add_rule("tiktok.com")
        set_rule_enabled(drop["id"], False)
        assert [r["domain"] for r in get_rules(enabled_only=True)] == ["instagram.com"]
        assert keep["id"]

    def test_delete(self, initialized_db):
        rule = add_rule("instagram.com")
        assert delete_rule(rule["id"]) is True
        assert get_rules() == []
        assert delete_rule(rule["id"]) is False

    def test_rule_joins_device_name(self, initialized_db, db_connection):
        db_connection.execute(
            "INSERT INTO devices (mac_address, ip_address, hostname, first_seen, last_seen) "
            "VALUES ('aa:bb:cc:00:00:07', '192.168.137.70', 'moto-g34-5G', "
            "datetime('now'), datetime('now'))"
        )
        db_connection.commit()
        add_rule("instagram.com", device_mac="AA:BB:CC:00:00:07")
        assert get_rules()[0]["device_name"] == "moto-g34-5G"

    def test_record_hits_accumulates(self, initialized_db):
        rule = add_rule("instagram.com")
        record_hits({rule["id"]: 3})
        record_hits({rule["id"]: 2})
        row = get_rules()[0]
        assert row["hit_count"] == 5
        assert row["last_hit"] is not None


class TestBlockerMatching:

    def _blocker(self):
        return DNSBlocker(iface="test0", sender=lambda *a, **k: None)

    def test_no_rules_is_inactive(self, initialized_db):
        b = self._blocker()
        b.reload()
        assert b.match("instagram.com", "aa:bb:cc:00:00:01") is None
        assert b.get_stats()["active"] is False

    def test_network_wide_rule_matches_any_client(self, initialized_db):
        rule = add_rule("instagram.com")
        b = self._blocker()
        b.reload()
        assert b.match("instagram.com", "aa:bb:cc:00:00:01") == rule["id"]
        assert b.match("instagram.com", "ff:ee:dd:00:00:09") == rule["id"]

    def test_subdomains_are_covered(self, initialized_db):
        rule = add_rule("instagram.com")
        b = self._blocker()
        b.reload()
        assert b.match("www.instagram.com", "aa:bb:cc:00:00:01") == rule["id"]
        assert b.match("i.cdn.instagram.com", "aa:bb:cc:00:00:01") == rule["id"]

    def test_does_not_match_lookalike_domain(self, initialized_db):
        """A rule on instagram.com must not block notinstagram.com — suffix
        matching has to respect the label boundary."""
        add_rule("instagram.com")
        b = self._blocker()
        b.reload()
        assert b.match("notinstagram.com", "aa:bb:cc:00:00:01") is None
        assert b.match("instagram.com.evil.example", "aa:bb:cc:00:00:01") is None

    def test_per_device_rule_only_blocks_that_device(self, initialized_db):
        rule = add_rule("instagram.com", device_mac="aa:bb:cc:00:00:01")
        b = self._blocker()
        b.reload()
        assert b.match("instagram.com", "aa:bb:cc:00:00:01") == rule["id"]
        assert b.match("instagram.com", "ff:ee:dd:00:00:09") is None

    def test_trailing_dot_and_case_are_handled(self, initialized_db):
        """QNAMEs come off the wire with a root dot and arbitrary case."""
        rule = add_rule("instagram.com")
        b = self._blocker()
        b.reload()
        assert b.match("WWW.Instagram.COM.", "AA:BB:CC:00:00:01") == rule["id"]

    def test_disabled_rule_stops_matching_after_reload(self, initialized_db):
        rule = add_rule("instagram.com")
        b = self._blocker()
        b.reload()
        assert b.match("instagram.com", "aa:bb:cc:00:00:01") == rule["id"]

        set_rule_enabled(rule["id"], False)
        b.reload()
        assert b.match("instagram.com", "aa:bb:cc:00:00:01") is None


class TestForgedReply:
    """The forged answer has to look like the resolver's own reply, or the
    client discards it and resolves normally."""

    def _query(self):
        from scapy.all import DNS, DNSQR, IP, UDP, Ether
        return (
            Ether(src="aa:bb:cc:00:00:01", dst="11:22:33:44:55:66")
            / IP(src="192.168.137.70", dst="192.168.137.1")
            / UDP(sport=54321, dport=53)
            / DNS(id=0x1234, rd=1, qd=DNSQR(qname="instagram.com"))
        )

    def test_nxdomain_reply_mirrors_the_query(self, initialized_db):
        from scapy.all import DNS, IP, UDP, Ether

        sent = []
        b = DNSBlocker(iface="test0", sender=lambda pkt, **kw: sent.append(pkt))
        add_rule("instagram.com")
        b.reload()

        b._send_nxdomain(self._query())

        assert len(sent) == 1
        reply = sent[0]
        # Addressing is reversed so it reaches the client...
        assert reply[Ether].dst == "aa:bb:cc:00:00:01"
        assert reply[IP].dst == "192.168.137.70"
        assert reply[IP].src == "192.168.137.1"
        # ...and the client only accepts it if the port and txid match.
        assert reply[UDP].dport == 54321
        assert reply[UDP].sport == 53
        assert reply[DNS].id == 0x1234
        assert reply[DNS].qr == 1
        assert reply[DNS].rcode == 3          # NXDOMAIN

    def test_handle_packet_queues_matching_query(self, initialized_db):
        b = DNSBlocker(iface="test0", sender=lambda *a, **k: None)
        add_rule("instagram.com")
        b.reload()
        assert b.handle_packet(self._query()) is True

    def test_handle_packet_ignores_unblocked_domain(self, initialized_db):
        from scapy.all import DNS, DNSQR, IP, UDP, Ether

        b = DNSBlocker(iface="test0", sender=lambda *a, **k: None)
        add_rule("instagram.com")
        b.reload()

        allowed = (
            Ether(src="aa:bb:cc:00:00:01", dst="11:22:33:44:55:66")
            / IP(src="192.168.137.70", dst="192.168.137.1")
            / UDP(sport=54321, dport=53)
            / DNS(id=1, rd=1, qd=DNSQR(qname="wikipedia.org"))
        )
        assert b.handle_packet(allowed) is False

    def test_handle_packet_ignores_dns_replies(self, initialized_db):
        """Only queries (qr=0) get spoofed — reacting to a reply would mean
        answering the resolver's own answer."""
        from scapy.all import DNS, DNSQR, IP, UDP, Ether

        b = DNSBlocker(iface="test0", sender=lambda *a, **k: None)
        add_rule("instagram.com")
        b.reload()

        reply = (
            Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:00:00:01")
            / IP(src="192.168.137.1", dst="192.168.137.70")
            / UDP(sport=53, dport=54321)
            / DNS(id=1, qr=1, qd=DNSQR(qname="instagram.com"))
        )
        assert b.handle_packet(reply) is False

    def test_handle_packet_is_a_noop_with_no_rules(self, initialized_db):
        b = DNSBlocker(iface="test0", sender=lambda *a, **k: None)
        b.reload()
        assert b.handle_packet(self._query()) is False

    def test_non_dns_packet_is_ignored(self, initialized_db):
        from scapy.all import IP, TCP, Ether

        b = DNSBlocker(iface="test0", sender=lambda *a, **k: None)
        add_rule("instagram.com")
        b.reload()
        pkt = (Ether() / IP(src="192.168.137.70", dst="1.2.3.4") / TCP(dport=443))
        assert b.handle_packet(pkt) is False


class TestBlockingApi:

    def test_list_empty(self, client):
        resp = client.get('/api/blocking/rules')
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['data'] == []
        assert body['status']['enforcing'] is False

    def test_create_and_list(self, client):
        resp = client.post('/api/blocking/rules', json={'domain': 'instagram.com'})
        assert resp.status_code == 201
        assert resp.get_json()['data']['domain'] == 'instagram.com'

        rows = client.get('/api/blocking/rules').get_json()['data']
        assert len(rows) == 1

    def test_create_rejects_invalid_domain(self, client):
        resp = client.post('/api/blocking/rules', json={'domain': 'not a domain'})
        assert resp.status_code == 400
        assert 'error' in resp.get_json()

    def test_create_per_device(self, client):
        resp = client.post('/api/blocking/rules', json={
            'domain': 'instagram.com', 'device_mac': 'AA:BB:CC:00:00:01',
        })
        assert resp.status_code == 201
        assert resp.get_json()['data']['device_mac'] == 'aa:bb:cc:00:00:01'

    def test_toggle_and_delete(self, client):
        rule_id = client.post(
            '/api/blocking/rules', json={'domain': 'instagram.com'},
        ).get_json()['data']['id']

        assert client.patch(
            f'/api/blocking/rules/{rule_id}', json={'enabled': False},
        ).status_code == 200
        assert client.get('/api/blocking/rules').get_json()['data'][0]['enabled'] == 0

        assert client.delete(f'/api/blocking/rules/{rule_id}').status_code == 200
        assert client.get('/api/blocking/rules').get_json()['data'] == []

    def test_missing_rule_is_404(self, client):
        assert client.patch('/api/blocking/rules/999', json={'enabled': True}).status_code == 404
        assert client.delete('/api/blocking/rules/999').status_code == 404

    def test_patch_without_enabled_is_400(self, client):
        rule_id = client.post(
            '/api/blocking/rules', json={'domain': 'instagram.com'},
        ).get_json()['data']['id']
        assert client.patch(f'/api/blocking/rules/{rule_id}', json={}).status_code == 400

    def test_mutation_reloads_the_running_blocker(self, client):
        """A rule the admin adds must apply to the next lookup, not the next
        restart — so every mutation reloads the blocker's in-memory index."""
        from orchestration import state

        blocker = DNSBlocker(iface="test0", sender=lambda *a, **k: None)
        state.dns_blocker = blocker
        try:
            client.post('/api/blocking/rules', json={'domain': 'instagram.com'})
            assert blocker.match("instagram.com", "aa:bb:cc:00:00:01") is not None
        finally:
            state.dns_blocker = None
