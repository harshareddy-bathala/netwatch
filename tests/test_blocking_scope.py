"""
test_blocking_scope.py - A per-device block must stay on that device
=====================================================================

Reported live: "website blocking isn't working... sometimes I feel that this
interrupts the network of client."

Both halves came from the same defect. Packet-level enforcement dropped every
blocked domain by *bare server IP*, so a rule naming one phone actually cut the
site off for every other client and for the laptop running NetWatch — while
the UI showed it scoped to one device. Blocking looked broken because it hit
the wrong things, and the network looked broken for the same reason.

These tests pin the distinction that fixes it:

* whole-device blocks (pause / quota / bedtime) drop everything for that client
* per-device domain rules drop only that client's conversation with the server
* network-wide rules drop the server for everyone, but only when asked to
"""

import os
import re
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.traffic_blocker import (
    MAX_FILTER_TERMS, TrafficBlocker, build_windivert_filter,
)
from packet_capture.sni_ip_learner import SniIpLearner

PHONE = "192.168.137.142"
TABLET = "192.168.137.178"
HOST = "192.168.137.1"
INSTAGRAM = "57.144.56.196"


class TestFilterShape:
    def test_device_block_drops_everything_for_that_client(self):
        f = build_windivert_filter(device_ips={PHONE})
        assert f"ip.SrcAddr == {PHONE}" in f
        assert f"ip.DstAddr == {PHONE}" in f

    def test_pair_binds_client_to_server_in_both_directions(self):
        f = build_windivert_filter(pairs={(PHONE, INSTAGRAM)})
        assert f"(ip.SrcAddr == {PHONE} and ip.DstAddr == {INSTAGRAM})" in f
        assert f"(ip.SrcAddr == {INSTAGRAM} and ip.DstAddr == {PHONE})" in f

    def test_pair_does_not_match_another_client(self):
        """The whole point: the tablet and the host keep Instagram."""
        f = build_windivert_filter(pairs={(PHONE, INSTAGRAM)})
        # Match whole addresses: HOST is a prefix of PHONE as a plain string.
        addrs = set(re.findall(r"\d+\.\d+\.\d+\.\d+", f))
        assert addrs == {PHONE, INSTAGRAM}
        # And crucially, no unqualified term for the server exists — an
        # unqualified term is what caught everyone else.
        assert f"ip.SrcAddr == {INSTAGRAM} or" not in f

    def test_network_scope_drops_the_server_outright(self):
        f = build_windivert_filter(server_ips={INSTAGRAM})
        assert f"ip.SrcAddr == {INSTAGRAM} or ip.DstAddr == {INSTAGRAM}" in f

    def test_empty_policy_is_none(self):
        assert build_windivert_filter() is None
        assert build_windivert_filter(set(), set(), set()) is None

    def test_ipv6_is_excluded_everywhere(self):
        f = build_windivert_filter(
            device_ips={"fe80::1"}, pairs={("fe80::2", INSTAGRAM)},
            server_ips={"2001:db8::1"},
        )
        assert f is None

    def test_terms_are_capped(self, caplog):
        pairs = {(f"10.0.0.{i}", INSTAGRAM) for i in range(1, 255)}
        f = build_windivert_filter(device_ips={f"10.1.0.{i}" for i in range(1, 60)},
                                   pairs=pairs)
        assert f.count(" or ") <= MAX_FILTER_TERMS * 3
        assert any("NOT being dropped" in r.message for r in caplog.records)

    def test_legacy_positional_call_still_means_device_block(self):
        """Existing callers passed a bare set of client IPs."""
        assert build_windivert_filter({PHONE}) == build_windivert_filter(
            device_ips={PHONE})


class TestPolicyState:
    def _blocker(self, monkeypatch):
        import packet_capture.traffic_blocker as m
        monkeypatch.setattr(m, "_PYDIVERT_OK", False)
        calls = []
        return TrafficBlocker(arp_blackhole=lambda ips: calls.append(set(ips))), calls

    def test_status_separates_the_three_kinds(self, monkeypatch):
        tb, _ = self._blocker(monkeypatch)
        tb.set_policy(device_ips={PHONE}, pairs={(TABLET, INSTAGRAM)},
                      server_ips={"1.2.3.4"})
        st = tb.get_status()
        assert st["blocked_ips"] == [PHONE]
        assert st["blocked_pairs"] == [(TABLET, INSTAGRAM)]
        assert st["blocked_servers"] == ["1.2.3.4"]
        tb.stop()

    def test_arp_fallback_only_gets_whole_device_blocks(self, monkeypatch):
        """ARP blackholing cannot express 'this client, but only to that
        server' — it would take the client off the network entirely, which is
        exactly the over-blocking we are removing."""
        tb, calls = self._blocker(monkeypatch)
        tb.set_policy(pairs={(PHONE, INSTAGRAM)})
        assert calls == []
        assert tb.get_status()["mode"] != "arp"
        tb.stop()

    def test_arp_fallback_used_for_device_block(self, monkeypatch):
        tb, calls = self._blocker(monkeypatch)
        tb.set_policy(device_ips={PHONE})
        assert calls == [{PHONE}]
        assert tb.get_status()["mode"] == "arp"
        tb.stop()

    def test_releasing_everything_turns_off(self, monkeypatch):
        tb, _ = self._blocker(monkeypatch)
        tb.set_policy(device_ips={PHONE})
        tb.set_policy()
        assert tb.get_status()["mode"] == "off"
        tb.stop()


class TestSniAttribution:
    """Learned CDN addresses must be attributable to the rule that caused them.

    Otherwise blocking instagram.com on one phone and youtube.com on another
    pools every learned address and each phone loses both sites.
    """

    def test_learned_ips_filtered_by_family(self):
        learner = SniIpLearner()
        learner.set_blocked_domains({"instagram.com", "youtube.com"})
        learner.observe("scontent.instagram.com", "57.144.56.196")
        learner.observe("rr1.googlevideo.youtube.com", "142.250.1.1")

        assert learner.learned_ips({"instagram.com"}) == {"57.144.56.196"}
        assert learner.learned_ips({"youtube.com"}) == {"142.250.1.1"}
        # No filter = everything, for the network-wide case.
        assert learner.learned_ips() == {"57.144.56.196", "142.250.1.1"}

    def test_unmatched_sni_is_ignored(self):
        learner = SniIpLearner()
        learner.set_blocked_domains({"instagram.com"})
        assert learner.observe("example.com", "1.2.3.4") is False
        assert learner.learned_ips() == set()

    def test_ttl_still_prunes(self):
        learner = SniIpLearner(ttl_seconds=1)
        learner.set_blocked_domains({"instagram.com"})
        learner.observe("instagram.com", INSTAGRAM)
        assert learner.learned_ips() == {INSTAGRAM}
        import time as _t
        _t.sleep(1.1)
        assert learner.learned_ips() == set()


class TestPauseExpiry:
    """A pause must not outlive the session that set it.

    The live database carried `paused=1` on a phone from 10:12 that was still
    blackholing its traffic hours later, across restarts, with nothing in the
    UI to explain it. Pauses are now bounded by default.
    """

    def test_unexpired_pause_still_blocks(self):
        from database.queries.policy_queries import is_blocked_now
        now = datetime(2026, 7, 20, 12, 0, 0)
        policy = {"paused": True,
                  "pause_expires_at": "2026-07-20 13:00:00"}
        assert is_blocked_now(policy, 0, now=now) == "paused"

    def test_expired_pause_releases_itself(self):
        from database.queries.policy_queries import is_blocked_now
        now = datetime(2026, 7, 20, 14, 0, 0)
        policy = {"paused": True,
                  "pause_expires_at": "2026-07-20 13:00:00"}
        assert is_blocked_now(policy, 0, now=now) is None

    def test_open_ended_pause_is_still_possible(self):
        """NULL expiry means 'until I resume it' — allowed, just not default."""
        from database.queries.policy_queries import is_blocked_now
        now = datetime(2030, 1, 1)
        assert is_blocked_now({"paused": True, "pause_expires_at": None},
                              0, now=now) == "paused"

    def test_unreadable_expiry_fails_open(self):
        """If we cannot tell when a block ends, stop blocking — cutting a
        device off forever is the worse failure."""
        from database.queries.policy_queries import is_blocked_now
        policy = {"paused": True, "pause_expires_at": "not-a-timestamp"}
        assert is_blocked_now(policy, 0, now=datetime(2026, 7, 20)) is None

    def test_quota_still_applies_after_a_pause_expires(self):
        from database.queries.policy_queries import is_blocked_now
        now = datetime(2026, 7, 20, 14, 0, 0)
        policy = {"paused": True, "pause_expires_at": "2026-07-20 13:00:00",
                  "daily_quota_mb": 1}
        assert is_blocked_now(policy, 5 * 1024 * 1024, now=now) == "quota_exceeded"


class TestRuleScopePersistence:
    def test_mac_less_rule_is_network_wide(self):
        from database.queries.blocking_queries import normalize_scope
        assert normalize_scope("device", None) == "network"
        assert normalize_scope(None, None) == "network"

    def test_default_for_a_device_rule_is_narrow(self):
        from database.queries.blocking_queries import normalize_scope
        assert normalize_scope(None, "22:5e:3e:1a:d0:f3") == "device"
        assert normalize_scope("nonsense", "22:5e:3e:1a:d0:f3") == "device"

    def test_network_scope_is_honoured_when_asked_for(self):
        from database.queries.blocking_queries import normalize_scope
        assert normalize_scope("network", "22:5e:3e:1a:d0:f3") == "network"


class TestEnforcerResolution:
    """End-to-end: rules in the DB -> the right shape of enforcement.

    This is the test that would have caught the original bug. It asserts on
    what the enforcer *hands the kernel*, not on what the rules table says.
    """

    def _seed_device(self, mac, ip, seconds_ago=0):
        from database.connection import get_connection
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO devices (mac_address, ip_address, ipv4_address,
                                        first_seen, last_seen)
                   VALUES (?, ?, ?, datetime('now'), datetime('now', ?))""",
                (mac, ip, ip, f"-{seconds_ago} seconds"),
            )
            conn.commit()

    def _stub_resolver(self, monkeypatch, mapping):
        """Pin domain->IP resolution so the test never touches real DNS."""
        import orchestration.background_tasks as bt
        from packet_capture.domain_blocklist import DomainBlocklist

        bl = DomainBlocklist(resolver=lambda d: set(mapping.get(d, ())))
        monkeypatch.setattr(bt, "_get_domain_blocklist", lambda: bl)
        return bl

    def test_device_rule_becomes_pairs_not_a_global_drop(
            self, initialized_db, monkeypatch):
        import orchestration.background_tasks as bt
        from database.queries.blocking_queries import add_rule

        self._seed_device("22:5e:3e:1a:d0:f3", PHONE)
        self._stub_resolver(monkeypatch, {"instagram.com": {INSTAGRAM}})
        add_rule("instagram.com", device_mac="22:5e:3e:1a:d0:f3")

        pairs, network_ips = bt._resolve_domain_targets()

        assert (PHONE, INSTAGRAM) in pairs
        # The critical assertion: nothing is dropped network-wide, so the
        # tablet and this host keep Instagram.
        assert network_ips == set()

    def test_network_rule_drops_for_everyone(self, initialized_db, monkeypatch):
        import orchestration.background_tasks as bt
        from database.queries.blocking_queries import add_rule

        self._stub_resolver(monkeypatch, {"instagram.com": {INSTAGRAM}})
        add_rule("instagram.com")          # no MAC = network-wide

        pairs, network_ips = bt._resolve_domain_targets()

        assert pairs == set()
        assert INSTAGRAM in network_ips

    def test_explicit_network_scope_on_a_device_rule(
            self, initialized_db, monkeypatch):
        import orchestration.background_tasks as bt
        from database.queries.blocking_queries import add_rule

        self._seed_device("22:5e:3e:1a:d0:f3", PHONE)
        self._stub_resolver(monkeypatch, {"instagram.com": {INSTAGRAM}})
        add_rule("instagram.com", device_mac="22:5e:3e:1a:d0:f3",
                 scope="network")

        pairs, network_ips = bt._resolve_domain_targets()

        assert pairs == set()
        assert INSTAGRAM in network_ips

    def test_absent_device_enforces_nothing(self, initialized_db, monkeypatch):
        """A device that left has no current lease, and guessing one would
        block whoever inherited the address."""
        import orchestration.background_tasks as bt
        from database.queries.blocking_queries import add_rule

        self._seed_device("22:5e:3e:1a:d0:f3", PHONE, seconds_ago=86400)
        self._stub_resolver(monkeypatch, {"instagram.com": {INSTAGRAM}})
        add_rule("instagram.com", device_mac="22:5e:3e:1a:d0:f3")

        pairs, network_ips = bt._resolve_domain_targets()

        assert pairs == set()
        assert network_ips == set()

    def test_stale_lease_is_not_used_for_device_blocks(self, initialized_db):
        """_macs_to_ips must not resurrect an address the device no longer holds."""
        import orchestration.background_tasks as bt
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.137.50", seconds_ago=86400)
        self._seed_device("aa:bb:cc:dd:ee:02", "192.168.137.51", seconds_ago=0)

        ips = bt._macs_to_ips({"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})

        assert ips == {"192.168.137.51"}


class TestDeviceTimestampsAreUTC:
    """`devices.last_seen` must be UTC, because every reader assumes it is.

    Found live: the Devices page showed a device "-95 minutes ago" — a
    negative age. The capture path wrote `devices.last_seen` from the packet's
    LOCAL timestamp while readers compare against `datetime('now')` /
    `datetime.utcnow()`, both UTC. On IST that puts every traffic-seen device
    5.5 hours in the future, so it never aged out of the active window, never
    went stale, and — critically — its DHCP lease never expired for the
    blocking recency check, silently defeating that guard.
    """

    def test_save_packet_writes_utc_last_seen(self, initialized_db):
        from datetime import datetime
        from database.connection import get_connection
        from database.queries import network_filters as nf
        from database.queries.packet_store import save_packet

        # Devices are only stored when they fall in the monitored subnet.
        nf.set_current_mode("hotspot")
        nf.set_subnet_from_ip("192.168.137.1", "255.255.255.0")

        # A packet stamped in LOCAL time, as the capture path supplies it.
        save_packet({
            "timestamp": datetime.now(),
            "source_ip": "192.168.137.142", "dest_ip": "57.144.56.196",
            "source_mac": "22:5e:3e:1a:d0:f3", "dest_mac": "aa:bb:cc:dd:ee:99",
            "protocol": "TCP", "bytes": 1500, "direction": "upload",
        })

        with get_connection() as conn:
            row = conn.execute(
                "SELECT last_seen FROM devices WHERE mac_address = ?",
                ("22:5e:3e:1a:d0:f3",),
            ).fetchone()

        assert row is not None, "device row should exist"
        stored = datetime.strptime(row[0][:19], "%Y-%m-%d %H:%M:%S")
        # Must be within a minute of UTC now — never in the future.
        drift = (datetime.utcnow() - stored).total_seconds()
        assert -60 < drift < 60, (
            f"last_seen is {drift:.0f}s from UTC now — it was written in "
            f"local time again"
        )

    def test_recency_bound_can_actually_expire_a_lease(self, initialized_db):
        """The Phase 3 guard is only real if timestamps age correctly."""
        import orchestration.background_tasks as bt
        from database.connection import get_connection

        with get_connection() as conn:
            conn.execute(
                """INSERT INTO devices (mac_address, ip_address, ipv4_address,
                                        first_seen, last_seen)
                   VALUES (?, ?, ?, datetime('now'), datetime('now', '-1 day'))""",
                ("22:5e:3e:1a:d0:f3", "192.168.137.142", "192.168.137.142"),
            )
            conn.commit()

        assert bt._macs_to_ips({"22:5e:3e:1a:d0:f3"}) == set()
