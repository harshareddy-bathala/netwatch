"""
test_discovery_manager.py - Discovery Upsert Regression Tests
==============================================================

Covers hotspot/public discovery upsert behaviors:
- active_mode assignment for connected hotspot clients
- CIDR-aware subnet filtering (no hardcoded /24 assumptions)
- stale IP refresh when fresher ARP data arrives
"""

import logging
import os
import sqlite3
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import get_connection
from orchestration import state
from orchestration.discovery_manager import (
    _upsert_arp_cache_devices,
    _clear_stale_active_mode_devices,
    _mark_recently_confirmed_macs,
    _get_recently_confirmed_macs,
    _should_promote_hotspot_cache_client,
)
from config import HOTSPOT_STALE_DEVICE_SECONDS


def _set_current_mode(monkeypatch, ip_address: str, netmask: str) -> None:
    """Provide a minimal interface_manager current mode for subnet checks."""
    mode = MagicMock()
    mode.interface.ip_address = ip_address
    mode.interface.netmask = netmask

    iface_manager = MagicMock()
    iface_manager.get_current_mode.return_value = mode
    monkeypatch.setattr(state, "interface_manager", iface_manager)


class TestDiscoveryManagerUpserts:
    def test_refreshes_stale_ip_and_sets_active_mode(self, initialized_db, monkeypatch):
        _set_current_mode(monkeypatch, ip_address="192.168.50.1", netmask="255.255.255.0")

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"):
            with get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO devices (mac_address, ip_address, ipv4_address, detected_mode, active_mode)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("AA:BB:CC:DD:EE:01", "192.168.50.10", "192.168.50.10", "hotspot", None),
                )
                conn.commit()

            _upsert_arp_cache_devices(
                [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.50.77", "hostname": "", "vendor": ""}],
                "hotspot",
                set_active_mode=True,
                local_ips=set(),
            )

            with get_connection() as conn:
                row = conn.execute(
                    "SELECT ip_address, ipv4_address, active_mode FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:01",),
                ).fetchone()

        assert row is not None
        assert row["ip_address"] == "192.168.50.77"
        assert row["ipv4_address"] == "192.168.50.77"
        assert row["active_mode"] == "hotspot"

    def test_uses_cidr_subnet_filter_instead_of_prefix(self, initialized_db, monkeypatch):
        # /16 network: 10.42.0.0/16 should include 10.42.99.9 and exclude 10.43.1.5.
        _set_current_mode(monkeypatch, ip_address="10.42.0.1", netmask="255.255.0.0")

        devices = [
            {"mac": "AA:BB:CC:DD:EE:02", "ip": "10.42.99.9", "hostname": "", "vendor": ""},
            {"mac": "AA:BB:CC:DD:EE:03", "ip": "10.43.1.5", "hostname": "", "vendor": ""},
        ]

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"):
            _upsert_arp_cache_devices(
                devices,
                "hotspot",
                set_active_mode=True,
                local_ips=set(),
            )

            with get_connection() as conn:
                in_subnet = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:02",),
                ).fetchone()["c"]
                out_subnet = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:03",),
                ).fetchone()["c"]

        assert in_subnet == 1
        assert out_subnet == 0

    def test_active_discovery_updates_in_memory_state(self, initialized_db, monkeypatch):
        _set_current_mode(monkeypatch, ip_address="192.168.50.1", netmask="255.255.255.0")

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"), \
             patch("utils.realtime_state.dashboard_state.upsert_discovered_device") as mock_mem_upsert:
            _upsert_arp_cache_devices(
                [{"mac": "AA:BB:CC:DD:EE:40", "ip": "192.168.50.44", "hostname": "", "vendor": ""}],
                "hotspot",
                set_active_mode=True,
                local_ips=set(),
            )

        mock_mem_upsert.assert_called_once()

    def test_stale_mode_generation_skips_upsert(self, initialized_db, monkeypatch):
        _set_current_mode(monkeypatch, ip_address="192.168.50.1", netmask="255.255.255.0")
        monkeypatch.setattr(state, "mode_generation", 5)

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"):
            _upsert_arp_cache_devices(
                [{"mac": "AA:BB:CC:DD:EE:50", "ip": "192.168.50.88", "hostname": "", "vendor": ""}],
                "hotspot",
                set_active_mode=True,
                local_ips=set(),
                expected_generation=4,
            )

            with get_connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:50",),
                ).fetchone()

        assert row["c"] == 0

    def test_active_upsert_overwrites_old_mode_tag(self, initialized_db, monkeypatch):
        _set_current_mode(monkeypatch, ip_address="192.168.50.1", netmask="255.255.255.0")

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"):
            with get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO devices (mac_address, ip_address, ipv4_address, detected_mode, active_mode)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("AA:BB:CC:DD:EE:60", "192.168.50.66", "192.168.50.66", "public_network", "public_network"),
                )
                conn.commit()

            _upsert_arp_cache_devices(
                [{"mac": "AA:BB:CC:DD:EE:60", "ip": "192.168.50.66", "hostname": "", "vendor": ""}],
                "hotspot",
                set_active_mode=True,
                local_ips=set(),
            )

            with get_connection() as conn:
                row = conn.execute(
                    "SELECT active_mode FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:60",),
                ).fetchone()

        assert row["active_mode"] == "hotspot"

    def test_cache_only_upsert_clears_active_mode(self, initialized_db, monkeypatch):
        _set_current_mode(monkeypatch, ip_address="192.168.50.1", netmask="255.255.255.0")

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"):
            with get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO devices (mac_address, ip_address, ipv4_address, detected_mode, active_mode)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("AA:BB:CC:DD:EE:70", "192.168.50.70", "192.168.50.70", "hotspot", "hotspot"),
                )
                conn.commit()

            _upsert_arp_cache_devices(
                [{"mac": "AA:BB:CC:DD:EE:70", "ip": "192.168.50.70", "hostname": "", "vendor": ""}],
                "hotspot",
                set_active_mode=False,
                local_ips=set(),
                clear_active_mode_when_inactive=True,
            )

            with get_connection() as conn:
                row = conn.execute(
                    "SELECT active_mode FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:70",),
                ).fetchone()

        assert row["active_mode"] is None

    def test_cache_only_upsert_preserves_confirmed_active_mode(self, initialized_db, monkeypatch):
        _set_current_mode(monkeypatch, ip_address="192.168.50.1", netmask="255.255.255.0")

        with patch("orchestration.discovery_manager.get_all_local_macs", return_value=set()), \
             patch("orchestration.discovery_manager._enqueue_resolution"):
            with get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO devices (mac_address, ip_address, ipv4_address, detected_mode, active_mode)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("AA:BB:CC:DD:EE:71", "192.168.50.71", "192.168.50.71", "hotspot", "hotspot"),
                )
                conn.commit()

            _upsert_arp_cache_devices(
                [{"mac": "AA:BB:CC:DD:EE:71", "ip": "192.168.50.71", "hostname": "", "vendor": ""}],
                "hotspot",
                set_active_mode=False,
                local_ips=set(),
                clear_active_mode_when_inactive=True,
                preserve_active_macs={"aa:bb:cc:dd:ee:71"},
            )

            with get_connection() as conn:
                row = conn.execute(
                    "SELECT active_mode FROM devices WHERE mac_address = ?",
                    ("AA:BB:CC:DD:EE:71",),
                ).fetchone()

        assert row["active_mode"] == "hotspot"

    def test_clear_stale_active_mode_devices(self, initialized_db):
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    mac_address, ip_address, ipv4_address, detected_mode, active_mode,
                    first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, datetime('now', '-5 minutes'), datetime('now', '-5 minutes'))
                """,
                ("AA:BB:CC:DD:EE:72", "192.168.50.72", "192.168.50.72", "hotspot", "hotspot"),
            )
            conn.execute(
                """
                INSERT INTO devices (
                    mac_address, ip_address, ipv4_address, detected_mode, active_mode,
                    first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                """,
                ("AA:BB:CC:DD:EE:73", "192.168.50.73", "192.168.50.73", "hotspot", "hotspot"),
            )
            conn.commit()

        cleared = _clear_stale_active_mode_devices("hotspot", 60)
        assert cleared >= 1

        with get_connection() as conn:
            stale = conn.execute(
                "SELECT active_mode FROM devices WHERE mac_address = ?",
                ("AA:BB:CC:DD:EE:72",),
            ).fetchone()["active_mode"]
            fresh = conn.execute(
                "SELECT active_mode FROM devices WHERE mac_address = ?",
                ("AA:BB:CC:DD:EE:73",),
            ).fetchone()["active_mode"]

        assert stale is None
        assert fresh == "hotspot"

    def test_clear_stale_active_mode_devices_commits_when_nothing_stale(
        self, initialized_db, caplog
    ):
        """The UPDATE opens a write transaction even when it matches no rows,
        so the connection must not go back to the pool still holding it (the
        pool would roll it back, but only after the write lock has been held
        across the handoff — once per discovery cycle)."""
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    mac_address, ip_address, ipv4_address, detected_mode, active_mode,
                    first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                """,
                ("AA:BB:CC:DD:EE:74", "192.168.50.74", "192.168.50.74", "hotspot", "hotspot"),
            )
            conn.commit()

        with caplog.at_level(logging.WARNING, logger="database.connection"):
            assert _clear_stale_active_mode_devices("hotspot", 60) == 0

        assert not [
            r for r in caplog.records if "open transaction" in r.getMessage()
        ], "connection was returned to the pool with an open write transaction"

    def test_clear_stale_active_mode_devices_retries_when_locked(self, initialized_db, monkeypatch):
        attempts = {"count": 0, "commits": 0, "sleeps": []}

        class _FakeCursor:
            def __init__(self):
                self.rowcount = 0

            def execute(self, *_args, **_kwargs):
                attempts["count"] += 1
                if attempts["count"] < 3:
                    raise sqlite3.OperationalError("database is locked")
                self.rowcount = 2

        class _FakeConn:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def cursor(self):
                return _FakeCursor()

            def commit(self):
                attempts["commits"] += 1

        monkeypatch.setattr(
            "orchestration.discovery_manager.get_connection",
            lambda: _FakeConn(),
        )
        monkeypatch.setattr(
            "orchestration.discovery_manager.time.sleep",
            lambda seconds: attempts["sleeps"].append(seconds),
        )

        cleared = _clear_stale_active_mode_devices("hotspot", 60)

        assert cleared == 2
        assert attempts["count"] == 3
        assert attempts["commits"] == 1
        assert attempts["sleeps"] == [0.15, 0.3]

    def test_recently_confirmed_macs_respect_age_window(self, initialized_db, monkeypatch):
        now_box = {"t": 1_000.0}

        monkeypatch.setattr(
            "orchestration.discovery_manager.time.time",
            lambda: now_box["t"],
        )

        _mark_recently_confirmed_macs({"AA:BB:CC:DD:EE:90"})
        assert "AA:BB:CC:DD:EE:90" in _get_recently_confirmed_macs(HOTSPOT_STALE_DEVICE_SECONDS)

        now_box["t"] += HOTSPOT_STALE_DEVICE_SECONDS + 1
        assert "AA:BB:CC:DD:EE:90" not in _get_recently_confirmed_macs(HOTSPOT_STALE_DEVICE_SECONDS)


class TestHotspotCachePromotion:
    def test_promotes_arp_client_when_ping_confirmed(self):
        client = {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.137.22",
            "status": "arp",
            "source": "arp",
        }
        assert _should_promote_hotspot_cache_client(client, {"192.168.137.22"}) is True

    def test_does_not_promote_arp_client_without_confirmation(self):
        client = {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.137.22",
            "status": "arp",
            "source": "arp",
        }
        assert _should_promote_hotspot_cache_client(client, set()) is False

    def test_does_not_promote_non_arp_weak_source(self):
        client = {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.137.22",
            "status": "cache",
            "source": "hostednetwork",
        }
        assert _should_promote_hotspot_cache_client(client, {"192.168.137.22"}) is False
