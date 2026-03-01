"""
test_self_ip_exclusion.py — Hotspot self-IP / MAC exclusion tests
==================================================================

Ensures that the host's own IPs and MACs (including the hotspot virtual
adapter's MAC, which differs from the physical WiFi MAC) are never
counted as discovered client devices.
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packet_capture.network_discovery import NetworkDiscovery


# ===================================================================
# MAC Validation
# ===================================================================

class TestMACValidation:
    """Tests for NetworkDiscovery.is_valid_mac()."""

    @pytest.mark.parametrize("mac", [
        "AA:BB:CC:DD:EE:FF",
        "aa:bb:cc:dd:ee:ff",
        "00:11:22:33:44:55",
        "2E:D0:43:A5:11:0C",
        "AA-BB-CC-DD-EE-FF",   # dash-separated (Windows format)
    ])
    def test_valid_macs(self, mac):
        assert NetworkDiscovery.is_valid_mac(mac) is True

    @pytest.mark.parametrize("mac", [
        ":::",                             # from ARP cache bug
        "",                                # empty
        "00:00:00",                        # too short
        "GG:HH:II:JJ:KK:LL",             # non-hex chars
        "AABBCCDDEEFF",                    # no separators
        "AA:BB:CC:DD:EE:FF:00",           # too many groups
        "A:B:C:D:E:F",                    # single-char groups
    ])
    def test_invalid_macs(self, mac):
        assert NetworkDiscovery.is_valid_mac(mac) is False


# ===================================================================
# Self-IP / MAC Exclusion in _add_device()
# ===================================================================

class TestAddDeviceExclusion:
    """Tests for _add_device() rejecting self-IPs, self-MACs, and bad MACs."""

    def _make_discovery(self, exclude_ips=None, exclude_macs=None):
        disc = NetworkDiscovery.__new__(NetworkDiscovery)
        disc.discovered_devices = {}
        disc._max_discovered_devices = 100
        disc.discovery_lock = __import__("threading").Lock()
        disc.exclude_ips = exclude_ips or set()
        disc.exclude_macs = {m.upper() for m in (exclude_macs or set())}
        return disc

    def test_add_device_normal(self):
        disc = self._make_discovery()
        disc._add_device({
            "ip": "192.168.137.5", "mac": "AA:BB:CC:DD:EE:01",
            "discovery_method": "arp",
        })
        assert "AA:BB:CC:DD:EE:01" in disc.discovered_devices

    def test_add_device_rejects_self_ip(self):
        disc = self._make_discovery(exclude_ips={"192.168.137.1"})
        disc._add_device({
            "ip": "192.168.137.1", "mac": "2E:D0:43:A5:11:0C",
            "discovery_method": "arp",
        })
        assert len(disc.discovered_devices) == 0

    def test_add_device_rejects_self_mac(self):
        disc = self._make_discovery(exclude_macs={"2E:D0:43:A5:11:0C"})
        disc._add_device({
            "ip": "192.168.137.99", "mac": "2E:D0:43:A5:11:0C",
            "discovery_method": "arp",
        })
        assert len(disc.discovered_devices) == 0

    def test_add_device_rejects_invalid_mac(self):
        disc = self._make_discovery()
        disc._add_device({
            "ip": "192.168.137.1", "mac": ":::",
            "discovery_method": "arp_cache",
        })
        assert len(disc.discovered_devices) == 0

    def test_add_device_rejects_short_mac(self):
        disc = self._make_discovery()
        disc._add_device({
            "ip": "192.168.137.1", "mac": "00:00:00",
            "discovery_method": "arp_cache",
        })
        assert len(disc.discovered_devices) == 0


# ===================================================================
# Self-IP Exclusion in arp_scan()
# ===================================================================

class TestArpScanExclusion:
    """arp_scan() should skip the host's own IPs/MACs."""

    def _make_discovery(self, exclude_ips=None, exclude_macs=None):
        disc = NetworkDiscovery.__new__(NetworkDiscovery)
        disc.interface = "Wi-Fi"
        disc.subnet = "192.168.137.0/24"
        disc.discovered_devices = {}
        disc._max_discovered_devices = 100
        disc.discovery_lock = __import__("threading").Lock()
        disc.arp_timeout = 1
        disc.exclude_ips = exclude_ips or set()
        disc.exclude_macs = {m.upper() for m in (exclude_macs or set())}
        return disc

    @patch("packet_capture.network_discovery.SCAPY_AVAILABLE", True)
    @patch("packet_capture.network_discovery.srp")
    @patch("packet_capture.network_discovery.Ether")
    @patch("packet_capture.network_discovery.ARP")
    def test_arp_scan_skips_self_ip(self, mock_arp, mock_ether, mock_srp):
        """Self-IP responses should not appear in the results."""
        # Mock: two responses — one is self (192.168.137.1), one is a real client
        self_resp = MagicMock()
        self_resp.psrc = "192.168.137.1"
        self_resp.hwsrc = "2E:D0:43:A5:11:0C"

        client_resp = MagicMock()
        client_resp.psrc = "192.168.137.5"
        client_resp.hwsrc = "AA:BB:CC:DD:EE:01"

        mock_srp.return_value = (
            [(MagicMock(), self_resp), (MagicMock(), client_resp)],
            [],
        )

        disc = self._make_discovery(
            exclude_ips={"192.168.137.1"},
            exclude_macs={"2E:D0:43:A5:11:0C"},
        )
        disc._resolve_hostname = MagicMock(return_value="")
        disc._get_mac_vendor = MagicMock(return_value="")
        disc._last_arp_device_count = -1

        devices = disc.arp_scan()
        # Only the real client should appear
        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.137.5"


# ===================================================================
# Self-IP / MAC Exclusion + MAC Validation in arp_cache_scan()
# ===================================================================

class TestArpCacheScanExclusion:
    """arp_cache_scan() should skip self-IPs and reject malformed MACs."""

    def _make_discovery(self, exclude_ips=None, exclude_macs=None,
                        subnet="192.168.137.0/24"):
        disc = NetworkDiscovery.__new__(NetworkDiscovery)
        disc.interface = "Wi-Fi"
        disc.subnet = subnet
        disc.discovered_devices = {}
        disc._max_discovered_devices = 100
        disc.discovery_lock = __import__("threading").Lock()
        disc.exclude_ips = exclude_ips or set()
        disc.exclude_macs = {m.upper() for m in (exclude_macs or set())}
        return disc

    @patch("subprocess.run")
    def test_arp_cache_skips_self_ip(self, mock_run):
        """Self-IP entries in the ARP cache should be excluded."""
        mock_run.return_value = MagicMock(
            stdout=(
                "  192.168.137.1    2e-d0-43-a5-11-0c    dynamic\n"
                "  192.168.137.5    aa-bb-cc-dd-ee-01    dynamic\n"
            ),
            returncode=0,
        )
        disc = self._make_discovery(exclude_ips={"192.168.137.1"})
        disc._resolve_hostname = MagicMock(return_value="")

        with patch("packet_capture.network_discovery.sys") as mock_sys:
            mock_sys.platform = "win32"
            devices = disc.arp_cache_scan()

        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.137.5"

    @patch("subprocess.run")
    def test_arp_cache_rejects_malformed_mac(self, mock_run):
        """Entries with ':::' or similar malformed MACs should be rejected."""
        mock_run.return_value = MagicMock(
            stdout=(
                "  192.168.137.1    ---    dynamic\n"
                "  192.168.137.5    aa-bb-cc-dd-ee-01    dynamic\n"
            ),
            returncode=0,
        )
        disc = self._make_discovery()
        disc._resolve_hostname = MagicMock(return_value="")

        with patch("packet_capture.network_discovery.sys") as mock_sys:
            mock_sys.platform = "win32"
            devices = disc.arp_cache_scan()

        # '---' becomes ':::' after replace('-', ':') — should be rejected
        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.137.5"


# ===================================================================
# set_exclusions() and _is_self() helpers
# ===================================================================

class TestExclusionHelpers:
    """Tests for set_exclusions() and _is_self()."""

    def _make_discovery(self):
        disc = NetworkDiscovery.__new__(NetworkDiscovery)
        disc.exclude_ips = set()
        disc.exclude_macs = set()
        return disc

    def test_set_exclusions_stores_upper_macs(self):
        disc = self._make_discovery()
        disc.set_exclusions(
            ips={"192.168.137.1"},
            macs={"2e:d0:43:a5:11:0c"},
        )
        assert "192.168.137.1" in disc.exclude_ips
        assert "2E:D0:43:A5:11:0C" in disc.exclude_macs

    def test_is_self_by_ip(self):
        disc = self._make_discovery()
        disc.exclude_ips = {"192.168.137.1"}
        assert disc._is_self("192.168.137.1", "AA:BB:CC:DD:EE:FF") is True

    def test_is_self_by_mac(self):
        disc = self._make_discovery()
        disc.exclude_macs = {"2E:D0:43:A5:11:0C"}
        assert disc._is_self("10.0.0.99", "2E:D0:43:A5:11:0C") is True

    def test_is_self_negative(self):
        disc = self._make_discovery()
        disc.exclude_ips = {"192.168.137.1"}
        disc.exclude_macs = {"2E:D0:43:A5:11:0C"}
        assert disc._is_self("192.168.137.5", "AA:BB:CC:DD:EE:01") is False

    def test_is_self_case_insensitive_mac(self):
        disc = self._make_discovery()
        disc.exclude_macs = {"2E:D0:43:A5:11:0C"}
        assert disc._is_self(None, "2e:d0:43:a5:11:0c") is True
