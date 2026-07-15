"""
test_hotspot_client_parsing.py - Hotspot client parsing regressions
===================================================================
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestHotspotClientParsing:
    def test_windows_clients_skip_host_mac_and_non_client_status(self, hotspot_mode, monkeypatch):
        from packet_capture.modes import hotspot_mode as hm

        hostednetwork_output = """
Hosted network status
---------------------
Status                 : Started
BSSID                  : aa:bb:cc:11:22:33
Number of clients      : 3
    1                  aa:bb:cc:dd:ee:01     Authenticated
    2                  aa:bb:cc:11:22:33     Connected
    3                  aa:bb:cc:dd:ee:02     Idle
"""

        arp_output = """
Interface: 192.168.137.1 --- 0x11
  Internet Address      Physical Address      Type
  192.168.137.20        aa-bb-cc-dd-ee-01     dynamic
  192.168.137.30        aa-bb-cc-dd-ee-03     dynamic
  192.168.137.200       aa-bb-cc-11-22-33     dynamic
"""

        def _fake_run_command(cmd):
            if cmd[:4] == ["netsh", "wlan", "show", "hostednetwork"]:
                return hostednetwork_output
            if cmd[:2] == ["arp", "-a"]:
                return arp_output
            return ""

        monkeypatch.setattr(hm, "IS_WINDOWS", True)
        monkeypatch.setattr(hm, "run_command", _fake_run_command)
        monkeypatch.setattr(
            hotspot_mode,
            "_collect_local_macs",
            lambda: {"aa:bb:cc:11:22:33"},
        )

        clients = hotspot_mode._get_windows_clients()
        macs = [c["mac"] for c in clients]
        by_mac = {c["mac"]: c for c in clients}

        assert "aa:bb:cc:11:22:33" not in macs
        assert "aa:bb:cc:dd:ee:01" in macs
        assert "aa:bb:cc:dd:ee:03" not in macs
        assert "aa:bb:cc:dd:ee:02" not in macs
        assert macs.count("aa:bb:cc:dd:ee:01") == 1
        assert by_mac["aa:bb:cc:dd:ee:01"]["ip"] == "192.168.137.20"
        assert by_mac["aa:bb:cc:dd:ee:01"].get("source") == "hostednetwork"

    def test_parse_arp_table_excludes_local_mac_even_with_non_local_ip(self, hotspot_mode, monkeypatch):
        from packet_capture.modes import hotspot_mode as hm

        arp_output = """
Interface: 192.168.137.1 --- 0x11
  Internet Address      Physical Address      Type
  192.168.137.200       aa-bb-cc-11-22-33     dynamic
  192.168.137.40        aa-bb-cc-dd-ee-40     dynamic
"""

        monkeypatch.setattr(hm, "IS_WINDOWS", True)
        monkeypatch.setattr(hm, "run_command", lambda _cmd: arp_output)
        monkeypatch.setattr(
            hotspot_mode,
            "_collect_local_macs",
            lambda: {"aa:bb:cc:11:22:33"},
        )

        clients = hotspot_mode._parse_arp_table()

        assert len(clients) == 1
        assert clients[0]["mac"] == "aa:bb:cc:dd:ee:40"
        assert clients[0]["ip"] == "192.168.137.40"
