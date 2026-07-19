"""
test_dashboard_device_count.py - Dashboard count must equal the Devices list
=============================================================================

Observed live: the Dashboard header read "2 devices" while the Devices page
listed exactly 1 (a single phone). The list dropped the monitoring host; the
in-memory count that feeds the dashboard did not. Both must agree.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.realtime_state import InMemoryDashboardState, DeviceInfo


HOST_MAC = "2e:d0:43:a5:22:70"
HOST_IP = "192.168.137.1"
PHONE_MAC = "22:5e:3e:1a:d0:f3"
PHONE_IP = "192.168.137.142"


def _hotspot_state():
    state = InMemoryDashboardState()
    state.set_mode_context(
        host_macs={HOST_MAC},
        our_mac="",                 # hotspot virtual adapter is invisible
        gateway_mac=HOST_MAC,       # in hotspot the host IS the gateway
        own_traffic_only=False,
        gateway_mac_exclude=True,
        our_ip=HOST_IP,
    )
    return state


def _add(state, mac, ip):
    with state._lock:
        state._devices[mac] = DeviceInfo(
            mac_address=mac, ip_address=ip, last_seen=time.time(),
        )


class TestHostExcludedFromCount:

    def test_host_not_counted_in_hotspot(self):
        state = _hotspot_state()
        _add(state, HOST_MAC, HOST_IP)
        _add(state, PHONE_MAC, PHONE_IP)
        assert state.get_active_device_count() == 1

    def test_host_excluded_by_ip_when_mac_differs(self):
        """The ICS adapter's MAC often isn't detectable — IP must still match."""
        state = _hotspot_state()
        _add(state, "aa:bb:cc:dd:ee:ff", HOST_IP)
        _add(state, PHONE_MAC, PHONE_IP)
        assert state.get_active_device_count() == 1

    def test_only_host_present_counts_zero(self):
        """Nothing connected must read 0, not 1."""
        state = _hotspot_state()
        _add(state, HOST_MAC, HOST_IP)
        assert state.get_active_device_count() == 0

    def test_dashboard_stats_agree_with_count(self):
        state = _hotspot_state()
        _add(state, HOST_MAC, HOST_IP)
        _add(state, PHONE_MAC, PHONE_IP)
        stats = state.snapshot()
        assert stats["active_devices"] == state.get_active_device_count() == 1

    def test_own_traffic_mode_still_counts_host(self):
        """public_network mode monitors THIS machine — it must stay visible."""
        state = InMemoryDashboardState()
        state.set_mode_context(
            host_macs={HOST_MAC}, our_mac=HOST_MAC, gateway_mac="",
            own_traffic_only=True, gateway_mac_exclude=False,
            our_ip="192.168.1.68",
        )
        _add(state, HOST_MAC, "192.168.1.68")
        assert state.get_active_device_count() == 1
