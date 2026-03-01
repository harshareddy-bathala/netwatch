"""
test_realtime_state.py - Phase 4 InMemoryDashboardState Tests
================================================================

Validates the in-memory hot-path state used by the SSE push loop.
"""

import time
import threading
import pytest

from utils.realtime_state import InMemoryDashboardState, DeviceInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(
    source_mac="aa:bb:cc:dd:ee:01",
    dest_mac="aa:bb:cc:dd:ee:02",
    source_ip="192.168.1.10",
    dest_ip="192.168.1.20",
    bytes_count=1500,
    protocol="TCP",
    direction="upload",
    device_name="Phone",
    vendor="Apple",
    dest_vendor="Samsung",
):
    return {
        "source_mac": source_mac,
        "dest_mac": dest_mac,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "bytes": bytes_count,
        "protocol": protocol,
        "direction": direction,
        "device_name": device_name,
        "vendor": vendor,
        "dest_vendor": dest_vendor,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestUpdateFromBatch:
    """update_from_batch correctly maintains running totals."""

    def test_single_packet_updates_totals(self):
        state = InMemoryDashboardState()
        pkt = _make_packet(bytes_count=1000)
        state.update_from_batch([pkt])
        snap = state.snapshot()
        assert snap["today_bytes"] == 1000
        assert snap["today_packets"] == 1

    def test_multiple_packets_accumulate(self):
        state = InMemoryDashboardState()
        batch = [_make_packet(bytes_count=500) for _ in range(10)]
        state.update_from_batch(batch)
        snap = state.snapshot()
        assert snap["today_bytes"] == 5000
        assert snap["today_packets"] == 10

    def test_empty_batch_is_noop(self):
        state = InMemoryDashboardState()
        state.update_from_batch([])
        snap = state.snapshot()
        assert snap["today_bytes"] == 0
        assert snap["today_packets"] == 0

    def test_malformed_packets_skipped(self):
        state = InMemoryDashboardState()
        # Packet with no keys at all shouldn't crash
        state.update_from_batch([{}, {"bytes": None}, _make_packet(bytes_count=100)])
        snap = state.snapshot()
        # At least the valid packet is counted
        assert snap["today_packets"] >= 1


class TestDeviceTracking:
    """Device registry tracks MACs correctly."""

    def test_source_device_tracked(self):
        state = InMemoryDashboardState()
        state.update_from_batch([_make_packet(source_mac="aa:bb:cc:dd:ee:11")])
        assert state.device_count >= 1

    def test_broadcast_mac_not_tracked(self):
        state = InMemoryDashboardState()
        state.update_from_batch([
            _make_packet(source_mac="ff:ff:ff:ff:ff:ff",
                         dest_mac="00:00:00:00:00:00"),
        ])
        assert state.device_count == 0

    def test_bytes_sent_and_received(self):
        state = InMemoryDashboardState()
        mac = "aa:bb:cc:dd:ee:33"
        state.update_from_batch([
            _make_packet(source_mac=mac, bytes_count=100),
            _make_packet(dest_mac=mac, bytes_count=200),
        ])
        # mac appears as both source and dest
        devices = state.get_top_devices_memory(limit=10)
        device = next((d for d in devices if d["mac_address"] == mac), None)
        assert device is not None
        assert device["bytes_sent"] == 100
        assert device["bytes_received"] == 200
        assert device["total_bytes"] == 300

    def test_active_device_count(self):
        state = InMemoryDashboardState()
        macs = [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(5)]
        batch = [_make_packet(source_mac=m) for m in macs]
        state.update_from_batch(batch)
        assert state.get_active_device_count(minutes=5) >= 5

    def test_max_devices_respected(self):
        state = InMemoryDashboardState()
        state.MAX_DEVICES = 3
        batch = [_make_packet(source_mac=f"aa:bb:cc:dd:{i:02x}:01",
                              dest_mac=f"aa:bb:cc:dd:{i:02x}:02")
                 for i in range(10)]
        state.update_from_batch(batch)
        assert state.device_count <= 3


class TestTopDevices:
    """get_top_devices_memory returns sorted results."""

    def test_top_devices_sorted_by_bytes(self):
        state = InMemoryDashboardState()
        state.update_from_batch([
            _make_packet(source_mac="aa:bb:cc:00:00:01", bytes_count=100),
            _make_packet(source_mac="aa:bb:cc:00:00:02", bytes_count=5000),
            _make_packet(source_mac="aa:bb:cc:00:00:03", bytes_count=500),
        ])
        top = state.get_top_devices_memory(limit=3)
        assert len(top) >= 2
        # First device should have highest bytes
        assert top[0]["total_bytes"] >= top[-1]["total_bytes"]

    def test_top_devices_limit(self):
        state = InMemoryDashboardState()
        batch = [_make_packet(source_mac=f"aa:bb:cc:00:{i:02x}:01")
                 for i in range(20)]
        state.update_from_batch(batch)
        top = state.get_top_devices_memory(limit=5)
        assert len(top) <= 5


class TestProtocolDistribution:
    """Protocol tracking aggregates correctly."""

    def test_protocol_tracked(self):
        state = InMemoryDashboardState()
        state.update_from_batch([
            _make_packet(protocol="TCP", bytes_count=100),
            _make_packet(protocol="UDP", bytes_count=200),
            _make_packet(protocol="TCP", bytes_count=300),
        ])
        protocols = state.get_protocols()
        tcp = next((p for p in protocols if p["name"] == "TCP"), None)
        udp = next((p for p in protocols if p["name"] == "UDP"), None)
        assert tcp is not None
        assert tcp["bytes"] == 400
        assert tcp["count"] == 2
        assert udp is not None
        assert udp["bytes"] == 200

    def test_protocol_percentages(self):
        state = InMemoryDashboardState()
        state.update_from_batch([
            _make_packet(protocol="TCP", bytes_count=700),
            _make_packet(protocol="UDP", bytes_count=300),
        ])
        protocols = state.get_protocols()
        for p in protocols:
            assert "percentage" in p
        total_pct = sum(p["percentage"] for p in protocols)
        assert abs(total_pct - 100.0) < 0.1


class TestSnapshot:
    """snapshot() returns complete state."""

    def test_snapshot_keys(self):
        state = InMemoryDashboardState()
        snap = state.snapshot()
        assert "today_bytes" in snap
        assert "today_packets" in snap
        assert "active_devices" in snap
        assert "top_devices" in snap
        assert "protocols" in snap
        assert "last_update" in snap

    def test_snapshot_after_batches(self):
        state = InMemoryDashboardState()
        state.update_from_batch([_make_packet(bytes_count=1000)])
        state.update_from_batch([_make_packet(bytes_count=2000)])
        snap = state.snapshot()
        assert snap["today_bytes"] == 3000
        assert snap["today_packets"] == 2


class TestClear:
    """clear() resets all state."""

    def test_clear_resets(self):
        state = InMemoryDashboardState()
        state.update_from_batch([_make_packet(bytes_count=999)])
        assert state.device_count > 0
        state.clear()
        snap = state.snapshot()
        assert snap["today_bytes"] == 0
        assert snap["today_packets"] == 0
        assert state.device_count == 0


class TestThreadSafety:
    """Concurrent reads and writes don't crash or corrupt state."""

    def test_concurrent_access(self):
        state = InMemoryDashboardState()
        errors = []

        def writer():
            try:
                for _ in range(100):
                    state.update_from_batch([_make_packet()])
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    state.snapshot()
                    state.get_top_devices_memory()
                    state.get_active_device_count()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread errors: {errors}"


class TestQueryCacheThresholds:
    """Phase 4 query categorization applies correct thresholds."""

    def test_critical_path_threshold(self):
        """Critical-path functions get 200ms threshold."""
        from utils.query_cache import time_query
        import logging

        @time_query
        def get_dashboard_data():
            return "fast"

        # The decorator should use 200ms for this function name
        # We just verify it doesn't error on call
        result = get_dashboard_data()
        assert result == "fast"

    def test_background_threshold(self):
        """Non-critical functions get 500ms threshold."""
        from utils.query_cache import time_query

        @time_query
        def get_some_history():
            return "ok"

        result = get_some_history()
        assert result == "ok"


# ===================================================================
#  Mode-awareness / OWN_TRAFFIC_ONLY scope filtering
# ===================================================================

class TestModeAwareness:
    """Verify that set_mode_context() controls which MACs are tracked."""

    OUR_MAC = "aa:bb:cc:dd:ee:01"
    GW_MAC = "aa:bb:cc:dd:ee:02"
    STRANGER_MAC = "ff:ff:ff:00:00:01"
    STRANGER_MAC2 = "ff:ff:ff:00:00:02"

    def _make_state(self, own_traffic_only: bool):
        state = InMemoryDashboardState()
        state.set_mode_context(
            our_mac=self.OUR_MAC,
            gateway_mac=self.GW_MAC,
            own_traffic_only=own_traffic_only,
            gateway_mac_exclude=own_traffic_only,
        )
        return state

    # ---- OWN_TRAFFIC_ONLY = True ----

    def test_own_traffic_tracks_our_mac_as_source(self):
        state = self._make_state(own_traffic_only=True)
        state.update_from_batch([_make_packet(
            source_mac=self.OUR_MAC, dest_mac="ff:ff:ff:ff:ff:ff",
        )])
        assert state.get_active_device_count() == 1

    def test_own_traffic_excludes_gateway_mac_as_dest(self):
        """Gateway MAC should be excluded — only self is shown."""
        state = self._make_state(own_traffic_only=True)
        state.update_from_batch([_make_packet(
            source_mac=self.OUR_MAC, dest_mac=self.GW_MAC,
        )])
        # Only OUR_MAC should be tracked, not GW_MAC
        assert state.get_active_device_count() == 1

    def test_own_traffic_rejects_stranger_source(self):
        state = self._make_state(own_traffic_only=True)
        state.update_from_batch([_make_packet(
            source_mac=self.STRANGER_MAC, dest_mac="ff:ff:ff:ff:ff:ff",
        )])
        assert state.get_active_device_count() == 0

    def test_own_traffic_rejects_stranger_dest(self):
        state = self._make_state(own_traffic_only=True)
        state.update_from_batch([_make_packet(
            source_mac=self.OUR_MAC, dest_mac=self.STRANGER_MAC,
        )])
        # Only OUR_MAC should be tracked, not STRANGER_MAC
        assert state.get_active_device_count() == 1

    def test_own_traffic_mixed_batch(self):
        """Batch with both allowed and disallowed MACs."""
        state = self._make_state(own_traffic_only=True)
        state.update_from_batch([
            _make_packet(source_mac=self.OUR_MAC, dest_mac=self.GW_MAC),
            _make_packet(source_mac=self.STRANGER_MAC, dest_mac=self.STRANGER_MAC2),
            _make_packet(source_mac=self.OUR_MAC, dest_mac=self.STRANGER_MAC),
        ])
        # Only OUR_MAC should be tracked (gateway excluded)
        assert state.get_active_device_count() == 1

    def test_own_traffic_case_insensitive(self):
        """MAC comparison should be case-insensitive."""
        state = self._make_state(own_traffic_only=True)
        state.update_from_batch([_make_packet(
            source_mac=self.OUR_MAC.upper(), dest_mac="ff:ff:ff:ff:ff:ff",
        )])
        assert state.get_active_device_count() == 1

    # ---- OWN_TRAFFIC_ONLY = False (hotspot / ethernet) ----

    def test_unrestricted_tracks_all_macs(self):
        state = self._make_state(own_traffic_only=False)
        state.update_from_batch([
            _make_packet(source_mac=self.OUR_MAC, dest_mac=self.GW_MAC),
            _make_packet(source_mac=self.STRANGER_MAC, dest_mac=self.STRANGER_MAC2),
        ])
        assert state.get_active_device_count() == 4

    # ---- clear() does NOT reset mode context ----

    def test_clear_preserves_mode_context(self):
        state = self._make_state(own_traffic_only=True)
        state.clear()
        state.update_from_batch([_make_packet(
            source_mac=self.STRANGER_MAC, dest_mac="ff:ff:ff:ff:ff:ff",
        )])
        # Mode context still active → stranger rejected
        assert state.get_active_device_count() == 0

    # ---- set_mode_context overrides previous setting ----

    def test_set_mode_context_overrides(self):
        state = self._make_state(own_traffic_only=True)
        # Switch to unrestricted
        state.set_mode_context(own_traffic_only=False)
        state.update_from_batch([_make_packet(
            source_mac=self.STRANGER_MAC, dest_mac="ff:ff:ff:ff:ff:ff",
        )])
        assert state.get_active_device_count() == 1

    def test_default_is_unrestricted(self):
        """Fresh state should track all MACs (backward compat)."""
        state = InMemoryDashboardState()
        state.update_from_batch([
            _make_packet(source_mac=self.STRANGER_MAC, dest_mac="ff:ff:ff:ff:ff:ff"),
            _make_packet(source_mac=self.STRANGER_MAC2, dest_mac="ff:ff:ff:ff:ff:ff"),
        ])
        assert state.get_active_device_count() == 2
