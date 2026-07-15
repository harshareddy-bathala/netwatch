"""
test_mode_transition_packet_handling.py - Phase 4 Transition Packet Tests
===========================================================================

Verifies transition-window packet behavior across the packet pipeline:

- PacketProcessor tags packets captured during mode transitions.
- DatabaseWriter excludes transition packets from in-memory dashboard updates.
- InMemoryDashboardState ignores transition packets in totals and device tracking.
- save_packets_batch classifies transition packets as control traffic.
"""

import os
import sys
import sqlite3
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_ethernet_mode(ip_address: str = "192.168.1.100"):
    from packet_capture.modes.base_mode import InterfaceInfo
    from packet_capture.modes.ethernet_mode import EthernetMode

    info = InterfaceInfo(
        name="eth0",
        friendly_name="Ethernet",
        ip_address=ip_address,
        mac_address="AA:BB:CC:DD:EE:FF",
        netmask="255.255.255.0",
        gateway="192.168.1.1",
        ssid=None,
        interface_type="ethernet",
        is_active=True,
    )
    return EthernetMode(info)


def _make_scapy_packet(src_ip: str, dst_ip: str):
    scapy = pytest.importorskip("scapy.all")
    return (
        scapy.Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / scapy.IP(src=src_ip, dst=dst_ip, ttl=64)
        / scapy.TCP(sport=52345, dport=443, flags="PA")
    )


def _make_packet_dict(
    source_mac: str = "aa:bb:cc:dd:ee:01",
    dest_mac: str = "aa:bb:cc:dd:ee:02",
    source_ip: str = "192.168.1.10",
    dest_ip: str = "8.8.8.8",
    bytes_count: int = 1000,
    direction: str = "upload",
):
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_mac": source_mac,
        "dest_mac": dest_mac,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "source_port": 52345,
        "dest_port": 443,
        "protocol": "HTTPS",
        "raw_protocol": "TCP",
        "bytes": bytes_count,
        "direction": direction,
    }


@pytest.fixture(autouse=True)
def _reset_transition_phase():
    from orchestration import state as orch_state

    original_phase = orch_state.mode_transition_phase
    orch_state.mode_transition_phase = "STABLE"
    try:
        yield
    finally:
        orch_state.mode_transition_phase = original_phase


class TestPacketProcessorTransitionHandling:
    def test_transition_packets_are_tagged_and_forced_to_transition_direction(self, monkeypatch):
        from packet_capture.packet_processor import PacketProcessor, _orch_state

        if _orch_state is None:
            pytest.skip("orchestration state unavailable")

        mode = _make_ethernet_mode()
        processor = PacketProcessor(mode, local_ips={mode.interface.ip_address})
        packet = _make_scapy_packet(mode.interface.ip_address, "8.8.8.8")

        monkeypatch.setattr(_orch_state, "mode_transition_phase", "EXITING_ETHERNET", raising=False)

        parsed = processor.process(packet)
        assert parsed is not None
        assert parsed.direction == "transition"
        assert parsed.is_control_traffic is True
        assert parsed.extra.get("is_transition_packet") is True
        assert parsed.extra.get("transition_phase") == "EXITING_ETHERNET"

    def test_stable_phase_packets_remain_non_transition(self, monkeypatch):
        from packet_capture.packet_processor import PacketProcessor, _orch_state

        if _orch_state is None:
            pytest.skip("orchestration state unavailable")

        mode = _make_ethernet_mode()
        processor = PacketProcessor(mode, local_ips={mode.interface.ip_address})
        packet = _make_scapy_packet(mode.interface.ip_address, "1.1.1.1")

        monkeypatch.setattr(_orch_state, "mode_transition_phase", "STABLE", raising=False)

        parsed = processor.process(packet)
        assert parsed is not None
        assert parsed.direction == "upload"
        assert parsed.is_control_traffic is False
        assert parsed.extra.get("is_transition_packet", False) is False
        assert parsed.extra.get("transition_phase") is None


class TestDatabaseWriterTransitionFiltering:
    def test_writer_excludes_transition_packets_from_dashboard_state_updates(self):
        from packet_capture.database_writer import DatabaseWriter, dashboard_state

        writer = DatabaseWriter(max_queue_size=10)
        writer._save_fn = MagicMock(return_value=2)

        normal_packet = _make_packet_dict(
            source_mac="aa:bb:cc:dd:ee:01",
            dest_mac="aa:bb:cc:dd:ee:02",
            bytes_count=1200,
        )
        transition_packet = _make_packet_dict(
            source_mac="aa:bb:cc:dd:ee:03",
            dest_mac="aa:bb:cc:dd:ee:04",
            bytes_count=900,
            direction="transition",
        )
        transition_packet["transition_phase"] = "ENTERING_PUBLIC_NETWORK"

        writer.enqueue([normal_packet, transition_packet])
        writer._stop_event.set()

        with patch.object(dashboard_state, "update_from_batch") as mock_update:
            writer._run()

        writer._save_fn.assert_called_once()
        mock_update.assert_called_once()
        dashboard_batch = mock_update.call_args.args[0]
        assert dashboard_batch == [normal_packet]

    def test_writer_skips_dashboard_update_when_batch_save_fails(self):
        from packet_capture.database_writer import DatabaseWriter, dashboard_state

        writer = DatabaseWriter(max_queue_size=10)
        writer._save_fn = MagicMock(return_value=-1)

        packet = _make_packet_dict(
            source_mac="aa:bb:cc:dd:ee:11",
            dest_mac="aa:bb:cc:dd:ee:12",
            bytes_count=500,
        )

        writer.enqueue([packet])
        writer._stop_event.set()

        with patch.object(dashboard_state, "update_from_batch") as mock_update:
            writer._run()

        writer._save_fn.assert_called_once()
        mock_update.assert_not_called()
        assert writer.db_errors == 1


class TestRealtimeStateTransitionFiltering:
    def test_update_from_batch_ignores_transition_packets(self):
        from utils.realtime_state import InMemoryDashboardState

        state = InMemoryDashboardState()
        normal_packet = _make_packet_dict(
            source_mac="aa:bb:cc:dd:ee:01",
            dest_mac="aa:bb:cc:dd:ee:02",
            bytes_count=1000,
        )
        transition_packet = _make_packet_dict(
            source_mac="aa:bb:cc:dd:ee:03",
            dest_mac="aa:bb:cc:dd:ee:04",
            bytes_count=750,
            direction="transition",
        )
        transition_packet["transition_phase"] = "EXITING_ETHERNET"

        state.update_from_batch([normal_packet, transition_packet])
        snapshot = state.snapshot()

        assert snapshot["today_bytes"] == 1000
        assert snapshot["today_packets"] == 1
        assert state.device_count == 1


class TestPacketStoreTransitionClassification:
    def test_save_packets_batch_marks_transition_phase_packets_as_control(self, initialized_db):
        from database.queries.device_queries import save_packets_batch

        packet = _make_packet_dict(direction="transition", bytes_count=512)
        packet["transition_phase"] = "ENTERING_PUBLIC_NETWORK"

        saved = save_packets_batch([packet])
        assert saved == 1

        conn = sqlite3.connect(initialized_db)
        try:
            row = conn.execute(
                "SELECT is_control, direction FROM traffic_summary ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()

        assert row is not None
        assert row[0] == 1
        assert row[1] == "transition"
