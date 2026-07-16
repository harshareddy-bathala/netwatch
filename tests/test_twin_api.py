"""
test_twin_api.py - Twin & Intelligence API Tests (Phase 1)
===========================================================

Covers backend/blueprints/twin_bp.py: twin snapshot, stats, flow/DNS
telemetry reads, behavior profile lookup, and graceful degradation
when the intelligence services are not running.
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestTwinEndpoint:

    def test_twin_empty_when_not_running(self, client):
        resp = client.get('/api/twin')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert data['nodes'] == []
        assert data['edges'] == []
        assert 'stats' in data

    def test_twin_returns_live_snapshot(self, client):
        from orchestration import state
        from intelligence.twin import TwinBuilder
        from intelligence.event_bus import EventBus

        twin = TwinBuilder(bus=EventBus(), seed_from_db=False)
        twin.ingest_packets([{
            "source_mac": "aa:bb:cc:00:00:01", "dest_mac": "aa:bb:cc:00:00:99",
            "source_ip": "192.168.1.10", "dest_ip": "93.184.216.34",
            "protocol": "HTTPS", "bytes": 1234,
        }])
        state.twin_builder = twin
        try:
            resp = client.get('/api/twin')
            assert resp.status_code == 200
            data = resp.get_json()['data']
            assert data['stats']['node_count'] == 2
            assert len(data['edges']) == 1
            assert data['edges'][0]['bytes'] == 1234
        finally:
            state.twin_builder = None

    def test_twin_max_edges_clamped(self, client):
        resp = client.get('/api/twin?max_edges=999999')
        assert resp.status_code == 200

    def test_twin_stats_endpoint(self, client):
        resp = client.get('/api/twin/stats')
        assert resp.status_code == 200
        data = resp.get_json()['data']
        assert 'twin' in data and 'behavior' in data and 'event_bus' in data


class TestTelemetryEndpoints:

    def test_flows_recent_empty(self, client):
        resp = client.get('/api/flows/recent')
        assert resp.status_code == 200
        assert resp.get_json()['data'] == []

    def test_flows_recent_returns_rows(self, client, db_connection):
        db_connection.execute("""
            INSERT INTO flows (first_seen, last_seen, source_ip, dest_ip,
                               source_port, dest_port, protocol, direction,
                               source_mac, bytes_total, packets_total,
                               is_control, duration_seconds)
            VALUES ('2026-07-14 10:00:00', '2026-07-14 10:00:30',
                    '192.168.1.10', '1.2.3.4', 50000, 443, 'HTTPS', 'upload',
                    'aa:bb:cc:00:00:01', 600, 3, 0, 30.0)
        """)
        db_connection.commit()
        resp = client.get('/api/flows/recent?mac=aa:bb:cc:00:00:01')
        assert resp.status_code == 200
        rows = resp.get_json()['data']
        assert len(rows) == 1
        assert rows[0]['bytes_total'] == 600

    def test_dns_recent_returns_rows(self, client, db_connection):
        db_connection.execute("""
            INSERT INTO dns_queries (timestamp, source_ip, source_mac,
                                     qname, qtype, protocol)
            VALUES ('2026-07-14 10:00:00', '192.168.1.10',
                    'aa:bb:cc:00:00:01', 'example.com', 1, 'DNS')
        """)
        db_connection.commit()
        resp = client.get('/api/dns/recent')
        assert resp.status_code == 200
        rows = resp.get_json()['data']
        assert len(rows) == 1
        assert rows[0]['qname'] == 'example.com'

    def test_limit_clamped(self, client):
        resp = client.get('/api/flows/recent?limit=999999')
        assert resp.status_code == 200

    def test_activity_enriches_with_device_name(self, client, db_connection):
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db_connection.execute("""
            INSERT INTO devices (mac_address, ip_address, hostname, first_seen, last_seen)
            VALUES ('aa:bb:cc:00:00:07', '192.168.137.70', 'moto-g34-5G',
                    ?, ?)
        """, (now, now))
        db_connection.execute("""
            INSERT INTO dns_queries (timestamp, source_ip, source_mac,
                                     qname, qtype, protocol)
            VALUES (?, '192.168.137.70', 'aa:bb:cc:00:00:07',
                    'instagram.com', 1, 'DNS')
        """, (now,))
        db_connection.commit()
        resp = client.get('/api/activity/recent')
        assert resp.status_code == 200
        rows = resp.get_json()['data']
        match = [r for r in rows if r['qname'] == 'instagram.com']
        assert match, "recent DNS lookup should appear in the activity feed"
        assert match[0]['device_name'] == 'moto-g34-5G'

    def test_activity_returns_unnamed_client(self, client, db_connection):
        """A lookup from a device with no directory row still appears (the
        client is simply shown by IP/MAC)."""
        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db_connection.execute("""
            INSERT INTO dns_queries (timestamp, source_ip, source_mac,
                                     qname, qtype, protocol)
            VALUES (?, '192.168.137.71', 'aa:bb:cc:00:00:08',
                    'unknown-app.example', 1, 'DNS')
        """, (now,))
        db_connection.commit()
        resp = client.get('/api/activity/recent')
        assert resp.status_code == 200
        rows = resp.get_json()['data']
        match = [r for r in rows if r['qname'] == 'unknown-app.example']
        assert match and match[0]['device_name'] is None

    def test_activity_window_excludes_old(self, client, db_connection):
        db_connection.execute("""
            INSERT INTO dns_queries (timestamp, source_ip, source_mac,
                                     qname, qtype, protocol)
            VALUES ('2020-01-01 00:00:00', '192.168.137.72',
                    'aa:bb:cc:00:00:09', 'ancient.example', 1, 'DNS')
        """)
        db_connection.commit()
        resp = client.get('/api/activity/recent?minutes=5')
        assert resp.status_code == 200
        rows = resp.get_json()['data']
        assert not any(r['qname'] == 'ancient.example' for r in rows)


class TestBehaviorEndpoint:

    def test_profile_empty_when_not_running(self, client):
        resp = client.get('/api/behavior/profiles/aa:bb:cc:00:00:01')
        assert resp.status_code == 200
        assert resp.get_json()['data']['metrics'] == {}

    def test_profile_returns_learned_baselines(self, client):
        from unittest.mock import MagicMock
        from orchestration import state
        from intelligence.behavior import BehaviorAnalyzer
        from intelligence.event_bus import EventBus

        clock = [1_750_000_000.0]
        analyzer = BehaviorAnalyzer(
            alert_engine=MagicMock(), bus=EventBus(), persist=False,
            now_fn=lambda: clock[0], window_seconds=60,
            min_baseline_samples=3,
        )
        for _ in range(3):
            analyzer.ingest_flow({
                "source_mac": "aa:bb:cc:00:00:01",
                "dest_ip": "1.2.3.4", "bytes_total": 1000,
            })
            clock[0] += 61
            analyzer.close_expired_windows()

        state.behavior_analyzer = analyzer
        try:
            resp = client.get('/api/behavior/profiles/AA:BB:CC:00:00:01')
            assert resp.status_code == 200
            data = resp.get_json()['data']
            assert data['mac'] == 'aa:bb:cc:00:00:01'
            assert any(data['metrics'][m] for m in data['metrics'])
        finally:
            state.behavior_analyzer = None
