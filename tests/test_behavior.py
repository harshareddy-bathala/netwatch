"""
test_behavior.py - Behavior Learning Tests (Phase 1)
=====================================================

Covers ``intelligence.behavior``: Welford baselines, warm-up guard,
z-score anomaly detection with evidence + confidence, baseline
poisoning protection, and profile persistence.
"""

import sys
import os
import math
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus
from intelligence.behavior import BehaviorAnalyzer, _Baseline, hour_of_week

PHONE = "aa:bb:cc:00:00:02"


class FakeClock:
    def __init__(self, start=1_750_000_000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _flow(mac=PHONE, dest="1.2.3.4", nbytes=1000):
    return {"source_mac": mac, "dest_ip": dest, "bytes_total": nbytes}


def _analyzer(clock, engine=None, **kw):
    kw.setdefault("window_seconds", 60)
    kw.setdefault("min_baseline_samples", 3)
    kw.setdefault("z_threshold", 4.0)
    return BehaviorAnalyzer(
        alert_engine=engine or MagicMock(),
        bus=EventBus(),
        persist=False,
        now_fn=clock,
        **kw,
    )


def _run_normal_window(analyzer, clock, nbytes=1000, flows=3):
    """Ingest a typical window and close it."""
    for i in range(flows):
        analyzer.ingest_flow(_flow(dest=f"1.2.3.{i + 1}", nbytes=nbytes // flows))
    clock.advance(61)
    return analyzer.close_expired_windows()


class TestBaselineMath:

    def test_welford_matches_numpy_style_stats(self):
        b = _Baseline()
        values = [10, 12, 14, 16, 18]
        for v in values:
            b.update(v)
        assert b.count == 5
        assert abs(b.mean - 14.0) < 1e-9
        # Sample std of [10,12,14,16,18] = sqrt(10)
        assert abs(b.std - math.sqrt(10)) < 1e-9

    def test_z_score_uses_std_floor(self):
        b = _Baseline()
        for _ in range(10):
            b.update(100.0)  # zero variance
        # Floor = 10% of mean = 10 → z for 200 = 10, not infinity
        assert abs(b.z_score(200.0) - 10.0) < 1e-9

    def test_hour_of_week_range(self):
        assert 0 <= hour_of_week() <= 167


class TestWarmup:

    def test_no_alert_before_min_samples(self):
        clock = FakeClock()
        engine = MagicMock()
        analyzer = _analyzer(clock, engine)

        # Two normal windows, then a wild spike — baseline has only
        # 2 samples (< 3 required), so no anomaly may fire.
        for _ in range(2):
            _run_normal_window(analyzer, clock)
        analyzer.ingest_flow(_flow(nbytes=10_000_000))
        clock.advance(61)
        reports = analyzer.close_expired_windows()
        assert reports == []
        engine.create_behavior_alert.assert_not_called()

    def test_normal_windows_grow_baseline(self):
        clock = FakeClock()
        analyzer = _analyzer(clock)
        for _ in range(4):
            _run_normal_window(analyzer, clock)
        summary = analyzer.get_profile_summary(PHONE)
        # All windows land in fake-clock hours; entries must exist
        total_samples = sum(
            e["samples"] for entries in summary["metrics"].values() for e in entries
        )
        assert total_samples >= 4  # at least the bytes metric learned 4x


class TestAnomalyDetection:

    def _trained(self, clock, engine):
        analyzer = _analyzer(clock, engine)
        for _ in range(5):
            _run_normal_window(analyzer, clock, nbytes=1000, flows=3)
        return analyzer

    def test_spike_produces_evidence_and_alert(self):
        clock = FakeClock()
        engine = MagicMock()
        analyzer = self._trained(clock, engine)

        analyzer.ingest_flow(_flow(nbytes=50_000_000))
        clock.advance(61)
        reports = analyzer.close_expired_windows()

        assert len(reports) == 1
        report = reports[0]
        assert report["mac"] == PHONE
        assert 0 < report["confidence"] < 1
        metrics_flagged = {e["metric"] for e in report["evidence"]}
        assert "bytes" in metrics_flagged
        for e in report["evidence"]:
            assert {"metric", "observed", "baseline_mean", "baseline_std",
                    "z_score", "hour_of_week"} <= set(e)

        engine.create_behavior_alert.assert_called_once()
        kwargs = engine.create_behavior_alert.call_args.kwargs
        assert kwargs["mac"] == PHONE
        assert kwargs["evidence"] == report["evidence"]

    def test_dest_fanout_flags_unique_dests(self):
        clock = FakeClock()
        engine = MagicMock()
        analyzer = self._trained(clock, engine)

        # Port-scan-like: many destinations, small bytes
        for i in range(200):
            analyzer.ingest_flow(_flow(dest=f"10.0.{i // 250}.{i % 250 + 1}", nbytes=60))
        clock.advance(61)
        reports = analyzer.close_expired_windows()
        assert reports, "destination fan-out must be flagged"
        metrics_flagged = {e["metric"] for e in reports[0]["evidence"]}
        assert "unique_dests" in metrics_flagged

    def test_normal_window_after_training_no_alert(self):
        clock = FakeClock()
        engine = MagicMock()
        analyzer = self._trained(clock, engine)

        reports = _run_normal_window(analyzer, clock, nbytes=1100, flows=3)
        assert reports == []
        engine.create_behavior_alert.assert_not_called()

    def test_anomalous_window_not_learned(self):
        """Baseline must not absorb anomalous windows (poisoning guard)."""
        clock = FakeClock()
        analyzer = self._trained(clock, MagicMock())
        before = analyzer.get_profile_summary(PHONE)

        analyzer.ingest_flow(_flow(nbytes=50_000_000))
        clock.advance(61)
        assert analyzer.close_expired_windows()

        after = analyzer.get_profile_summary(PHONE)
        assert before == after  # no baseline mutation from the anomaly

    def test_two_devices_alert_independently(self):
        clock = FakeClock()
        engine = MagicMock()
        analyzer = _analyzer(clock, engine)
        other = "aa:bb:cc:00:00:03"

        for _ in range(5):
            for mac in (PHONE, other):
                for i in range(3):
                    analyzer.ingest_flow(_flow(mac=mac, dest=f"1.2.3.{i+1}", nbytes=300))
            clock.advance(61)
            analyzer.close_expired_windows()

        analyzer.ingest_flow(_flow(mac=PHONE, nbytes=50_000_000))
        analyzer.ingest_flow(_flow(mac=other, nbytes=50_000_000))
        clock.advance(61)
        reports = analyzer.close_expired_windows()
        assert {r["mac"] for r in reports} == {PHONE, other}
        assert engine.create_behavior_alert.call_count == 2


class TestPersistence:

    def test_profiles_round_trip(self, monkeypatch):
        import sqlite3
        from contextlib import contextmanager

        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("""
            CREATE TABLE behavior_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL, hour_of_week INTEGER NOT NULL,
                metric TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
                mean REAL NOT NULL DEFAULT 0, m2 REAL NOT NULL DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(mac_address, hour_of_week, metric)
            )
        """)

        @contextmanager
        def fake_conn():
            yield db

        import intelligence.behavior as behavior_mod
        import database.connection as conn_mod
        monkeypatch.setattr(conn_mod, "get_connection", fake_conn)

        clock = FakeClock()
        analyzer = BehaviorAnalyzer(
            alert_engine=MagicMock(), bus=EventBus(), persist=True,
            now_fn=clock, window_seconds=60, min_baseline_samples=3,
        )
        for _ in range(3):
            _run_normal_window(analyzer, clock)

        rows = db.execute("SELECT COUNT(*) FROM behavior_profiles").fetchone()[0]
        assert rows > 0

        # A fresh analyzer loads the same baselines back
        analyzer2 = BehaviorAnalyzer(
            alert_engine=MagicMock(), bus=EventBus(), persist=True,
            now_fn=clock, window_seconds=60, min_baseline_samples=3,
        )
        analyzer2._load_profiles()
        s1 = analyzer.get_profile_summary(PHONE)
        s2 = analyzer2.get_profile_summary(PHONE)
        assert s1 == s2
