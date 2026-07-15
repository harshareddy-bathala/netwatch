"""
behavior.py - Per-Device Behavior Learning (Phase 1)
=====================================================

Learns what "normal" looks like for every device and flags deviations
with explainable evidence.  Consumes ``flow.completed`` and
``dns.query`` events from the bus — never the capture hot path.

Model
-----
For each device (MAC) the analyzer accumulates an **observation window**
(default 10 min) of four metrics:

* ``bytes``        — total flow bytes
* ``flows``        — completed-flow count
* ``unique_dests`` — distinct destination IPs
* ``dns_queries``  — DNS query count

When a window closes, each metric is compared against the device's
baseline for the current **hour-of-week** (0-167) stored as Welford
running statistics (count/mean/m2) in the ``behavior_profiles`` table.
Metrics whose z-score exceeds ``BEHAVIOR_Z_THRESHOLD`` (with at least
``BEHAVIOR_MIN_BASELINE_SAMPLES`` baseline samples) become evidence
items; any evidence produces one per-device alert via
``AlertEngine.create_behavior_alert`` with a confidence score.

Windows that scored as anomalous are **not** folded into the baseline
(prevents attackers from slowly poisoning "normal"); everything else is
learned online and persisted, so knowledge survives restarts.
"""

import logging
import math
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

from intelligence.event_bus import event_bus as _default_bus

logger = logging.getLogger(__name__)

try:
    from config import (
        BEHAVIOR_WINDOW_SECONDS,
        BEHAVIOR_MIN_BASELINE_SAMPLES,
        BEHAVIOR_Z_THRESHOLD,
        BEHAVIOR_MAX_DEVICES,
    )
except ImportError:
    BEHAVIOR_WINDOW_SECONDS = 600
    BEHAVIOR_MIN_BASELINE_SAMPLES = 12
    BEHAVIOR_Z_THRESHOLD = 4.0
    BEHAVIOR_MAX_DEVICES = 1000

METRICS = ("bytes", "flows", "unique_dests", "dns_queries")

# Minimum absolute standard deviation used in z-scores.  Very stable
# baselines (std≈0) would otherwise flag trivial changes.
_STD_FLOOR_FRACTION = 0.10   # 10% of the mean
_STD_FLOOR_ABS = 1.0


def hour_of_week(ts: Optional[float] = None) -> int:
    """Return 0-167 bucket (weekday*24 + hour) for *ts* (default now)."""
    dt = datetime.fromtimestamp(ts) if ts else datetime.now()
    return dt.weekday() * 24 + dt.hour


class _Baseline:
    """Welford running statistics for one (device, hour-of-week, metric)."""

    __slots__ = ("count", "mean", "m2", "dirty")

    def __init__(self, count: int = 0, mean: float = 0.0, m2: float = 0.0):
        self.count = count
        self.mean = mean
        self.m2 = m2
        self.dirty = False

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        self.dirty = True

    @property
    def std(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self.m2 / (self.count - 1))

    def z_score(self, value: float) -> float:
        floor = max(_STD_FLOOR_ABS, abs(self.mean) * _STD_FLOOR_FRACTION)
        return (value - self.mean) / max(self.std, floor)


class _Window:
    """Accumulating observation window for one device."""

    __slots__ = ("started", "bytes", "flows", "dests", "dns_queries", "hostname")

    def __init__(self, now: float):
        self.started = now
        self.bytes = 0
        self.flows = 0
        self.dests: Set[str] = set()
        self.dns_queries = 0
        self.hostname = ""

    def metrics(self) -> Dict[str, float]:
        return {
            "bytes": float(self.bytes),
            "flows": float(self.flows),
            "unique_dests": float(len(self.dests)),
            "dns_queries": float(self.dns_queries),
        }


class BehaviorAnalyzer:
    """Event-bus consumer implementing per-device baseline learning."""

    def __init__(
        self,
        alert_engine=None,
        shutdown_event: Optional[threading.Event] = None,
        bus=None,
        window_seconds: float = BEHAVIOR_WINDOW_SECONDS,
        min_baseline_samples: int = BEHAVIOR_MIN_BASELINE_SAMPLES,
        z_threshold: float = BEHAVIOR_Z_THRESHOLD,
        max_devices: int = BEHAVIOR_MAX_DEVICES,
        persist: bool = True,
        now_fn: Callable[[], float] = time.time,
    ):
        self._alert_engine = alert_engine
        self._bus = bus or _default_bus
        self._shutdown_event = shutdown_event or threading.Event()
        self._window_seconds = window_seconds
        self._min_samples = min_baseline_samples
        self._z_threshold = z_threshold
        self._max_devices = max_devices
        self._persist = persist
        self._now = now_fn

        self._lock = threading.Lock()
        self._windows: Dict[str, _Window] = {}
        # (mac, hour_of_week, metric) → _Baseline
        self._baselines: Dict[tuple, _Baseline] = {}

        self._thread: Optional[threading.Thread] = None
        self._sub = None

        # Diagnostics
        self.windows_closed = 0
        self.anomalies_found = 0

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        if self._persist:
            try:
                self._load_profiles()
            except Exception as exc:
                logger.warning("Behavior profile load failed (cold start): %s", exc)
        self._sub = self._bus.subscribe(
            ["flow.completed", "dns.query"], name="behavior-analyzer",
        )
        self._thread = threading.Thread(
            target=self._run, name="BehaviorAnalyzer", daemon=True,
        )
        self._thread.start()
        logger.info(
            "BehaviorAnalyzer started (window=%ss, min_samples=%d, z>=%.1f, "
            "profiles=%d loaded)",
            self._window_seconds, self._min_samples, self._z_threshold,
            len(self._baselines),
        )
        return True

    def stop(self, timeout: float = 5.0) -> None:
        self._shutdown_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._sub is not None:
            self._bus.unsubscribe(self._sub)

    def _run(self) -> None:
        while not self._shutdown_event.is_set():
            event = self._sub.get(timeout=1.0)
            if event is not None:
                try:
                    if event.topic == "flow.completed":
                        self.ingest_flow(event.payload)
                    elif event.topic == "dns.query":
                        self.ingest_dns(event.payload)
                except Exception as exc:
                    logger.error("BehaviorAnalyzer ingest error: %s", exc)
            try:
                self.close_expired_windows()
            except Exception as exc:
                logger.error("BehaviorAnalyzer window error: %s", exc)
        # Persist learned state on shutdown (windows are discarded —
        # partial windows would bias the baseline low).
        if self._persist:
            try:
                self._save_profiles()
            except Exception as exc:
                logger.error("Behavior profile save failed: %s", exc)
        logger.info("BehaviorAnalyzer thread exited")

    # ------------------------------------------------------------------ #
    #  Ingestion
    # ------------------------------------------------------------------ #

    @staticmethod
    def _norm_mac(mac: Optional[str]) -> str:
        return (mac or "").lower().replace("-", ":").strip()

    def _window_for(self, mac: str) -> Optional[_Window]:
        window = self._windows.get(mac)
        if window is None:
            if len(self._windows) >= self._max_devices:
                return None
            window = _Window(self._now())
            self._windows[mac] = window
        return window

    def ingest_flow(self, flow: dict) -> None:
        """Fold one completed flow into its device's current window."""
        mac = self._norm_mac(flow.get("source_mac"))
        if not mac or mac.startswith(("ff:ff:ff", "01:00:5e", "33:33")):
            return
        with self._lock:
            window = self._window_for(mac)
            if window is None:
                return
            window.bytes += int(flow.get("bytes_total") or 0)
            window.flows += 1
            dest = flow.get("dest_ip")
            if dest:
                window.dests.add(dest)

    def ingest_dns(self, dns_event: dict) -> None:
        mac = self._norm_mac(dns_event.get("source_mac"))
        if not mac:
            return
        with self._lock:
            window = self._window_for(mac)
            if window is not None:
                window.dns_queries += 1

    # ------------------------------------------------------------------ #
    #  Window close → score → learn
    # ------------------------------------------------------------------ #

    def close_expired_windows(self) -> List[dict]:
        """Close windows older than window_seconds; return anomaly reports."""
        now = self._now()
        reports: List[dict] = []
        with self._lock:
            expired = [
                (mac, w) for mac, w in self._windows.items()
                if now - w.started >= self._window_seconds
            ]
            for mac, _ in expired:
                del self._windows[mac]

        for mac, window in expired:
            report = self._score_and_learn(mac, window)
            if report is not None:
                reports.append(report)

        if expired and self._persist:
            try:
                self._save_profiles()
            except Exception as exc:
                logger.error("Behavior profile save failed: %s", exc)
        return reports

    def _score_and_learn(self, mac: str, window: _Window) -> Optional[dict]:
        how = hour_of_week(window.started)
        observed = window.metrics()
        evidence: List[dict] = []
        max_z = 0.0

        with self._lock:
            for metric, value in observed.items():
                baseline = self._baselines.get((mac, how, metric))
                if baseline is None:
                    baseline = _Baseline()
                    self._baselines[(mac, how, metric)] = baseline

                if baseline.count >= self._min_samples:
                    z = baseline.z_score(value)
                    if z >= self._z_threshold:
                        evidence.append({
                            "metric": metric,
                            "observed": value,
                            "baseline_mean": round(baseline.mean, 2),
                            "baseline_std": round(baseline.std, 2),
                            "baseline_samples": baseline.count,
                            "z_score": round(z, 2),
                            "hour_of_week": how,
                        })
                        max_z = max(max_z, z)

            self.windows_closed += 1

            if not evidence:
                # Normal window — learn it.
                for metric, value in observed.items():
                    self._baselines[(mac, how, metric)].update(value)
                return None

        # Anomalous window — alert, don't learn (avoids baseline poisoning).
        self.anomalies_found += 1
        confidence = min(0.99, max_z / (max_z + self._z_threshold))
        severity = "critical" if max_z >= 3 * self._z_threshold else "warning"
        report = {
            "mac": mac,
            "hostname": window.hostname,
            "evidence": evidence,
            "confidence": round(confidence, 4),
            "severity": severity,
        }

        engine = self._alert_engine
        if engine is None:
            try:
                from alerts import get_shared_engine
                engine = get_shared_engine()
            except Exception:
                engine = None
        if engine is not None:
            try:
                engine.create_behavior_alert(
                    mac=mac,
                    hostname=window.hostname,
                    evidence=evidence,
                    confidence=confidence,
                    severity=severity,
                )
            except Exception as exc:
                logger.error("Behavior alert creation failed: %s", exc)

        logger.warning(
            "BEHAVIOR ANOMALY: %s (confidence=%.0f%%, evidence=%d, max_z=%.1f)",
            mac, confidence * 100, len(evidence), max_z,
        )
        return report

    # ------------------------------------------------------------------ #
    #  Persistence
    # ------------------------------------------------------------------ #

    def _load_profiles(self) -> None:
        from database.connection import get_connection
        with get_connection() as conn:
            cursor = conn.execute(
                "SELECT mac_address, hour_of_week, metric, count, mean, m2 "
                "FROM behavior_profiles"
            )
            for row in cursor.fetchall():
                key = (row["mac_address"], int(row["hour_of_week"]), row["metric"])
                self._baselines[key] = _Baseline(
                    count=int(row["count"]),
                    mean=float(row["mean"]),
                    m2=float(row["m2"]),
                )

    def _save_profiles(self) -> None:
        with self._lock:
            dirty = [
                (key, b) for key, b in self._baselines.items() if b.dirty
            ]
            for _, b in dirty:
                b.dirty = False
        if not dirty:
            return
        from database.connection import get_connection
        rows = [
            {
                "mac_address": key[0],
                "hour_of_week": key[1],
                "metric": key[2],
                "count": b.count,
                "mean": b.mean,
                "m2": b.m2,
            }
            for key, b in dirty
        ]
        with get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO behavior_profiles
                    (mac_address, hour_of_week, metric, count, mean, m2, updated_at)
                VALUES (:mac_address, :hour_of_week, :metric, :count, :mean, :m2,
                        datetime('now'))
                ON CONFLICT(mac_address, hour_of_week, metric)
                DO UPDATE SET count = excluded.count,
                              mean = excluded.mean,
                              m2 = excluded.m2,
                              updated_at = excluded.updated_at
                """,
                rows,
            )
            conn.commit()
        logger.debug("Behavior profiles persisted: %d entries", len(rows))

    # ------------------------------------------------------------------ #
    #  Introspection (for /api/behavior)
    # ------------------------------------------------------------------ #

    def get_profile_summary(self, mac: str) -> dict:
        """Return learned baselines for one device, grouped by metric."""
        mac = self._norm_mac(mac)
        out: Dict[str, list] = {m: [] for m in METRICS}
        with self._lock:
            for (bmac, how, metric), b in self._baselines.items():
                if bmac == mac and b.count > 0:
                    out[metric].append({
                        "hour_of_week": how,
                        "samples": b.count,
                        "mean": round(b.mean, 2),
                        "std": round(b.std, 2),
                    })
        for metric in out:
            out[metric].sort(key=lambda e: e["hour_of_week"])
        return {"mac": mac, "metrics": out}

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "devices_windowed": len(self._windows),
                "baseline_entries": len(self._baselines),
                "windows_closed": self.windows_closed,
                "anomalies_found": self.anomalies_found,
                "running": bool(self._thread and self._thread.is_alive()),
            }
