"""
idle_baseline.py - Idle Client Baseline Metrics Helpers
=========================================================

Shared helpers for Phase 5 baseline validation:
- app/control bytes and packet rates over a time window
- control-overhead ratio
- mode transition count in the same window
"""

from datetime import datetime, timedelta
from typing import Optional

from config import (
    IDLE_BASELINE_APP_BYTES_PER_HOUR_LIMIT,
    IDLE_BASELINE_APP_PPS_LIMIT,
    IDLE_BASELINE_CONTROL_BYTES_PER_HOUR_MIN,
    IDLE_BASELINE_CONTROL_BYTES_PER_HOUR_MAX,
)
from database.connection import get_connection


def _to_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_div(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def count_mode_transitions(hours: int = 24, now_ts: Optional[float] = None) -> int:
    """Count recorded mode transitions in the last *hours* hours."""
    try:
        import time
        from orchestration import state as orch_state

        horizon = max(1, int(hours)) * 3600
        now_value = now_ts if now_ts is not None else time.time()
        cutoff = now_value - horizon

        with orch_state.mode_transition_events_lock:
            return sum(
                1
                for evt in orch_state.mode_transition_events
                if float(evt.get("timestamp", 0.0) or 0.0) >= cutoff
            )
    except Exception:
        return 0


def collect_idle_baseline_metrics(hours: int = 24) -> dict:
    """Collect app/control baseline metrics from traffic_summary."""
    window_hours = max(1, int(hours))
    since = (datetime.now() - timedelta(hours=window_hours)).strftime("%Y-%m-%d %H:%M:%S")

    app_bytes = 0
    control_bytes = 0
    app_packets = 0
    control_packets = 0
    transition_packets = 0

    try:
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN bytes_transferred ELSE 0 END), 0) AS app_bytes,
                    COALESCE(SUM(CASE WHEN COALESCE(is_control, 0) = 1 THEN bytes_transferred ELSE 0 END), 0) AS control_bytes,
                    COALESCE(SUM(CASE WHEN COALESCE(is_control, 0) = 0 THEN 1 ELSE 0 END), 0) AS app_packets,
                    COALESCE(SUM(CASE WHEN COALESCE(is_control, 0) = 1 THEN 1 ELSE 0 END), 0) AS control_packets
                FROM traffic_summary
                WHERE timestamp >= ?
                """,
                (since,),
            ).fetchone()

            if row is not None:
                app_bytes = _to_int(row["app_bytes"])
                control_bytes = _to_int(row["control_bytes"])
                app_packets = _to_int(row["app_packets"])
                control_packets = _to_int(row["control_packets"])

            trow = conn.execute(
                """
                SELECT COALESCE(COUNT(*), 0) AS transition_packets
                FROM traffic_summary
                WHERE timestamp >= ? AND direction = 'transition'
                """,
                (since,),
            ).fetchone()
            transition_packets = _to_int(trow["transition_packets"] if trow is not None else 0)
    except Exception:
        pass

    window_seconds = float(window_hours * 3600)
    app_bytes_per_hour = _safe_div(app_bytes, window_hours)
    control_bytes_per_hour = _safe_div(control_bytes, window_hours)
    app_pps = _safe_div(app_packets, window_seconds)
    control_pps = _safe_div(control_packets, window_seconds)
    control_overhead_ratio = _safe_div(control_bytes, app_bytes) if app_bytes else (1.0 if control_bytes else 0.0)

    within_app_bytes = app_bytes_per_hour <= IDLE_BASELINE_APP_BYTES_PER_HOUR_LIMIT
    within_app_pps = app_pps <= IDLE_BASELINE_APP_PPS_LIMIT
    control_within_band = (
        IDLE_BASELINE_CONTROL_BYTES_PER_HOUR_MIN
        <= control_bytes_per_hour
        <= IDLE_BASELINE_CONTROL_BYTES_PER_HOUR_MAX
    )

    mode_transition_count = count_mode_transitions(hours=window_hours)

    status = "ok" if (within_app_bytes and within_app_pps and mode_transition_count <= 2) else "warning"

    return {
        "window_hours": window_hours,
        "generated_at": datetime.now().isoformat(),
        "app_bytes": app_bytes,
        "control_bytes": control_bytes,
        "app_packets": app_packets,
        "control_packets": control_packets,
        "app_bytes_per_hour": round(app_bytes_per_hour, 2),
        "control_bytes_per_hour": round(control_bytes_per_hour, 2),
        "app_pps": round(app_pps, 4),
        "control_pps": round(control_pps, 4),
        "control_overhead_ratio": round(control_overhead_ratio, 4),
        "transition_packets": transition_packets,
        "mode_transition_count": mode_transition_count,
        "active_devices_realtime": _get_active_devices_realtime(),
        "thresholds": {
            "app_bytes_per_hour_limit": IDLE_BASELINE_APP_BYTES_PER_HOUR_LIMIT,
            "app_pps_limit": IDLE_BASELINE_APP_PPS_LIMIT,
            "control_bytes_per_hour_min": IDLE_BASELINE_CONTROL_BYTES_PER_HOUR_MIN,
            "control_bytes_per_hour_max": IDLE_BASELINE_CONTROL_BYTES_PER_HOUR_MAX,
        },
        "checks": {
            "app_bytes_within_limit": within_app_bytes,
            "app_pps_within_limit": within_app_pps,
            "control_bytes_within_expected_band": control_within_band,
            "mode_transitions_within_limit": mode_transition_count <= 2,
        },
        "status": status,
    }


def _get_active_devices_realtime() -> int:
    """Read active device count from in-memory state (best-effort)."""
    try:
        from utils.realtime_state import dashboard_state
        return int(dashboard_state.get_active_device_count(minutes=1))
    except Exception:
        return 0
