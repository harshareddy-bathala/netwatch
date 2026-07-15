"""
export_baseline_metrics.py - Phase 5 Baseline Metrics Export
=============================================================

Exports idle-client baseline metrics to JSON and CSV for regression tracking.

Usage:
    python scripts/export_baseline_metrics.py --hours 24
    python scripts/export_baseline_metrics.py --hours 72 --json-out docs/baseline_metrics.json --csv-out docs/baseline_metrics.csv
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.idle_baseline import collect_idle_baseline_metrics  # noqa: E402


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)


def _write_json(path: str, sample: dict) -> None:
    _ensure_parent(path)

    payload = {
        "updated_at": datetime.now().isoformat(),
        "samples": [sample],
    }

    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
            if isinstance(existing, dict) and isinstance(existing.get("samples"), list):
                samples = existing["samples"]
                samples.append(sample)
                payload = {
                    "updated_at": datetime.now().isoformat(),
                    "samples": samples,
                }
        except Exception:
            pass

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def _write_csv(path: str, sample: dict) -> None:
    _ensure_parent(path)

    fieldnames = [
        "generated_at",
        "window_hours",
        "app_bytes_per_hour",
        "control_bytes_per_hour",
        "app_pps",
        "control_pps",
        "control_overhead_ratio",
        "mode_transition_count",
        "active_devices_realtime",
        "status",
    ]

    row = {key: sample.get(key) for key in fieldnames}
    write_header = not os.path.exists(path)

    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export idle baseline metrics to JSON/CSV")
    parser.add_argument("--hours", type=int, default=24, help="Window size in hours (default: 24)")
    parser.add_argument(
        "--json-out",
        default=os.path.join("docs", "baseline_metrics.json"),
        help="Path to JSON output file",
    )
    parser.add_argument(
        "--csv-out",
        default=os.path.join("docs", "baseline_metrics.csv"),
        help="Path to CSV output file",
    )

    args = parser.parse_args()

    metrics = collect_idle_baseline_metrics(hours=max(1, args.hours))

    _write_json(args.json_out, metrics)
    _write_csv(args.csv_out, metrics)

    print(
        "Exported baseline metrics:",
        f"status={metrics.get('status')}",
        f"app_bytes_per_hour={metrics.get('app_bytes_per_hour')}",
        f"control_bytes_per_hour={metrics.get('control_bytes_per_hour')}",
        f"mode_transition_count={metrics.get('mode_transition_count')}",
    )
    print(f"JSON: {args.json_out}")
    print(f"CSV: {args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
