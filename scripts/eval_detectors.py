"""
eval_detectors.py - Threat Detector Evaluation Runner (Phase 4)
================================================================

Runs the labeled dataset through the threat detector pack and prints a
precision / recall / F1 table (or JSON).  Optionally writes the dataset
and the report to disk for thesis material.

Usage::

    python scripts/eval_detectors.py
    python scripts/eval_detectors.py --json
    python scripts/eval_detectors.py --report-out docs/detector_eval.json \
                                     --dataset-out docs/threat_dataset.json
"""

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluation.detector_eval import evaluate, report_to_dict, format_table  # noqa: E402
from evaluation.threat_dataset import export_json, dataset_stats  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON")
    parser.add_argument("--report-out", default=None,
                        help="write the JSON report to this path")
    parser.add_argument("--dataset-out", default=None,
                        help="export the labeled dataset JSON to this path")
    args = parser.parse_args(argv)

    if args.dataset_out:
        export_json(args.dataset_out)
        print(f"dataset written to {args.dataset_out} "
              f"({sum(dataset_stats().values())} scenarios)")

    report = evaluate()
    payload = report_to_dict(report)

    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"report written to {args.report_out}")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("\nNetWatch — Threat Detector Evaluation")
        print(f"dataset: {dataset_stats()}\n")
        print(format_table(report))
        misses = [r for r in report.scenarios if not r.correct]
        if misses:
            print("\nmisclassified scenarios:")
            for r in misses:
                print(f"  {r.id} (label={r.label}) fired={r.fired}")
        print()

    # Non-zero exit if the detector pack regressed badly (macro-F1 floor).
    return 0 if report.macro_f1 >= 0.75 else 1


if __name__ == "__main__":
    sys.exit(main())
