"""
detector_eval.py - Threat Detector Evaluation (Phase 4)
========================================================

Runs the labeled dataset (:mod:`evaluation.threat_dataset`) through the
*real* ThreatDetector and reports precision / recall / F1 per detector,
plus a per-scenario breakdown and overall macro/micro averages.

Metric (multi-label detection):
  For each scenario (ground-truth label L, set of fired threat types F)
  and each threat type T:
    * T in F and L == T                → true positive  for T
    * T in F and L != T (incl. benign) → false positive for T
    * T not in F and L == T            → false negative for T
  precision_T = TP / (TP + FP),  recall_T = TP / (TP + FN),  F1 = HM.

Benign scenarios can only produce false positives — they are the
precision stressors.
"""

import random
from dataclasses import dataclass, field
from typing import Dict, List, Set

from evaluation.threat_dataset import (
    Scenario, build_dataset, THREAT_LABELS, BENIGN,
    DWELL_SECONDS, jittery_dwell, _SEED,
)


class _CapturingEngine:
    """Records threat alerts (same interface ThreatDetector calls)."""

    def __init__(self):
        self.fired: List[str] = []

    def create_threat_alert(self, *, threat_type, mac, message, evidence,
                            confidence, severity):
        self.fired.append(threat_type)
        return len(self.fired)


class _Clock:
    def __init__(self, start=1_000_000.0):
        self.t = start

    def __call__(self):
        return self.t

    def tick(self, seconds):
        self.t += seconds


@dataclass
class ScenarioResult:
    id: str
    label: str
    fired: List[str]
    correct: bool          # labeled threat fired (attack) / nothing fired (benign)


@dataclass
class DetectorMetrics:
    threat: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class EvalReport:
    per_detector: Dict[str, DetectorMetrics]
    scenarios: List[ScenarioResult]
    benign_false_positive_rate: float
    macro_f1: float
    accuracy: float                          # scenarios classified correctly
    label_counts: Dict[str, int] = field(default_factory=dict)


def run_scenario(scenario: Scenario) -> Set[str]:
    """Replay one scenario through a fresh detector; return fired threats."""
    from intelligence.threats import ThreatDetector

    engine = _CapturingEngine()
    clock = _Clock()
    det = ThreatDetector(alert_engine=engine, seed_known_macs=False,
                         now_fn=clock)
    for mac in scenario.known_macs:
        det._known_macs.add(mac.lower())

    jitter_rng = random.Random(_SEED)
    dwell = DWELL_SECONDS.get(scenario.label, 1.0)
    for event in scenario.events:
        kind = event.get("kind")
        if kind == "flow":
            det.ingest_flow(event)
        elif kind == "dns":
            det.ingest_dns(event)
        if scenario.id == "benign-jittery":
            clock.tick(jittery_dwell(jitter_rng))
        else:
            clock.tick(dwell)
    return set(engine.fired)


def evaluate(dataset: List[Scenario] = None) -> EvalReport:
    """Run the full dataset and compute metrics."""
    dataset = dataset if dataset is not None else build_dataset()
    metrics = {t: DetectorMetrics(threat=t) for t in THREAT_LABELS}
    results: List[ScenarioResult] = []
    correct_count = 0
    benign_total = 0
    benign_fp = 0

    for scenario in dataset:
        fired = run_scenario(scenario)
        label = scenario.label

        for t in THREAT_LABELS:
            in_fired = t in fired
            if in_fired and label == t:
                metrics[t].tp += 1
            elif in_fired and label != t:
                metrics[t].fp += 1
            elif not in_fired and label == t:
                metrics[t].fn += 1

        if label == BENIGN:
            benign_total += 1
            if fired:
                benign_fp += 1
            correct = not fired
        else:
            correct = label in fired
        correct_count += int(correct)
        results.append(ScenarioResult(id=scenario.id, label=label,
                                      fired=sorted(fired), correct=correct))

    macro_f1 = sum(m.f1 for m in metrics.values()) / len(metrics)
    label_counts: Dict[str, int] = {}
    for s in dataset:
        label_counts[s.label] = label_counts.get(s.label, 0) + 1

    return EvalReport(
        per_detector=metrics,
        scenarios=results,
        benign_false_positive_rate=(benign_fp / benign_total) if benign_total else 0.0,
        macro_f1=macro_f1,
        accuracy=correct_count / len(dataset) if dataset else 0.0,
        label_counts=label_counts,
    )


def report_to_dict(report: EvalReport) -> dict:
    """JSON-serialisable form of an EvalReport."""
    return {
        "per_detector": {
            t: {"precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
                "tp": m.tp, "fp": m.fp, "fn": m.fn}
            for t, m in report.per_detector.items()
        },
        "overall": {
            "macro_f1": round(report.macro_f1, 4),
            "accuracy": round(report.accuracy, 4),
            "benign_false_positive_rate": round(report.benign_false_positive_rate, 4),
        },
        "label_counts": report.label_counts,
        "scenarios": [
            {"id": r.id, "label": r.label, "fired": r.fired, "correct": r.correct}
            for r in report.scenarios
        ],
    }


def format_table(report: EvalReport) -> str:
    """Human-readable precision/recall table."""
    lines = []
    lines.append(f"{'detector':<18}{'precision':>11}{'recall':>9}"
                 f"{'f1':>7}{'tp':>5}{'fp':>5}{'fn':>5}")
    lines.append("-" * 60)
    for t in THREAT_LABELS:
        m = report.per_detector[t]
        lines.append(f"{t:<18}{m.precision:>11.3f}{m.recall:>9.3f}"
                     f"{m.f1:>7.3f}{m.tp:>5}{m.fp:>5}{m.fn:>5}")
    lines.append("-" * 60)
    lines.append(f"macro-F1 {report.macro_f1:.3f}   "
                 f"accuracy {report.accuracy:.3f}   "
                 f"benign FP-rate {report.benign_false_positive_rate:.3f}")
    return "\n".join(lines)
