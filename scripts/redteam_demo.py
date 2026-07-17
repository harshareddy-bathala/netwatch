"""
redteam_demo.py - Threat Detector Pack Demo (Phase 2)
======================================================

Drives NetWatch's real ``ThreatDetector`` through each named attack shape
and prints the alert it produces — port scan, network sweep, C2
beaconing, DNS tunneling, rogue device, and lateral movement.

This is the capstone demo for the Phase 2 exit criterion ("red-team demo
script triggers named threats").  It is **self-contained and offline**:
no packet capture, no root, no network target.  It feeds crafted
``flow.completed`` / ``dns.query`` payloads — the exact dict shape the
live FlowNormalizer publishes on the event bus — into the same detector
class the running system uses, so what fires here is what fires in
production.

A controllable clock (``--now``) lets the time-based detectors
(beaconing) run deterministically without real waits.

Usage::

    python scripts/redteam_demo.py            # run every scenario
    python scripts/redteam_demo.py --json      # machine-readable output
    python scripts/redteam_demo.py --only beaconing dns_tunneling
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from intelligence.threats import ThreatDetector  # noqa: E402


class _CapturingEngine:
    """Stand-in AlertEngine that records threat alerts instead of writing
    them to the database — same method signature the detector calls."""

    def __init__(self):
        self.alerts: List[dict] = []

    def create_threat_alert(self, *, threat_type, mac, message, evidence,
                            confidence, severity):
        self.alerts.append({
            "threat_type": threat_type,
            "mac": mac,
            "severity": severity,
            "confidence": confidence,
            "message": message,
            "evidence": evidence,
        })
        return len(self.alerts)


class _Clock:
    """Monotonic fake clock advanced explicitly by the scenarios."""

    def __init__(self, start: float = 1_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def tick(self, seconds: float) -> None:
        self.t += seconds


# ---------------------------------------------------------------------------
# Payload builders (mirror FlowNormalizer output)
# ---------------------------------------------------------------------------

def _flow(src_mac: str, dst_ip: str, dst_port: int, *,
          source_ip: str = "10.143.77.50", protocol: str = "TCP") -> dict:
    return {
        "source_mac": src_mac,
        "source_ip": source_ip,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "protocol": protocol,
        "is_control": False,
    }


def _dns(src_mac: str, qname: str, source_ip: str = "10.143.77.50") -> dict:
    return {"source_mac": src_mac, "source_ip": source_ip,
            "qname": qname, "qtype": "A"}


# ---------------------------------------------------------------------------
# Scenarios — each crafts the traffic shape for one detector
# ---------------------------------------------------------------------------
#
# Every scenario is a dict:
#   attacker  — the source MAC driving the attack
#   expect    — the threat_type this scenario is meant to trigger
#   build     — feeds the crafted flows/DNS into the detector
#
# For every scenario except rogue_device the attacker is pre-registered as
# a known device (``preknown=True``) so the run isolates the intended
# behaviour instead of also tripping rogue_device on the attacker's first
# flow — which is correct, but noise for a per-detector demo.

def _build_port_scan(det, clock, attacker):
    """One host, many ports → vertical port scan."""
    for port in range(20, 20 + 30):          # 30 distinct ports (threshold 15)
        det.ingest_flow(_flow(attacker, "10.143.77.9", port))
        clock.tick(0.5)


def _build_network_sweep(det, clock, attacker):
    """One port, many hosts → horizontal sweep."""
    for host in range(1, 20):                # 19 hosts (threshold 10) on 445
        det.ingest_flow(_flow(attacker, f"10.143.77.{host}", 445))
        clock.tick(0.5)


def _build_beaconing(det, clock, attacker):
    """Regular low-jitter callouts to one external host:port → C2 beacon."""
    for _ in range(12):                      # min_observations 6
        det.ingest_flow(_flow(attacker, "203.0.113.66", 443, protocol="HTTPS"))
        clock.tick(60.0)                     # steady 60s heartbeat, ~0 jitter


def _build_dns_tunneling(det, clock, attacker):
    """Burst of long high-entropy subdomains to one domain → tunneling."""
    import secrets
    for _ in range(30):                      # threshold 25
        label = secrets.token_hex(28)        # 56 hex chars, high entropy
        det.ingest_dns(_dns(attacker, f"{label}.exfil.example.com"))
        clock.tick(1.0)


def _build_rogue_device(det, clock, attacker):
    """A never-before-seen internal MAC's first flow → rogue device."""
    det.ingest_flow(_flow(attacker, "10.143.77.1", 80,
                          source_ip="10.143.77.201"))


def _build_lateral_movement(det, clock, attacker):
    """One internal host fanning out to several internal hosts on admin
    ports → lateral movement."""
    for host in (11, 12, 13, 14):            # 4 hosts (threshold 3)
        det.ingest_flow(_flow(attacker, f"10.143.77.{host}", 445,
                              source_ip="10.143.77.202"))
        clock.tick(2.0)


SCENARIOS = {
    "port_scan": {
        "attacker": "de:ad:be:ef:00:01", "expect": "port_scan",
        "preknown": True, "build": _build_port_scan,
    },
    "network_sweep": {
        "attacker": "de:ad:be:ef:00:02", "expect": "port_scan",
        "preknown": True, "build": _build_network_sweep,
    },
    "beaconing": {
        "attacker": "de:ad:be:ef:00:03", "expect": "beaconing",
        "preknown": True, "build": _build_beaconing,
    },
    "dns_tunneling": {
        "attacker": "de:ad:be:ef:00:04", "expect": "dns_tunneling",
        "preknown": True, "build": _build_dns_tunneling,
    },
    "rogue_device": {
        "attacker": "de:ad:be:ef:00:05", "expect": "rogue_device",
        "preknown": False, "build": _build_rogue_device,
    },
    "lateral_movement": {
        "attacker": "de:ad:be:ef:00:06", "expect": "lateral_movement",
        "preknown": True, "build": _build_lateral_movement,
    },
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(only: Optional[List[str]] = None) -> Dict[str, dict]:
    """Run each scenario in isolation.

    Returns scenario → {expect, alerts, fired} where *fired* is True when
    the scenario's intended threat_type appeared among the alerts.
    """
    names = only or list(SCENARIOS)
    results: Dict[str, dict] = {}
    for name in names:
        if name not in SCENARIOS:
            raise SystemExit(f"unknown scenario: {name!r} "
                             f"(choose from {', '.join(SCENARIOS)})")
        spec = SCENARIOS[name]
        engine = _CapturingEngine()
        clock = _Clock()
        # Fresh detector per scenario, deterministic clock, no DB seeding.
        det = ThreatDetector(alert_engine=engine, seed_known_macs=False,
                             now_fn=clock)
        if spec["preknown"]:
            # Register the attacker as an already-known device so we isolate
            # the target behaviour instead of also firing rogue_device.
            det._known_macs.add(spec["attacker"])
        spec["build"](det, clock, spec["attacker"])
        alerts = engine.alerts
        results[name] = {
            "expect": spec["expect"],
            "alerts": alerts,
            "fired": any(a["threat_type"] == spec["expect"] for a in alerts),
        }
    return results


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _print_report(results: Dict[str, dict]) -> None:
    if _supports_color():
        RED, GRN, DIM, BOLD, RST = (
            "\033[31m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"
        )
    else:
        RED = GRN = DIM = BOLD = RST = ""
    print(f"\n{BOLD}NetWatch - Red-Team Threat Detector Demo{RST}")
    print(f"{DIM}Feeding crafted flows/DNS into the live ThreatDetector "
          f"code path.{RST}\n")
    fired = 0
    for name, res in results.items():
        expect = res["expect"]
        named = [a for a in res["alerts"] if a["threat_type"] == expect]
        if res["fired"]:
            fired += 1
            for a in named:
                print(f"  {GRN}[FIRED]{RST} {BOLD}{name}{RST} "
                      f"-> {a['threat_type']} "
                      f"({a['severity']}, confidence {a['confidence']:.2f})")
                print(f"          {a['message']}")
                for ev in a["evidence"]:
                    print(f"          {DIM}evidence: "
                          f"{json.dumps(ev, default=str)}{RST}")
        else:
            print(f"  {RED}[MISS]{RST}  {BOLD}{name}{RST} -> expected "
                  f"{expect}, none fired (check thresholds/config)")
    total = len(results)
    color = GRN if fired == total else RED
    print(f"\n{color}{fired}/{total} scenarios triggered their named "
          f"threat.{RST}\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", metavar="SCENARIO",
                        help=f"run a subset: {', '.join(SCENARIOS)}")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of a report")
    args = parser.parse_args(argv)

    results = run(only=args.only)

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        _print_report(results)

    # Non-zero exit if any requested scenario failed to fire its named
    # threat — usable as a CI smoke check for the detector pack.
    missed = [name for name, res in results.items() if not res["fired"]]
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
