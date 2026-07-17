"""
threat_dataset.py - Labeled Traffic Dataset (Phase 4)
======================================================

A deterministic, publishable dataset of labeled traffic scenarios for
evaluating the threat detector pack.  Each scenario is a short sequence
of flow / DNS events with a ground-truth label — either a threat type or
``benign``.

The benign scenarios are deliberately *near-misses*: normal browsing
(a few ports), a single file-share connection (below the lateral
threshold), jittery periodic traffic (not a beacon), ordinary short DNS.
Precision is only meaningful when the dataset contains traffic that
*looks* a little like an attack but isn't — otherwise a detector that
fires on everything would score perfectly.

Scenarios are built programmatically from a fixed seed so the dataset is
reproducible, and :func:`export_json` writes it out for publication /
thesis material.

Event shapes match the detector's ingest API exactly:

    flow: {kind:"flow", source_mac, source_ip, dest_ip, dest_port,
           protocol, is_control}
    dns:  {kind:"dns",  source_mac, source_ip, qname, qtype}
"""

import json
import random
from dataclasses import dataclass, field, asdict
from typing import Dict, List

# Ground-truth labels.
THREAT_LABELS = [
    "port_scan", "beaconing", "dns_tunneling",
    "rogue_device", "lateral_movement",
]
BENIGN = "benign"

_SEED = 20260715
_INTERNAL = "10.143.77."
_KNOWN_DEVICE = "aa:bb:cc:00:00:aa"   # an established, trusted device MAC


@dataclass
class Scenario:
    """One labeled traffic scenario."""
    id: str
    label: str                       # threat type or "benign"
    description: str
    events: List[dict]
    # Devices already known on the network before this scenario runs.  The
    # harness seeds these so benign / non-rogue traffic doesn't trip the
    # rogue-device detector (a new MAC genuinely IS rogue).
    known_macs: List[str] = field(default_factory=list)


def _flow(mac, dst_ip, dst_port, src_ip=None, protocol="TCP"):
    return {"kind": "flow", "source_mac": mac,
            "source_ip": src_ip or (_INTERNAL + "50"),
            "dest_ip": dst_ip, "dest_port": dst_port,
            "protocol": protocol, "is_control": False}


def _dns(mac, qname, src_ip=None):
    return {"kind": "dns", "source_mac": mac,
            "source_ip": src_ip or (_INTERNAL + "50"),
            "qname": qname, "qtype": "A"}


def build_dataset() -> List[Scenario]:
    """Construct the full labeled dataset (deterministic)."""
    rng = random.Random(_SEED)
    scenarios: List[Scenario] = []

    # ---- port_scan: vertical + horizontal ------------------------------
    for n in range(2):
        mac = f"de:ad:00:00:01:{n:02x}"
        target = f"{_INTERNAL}{9 + n}"
        events = [_flow(mac, target, 20 + p) for p in range(25)]
        scenarios.append(Scenario(
            id=f"portscan-vertical-{n}", label="port_scan",
            description="one host probed on many ports",
            events=events, known_macs=[mac]))
    for n in range(2):
        mac = f"de:ad:00:00:02:{n:02x}"
        # Sweep a non-admin service port (80). A 445/SMB sweep would also
        # (correctly) trip lateral_movement — admin-port horizontal sweeps
        # co-trigger both detectors — so we keep the port-scan label clean
        # by using a web port the lateral detector ignores.
        events = [_flow(mac, f"{_INTERNAL}{h}", 80) for h in range(1, 16)]
        scenarios.append(Scenario(
            id=f"portscan-horizontal-{n}", label="port_scan",
            description="one non-admin port swept across many hosts",
            events=events, known_macs=[mac]))

    # ---- beaconing: steady low-jitter callouts -------------------------
    for n in range(2):
        mac = f"de:ad:00:00:03:{n:02x}"
        c2 = f"203.0.113.{10 + n}"
        # 12 flows; the harness clock advances per event, jitter ~0.
        events = [_flow(mac, c2, 443, protocol="HTTPS") for _ in range(12)]
        scenarios.append(Scenario(
            id=f"beacon-{n}", label="beaconing",
            description="regular low-jitter C2 heartbeat",
            events=events, known_macs=[mac],
            # per-event dwell drives the beacon interval (see harness)
        ))

    # ---- dns_tunneling: long high-entropy label bursts -----------------
    for n in range(2):
        mac = f"de:ad:00:00:04:{n:02x}"
        domain = f"exfil{n}.example.com"
        events = []
        for _ in range(30):
            label = "".join(rng.choice("0123456789abcdef") for _ in range(56))
            events.append(_dns(mac, f"{label}.{domain}"))
        scenarios.append(Scenario(
            id=f"dnstunnel-{n}", label="dns_tunneling",
            description="query burst with long high-entropy subdomains",
            events=events, known_macs=[mac]))

    # ---- rogue_device: first flow from an unknown MAC ------------------
    for n in range(2):
        mac = f"de:ad:00:00:05:{n:02x}"
        scenarios.append(Scenario(
            id=f"rogue-{n}", label="rogue_device",
            description="never-before-seen device joins the network",
            events=[_flow(mac, f"{_INTERNAL}1", 80, src_ip=f"{_INTERNAL}{200 + n}")],
            known_macs=[]))   # deliberately NOT known

    # ---- lateral_movement: admin-port fan-out --------------------------
    for n in range(2):
        mac = f"de:ad:00:00:06:{n:02x}"
        events = [_flow(mac, f"{_INTERNAL}{10 + h}", 445,
                        src_ip=f"{_INTERNAL}{210 + n}") for h in range(4)]
        scenarios.append(Scenario(
            id=f"lateral-{n}", label="lateral_movement",
            description="one host reaches several internal hosts on admin ports",
            events=events, known_macs=[mac]))

    # ---- benign near-misses (precision stressors) ----------------------
    # Normal browsing: a few ports to a few external hosts.
    scenarios.append(Scenario(
        id="benign-browsing", label=BENIGN,
        description="normal web browsing (few ports, few hosts)",
        events=[_flow(_KNOWN_DEVICE, "93.184.216.34", 443, protocol="HTTPS"),
                _flow(_KNOWN_DEVICE, "93.184.216.34", 80),
                _flow(_KNOWN_DEVICE, "140.82.112.3", 443, protocol="HTTPS")],
        known_macs=[_KNOWN_DEVICE]))

    # Single file share to ONE internal server (below lateral threshold 3).
    scenarios.append(Scenario(
        id="benign-fileshare", label=BENIGN,
        description="single SMB connection to one file server",
        events=[_flow(_KNOWN_DEVICE, f"{_INTERNAL}5", 445) for _ in range(6)],
        known_macs=[_KNOWN_DEVICE]))

    # Ordinary DNS: short qnames to many different domains (not tunneling).
    scenarios.append(Scenario(
        id="benign-dns", label=BENIGN,
        description="ordinary short DNS lookups to varied domains",
        events=[_dns(_KNOWN_DEVICE, d) for d in
                ["google.com", "github.com", "cloudflare.com", "wikipedia.org",
                 "python.org", "example.net", "cdn.jsdelivr.net"]],
        known_macs=[_KNOWN_DEVICE]))

    # Reverse-DNS PTR burst (long qnames, but .arpa — must NOT be tunneling).
    ptr = ".".join("b" for _ in range(32))
    scenarios.append(Scenario(
        id="benign-ptr-burst", label=BENIGN,
        description="ip6.arpa reverse-DNS burst (long qnames, legitimate)",
        events=[_dns(_KNOWN_DEVICE, f"{i}.{ptr}.ip6.arpa") for i in range(30)],
        known_macs=[_KNOWN_DEVICE]))

    # Jittery periodic traffic to an external host (not a clean beacon).
    scenarios.append(Scenario(
        id="benign-jittery", label=BENIGN,
        description="irregular periodic traffic (high jitter, not a beacon)",
        events=[_flow(_KNOWN_DEVICE, "203.0.113.200", 443, protocol="HTTPS")
                for _ in range(12)],
        known_macs=[_KNOWN_DEVICE]))

    # A known device doing a little of everything — nothing should fire.
    scenarios.append(Scenario(
        id="benign-mixed", label=BENIGN,
        description="known device with mixed normal traffic",
        events=[_flow(_KNOWN_DEVICE, "1.1.1.1", 443, protocol="HTTPS"),
                _dns(_KNOWN_DEVICE, "news.example.com"),
                _flow(_KNOWN_DEVICE, f"{_INTERNAL}1", 53, protocol="UDP")],
        known_macs=[_KNOWN_DEVICE]))

    return scenarios


# Per-event dwell time (seconds) the harness advances its clock by, per
# label.  Beaconing needs a steady multi-second interval to look like a
# heartbeat; the jittery benign case overrides dwell per-event.
DWELL_SECONDS: Dict[str, float] = {
    "beaconing": 60.0,
    BENIGN: 1.0,
    "port_scan": 0.5,
    "dns_tunneling": 1.0,
    "rogue_device": 0.5,
    "lateral_movement": 2.0,
}


def jittery_dwell(rng: random.Random) -> float:
    """Dwell generator for the jittery benign scenario: wide spread so the
    beacon detector's low-jitter test fails."""
    return rng.choice([5.0, 45.0, 12.0, 90.0, 8.0, 70.0])


def export_json(path: str) -> None:
    """Write the dataset to *path* as JSON (for publication)."""
    data = {
        "version": "1.0",
        "seed": _SEED,
        "labels": THREAT_LABELS + [BENIGN],
        "scenarios": [asdict(s) for s in build_dataset()],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def dataset_stats() -> Dict[str, int]:
    """Count scenarios per label — handy for reports."""
    counts: Dict[str, int] = {}
    for s in build_dataset():
        counts[s.label] = counts.get(s.label, 0) + 1
    return counts
