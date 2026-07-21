<div style="font-family: 'Georgia', serif; max-width: 780px; margin: auto; font-size: 13.5px; line-height: 1.65;">

# NetWatch — Intelligent Network Traffic Analysis System

> *A self-hosted, real-time network monitoring platform that detects, explains, and lets you act on what happens on your network — with the AI running locally and no cloud dependency anywhere.*

---

## Problem Statement

Modern networks — home hotspots, office LANs, campus Wi-Fi — operate largely as black boxes. Administrators and power users have no quick way to see *who* is on their network, *how much* bandwidth each device consumes, or *when* something unusual is happening. Basic router UIs show connected devices but offer no traffic analytics, no historical data, and no anomaly detection. Security incidents, bandwidth hogs, and rogue devices go unnoticed until damage is done.

---

## Existing Solutions

| Tool | Limitation |
|---|---|
| **Wireshark** | Packet capture only — no dashboards, no persistence, no alerting |
| **PRTG / SolarWinds** | Expensive enterprise tools; require SNMP infrastructure and cloud accounts |
| **ntopng** | Powerful but complex to deploy; relies on dedicated probes or external collectors |
| **Router firmware (DD-WRT etc.)** | Hardware-locked; limited analytics; no ML; no alert system |

All existing approaches either require heavy infrastructure, send data to the cloud, or demand significant networking expertise just to get started. None combine **automatic mode detection + real-time dashboard + ML anomaly detection** in a single, zero-cloud, cross-platform tool.

---

## Proposed Solution — NetWatch

NetWatch is a Python-based monitoring daemon that runs locally on any machine connected to a network. It captures raw packets using Scapy, processes them in real-time, stores data in SQLite, and serves a live web dashboard — all without any external services.

**Core pipeline:**  
Packet capture (Scapy/Npcap) → Packet processor → Event bus → Intelligence layer → SQLite storage → Flask REST + SSE → Vanilla JS dashboard

**Key capabilities:**
- **Automatic mode detection** — Identifies whether the host is a hotspot, wired node, Wi-Fi client, or port-mirror tap, and adjusts capture strategy accordingly.
- **Real-time bandwidth charts** — Per-device upload/download pushed to browser every 3 seconds via Server-Sent Events.
- **Device tracking** — MAC-address–based identity with passive fingerprinting (phone / laptop / TV / IoT / printer), hostname resolution (DNS + mDNS) and GeoIP for external IPs.
- **Activity attribution** — Resolves which *site and app* a client is using, entirely offline, from DNS and TLS/QUIC SNI matched against a bundled catalog.
- **Threat detection** — Rule-based detectors for port scanning, C2 beaconing, DNS tunnelling, rogue devices and lateral movement, each alert carrying its evidence and a confidence score.
- **Behavioural baselines** — Per-device hour-of-week profiles; deviations flagged by z-score, so "2 GB transferred" is only an alert if it is unusual *for that device, at that hour*.
- **ML anomaly detection** — Isolation Forest model trained continuously on live traffic features (packet rate, byte rate, connection count, protocol mix).
- **Incident fusion** — Related alerts collapse into risk-scored incidents, turning hundreds of notifications into a handful of things to triage.
- **Forecasting** — Holt double-exponential smoothing projects bandwidth forward with confidence bands and a link-saturation ETA.
- **Natural-language investigation** — "Ask NetWatch" answers questions about your own traffic via a tool-calling loop over read-only queries, returning the full tool trace alongside the answer.
- **Enforcement** — Per-device domain blocking, data quotas, blocked time windows and bounded pauses, via DNS sinkhole or kernel-level packet drop.
- **1304 automated tests** — Unit, integration, performance and evaluation coverage across all modules.

**The AI boundary.** All detection, attribution and forecasting above is
deterministic. A language model is used only to *narrate* facts and *recommend*
actions — never to decide. Recommendations are proposals a human approves;
answers ship with the queries that produced them; and every AI feature has a
deterministic fallback, so NetWatch works fully with no model installed. The
model itself runs locally via Ollama, so this adds no cloud dependency.

---

## Why NetWatch?

The core motivation is **privacy and accessibility**. Every byte of traffic data stays on the user's machine — no SaaS subscriptions, no API keys, no data leaving the network. At the same time, the setup is a single `pip install` + `python main.py`, making it accessible to developers, students, and small-business operators who cannot afford or justify enterprise tools.

---

## Advantages

- **Zero-cloud, zero-cost** — SQLite storage, no external dependencies; works fully offline.
- **Adaptive intelligence** — Automatically switches capture strategy when the network mode changes (e.g., hotspot turned off mid-session) without manual intervention.
- **Production-hardened** — Connection pool, async DB writer with overflow monitoring, 15-second graceful shutdown watchdog, rotating log files, and Docker/systemd deployment packages included.
- **Cross-platform** — Tested on Windows, Linux, and macOS with platform-specific privilege and driver handling.
- **Extensible** — Clean modular architecture (packet capture, orchestration, alerts, database, frontend) allows adding new protocols, modes, or ML models independently.

---

## Disadvantages

- **Requires elevated privileges** — Raw packet capture mandates Administrator/root access on all platforms — a non-starter in shared or restricted environments.
- **Visibility is host-scoped** — Without a managed switch or port mirror, only traffic passing through the monitoring host is captured; switched LAN segments are invisible.
- **Resource consumption** — Continuous packet capture and ML inference add CPU/memory overhead, making it unsuitable for very low-power embedded devices.
- **SQLite ceiling** — Local SQLite works well for home/small-office scale; high-traffic enterprise environments would require migration to PostgreSQL or a time-series DB.

---

## Future Directions

- **Threat intelligence feeds** — Correlate captured IPs against public blocklists (abuse.ch, Feodo Tracker) for automatic threat tagging, without breaking the offline-by-default guarantee.
- **Distributed agents** — A lightweight agent model where multiple hosts report to a central NetWatch instance, enabling full network-wide visibility without a managed switch.
- **eBPF capture backend** — Replace Scapy/libpcap with eBPF on Linux for near-zero-overhead capture at scale.
- **Mobile dashboard** — Progressive Web App wrapper for on-the-go monitoring from a phone.

---

*NetWatch · Python 3.11+ · MIT License · Local-first · 1304 tests*

</div>
