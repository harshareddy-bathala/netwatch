# NetWatch v3.0.0 — Presentation Guide

> **Presenter notes & talking points for a live demo / project walkthrough.**
> Use this document as your slide-by-slide script. Each numbered section
> maps to one "slide" or demo segment — spend roughly the time indicated.

---

## Slide 0 — Title (30 s)

> **NetWatch — Intelligent Network Traffic Analysis System**

- "Good [morning/afternoon], we are Team NetWatch."
- "Today we'll walk you through a production-ready, real-time network
  monitoring system built entirely in Python — zero cloud, zero cost."
- Introduce yourself (Manoj — Packet Capture), then let each member
  introduce briefly:

| Name | Role |
|------|------|
| **Harsha** | Project Lead · DevOps · ML · Integration & Testing |
| **Likitha** | Frontend Development |
| **Chinmay** | Backend Development |
| **Manoj** | Packet Capture Engine |
| **Deepika** | Database & Documentation |

---

## Slide 1 — Problem Statement (1 min)

- "Most network monitoring tools are either enterprise-grade and
  expensive (PRTG, SolarWinds, Wireshark for raw captures) or
  cloud-dependent (Datadog, New Relic)."
- "There's no lightweight, local-only, cross-platform tool that
  auto-detects your network type, captures packets, runs ML anomaly
  detection, and gives you a live web dashboard — all from a single
  `python main.py` command."
- **Key pain points we solve:**
  1. No cloud dependency — everything runs on your laptop
  2. Auto-detects Hotspot / WiFi / Ethernet / Port Mirror / Public mode
  3. Real-time dashboard with 3-second SSE push
  4. ML-powered anomaly detection (Isolation Forest)
  5. Cross-platform: Windows, Linux, macOS

---

## Slide 2 — Architecture Overview (2 min)

> Show the system diagram from `docs/ARCHITECTURE.md` or draw live.

```
  Network Interface
        │
  ┌─────▼──────────────┐
  │  Packet Capture     │  ← Scapy + BPF filters, mode-aware
  │  (capture_engine)   │
  └─────┬──────────────┘
        │ Parsed packets
  ┌─────▼──────────────┐
  │  SQLite Database    │  ← WAL mode, connection pool, rollup
  │  (connection pool)  │
  └─────┬──────────────┘
        │
   ┌────┴────┐
   │         │
┌──▼───┐  ┌──▼──────────┐
│Alerts│  │Flask REST API│  ← Blueprints, middleware, SSE
│ + ML │  │  + Frontend  │
└──────┘  └─────────────┘
```

**Talking points:**
- Single-process, multi-threaded monolith — capture thread, anomaly
  thread, health monitor thread, cleanup thread, Flask main thread.
- All data stays local in `netwatch.db` (SQLite WAL).
- Frontend is a vanilla JS SPA — no React/Angular build step.

---

## Slide 3 — Network Mode Detection (2 min)

> This is our **USP** — auto-detection of the network topology.

| Mode | When | What you see | ARP Scan | Promiscuous |
|------|------|--------------|----------|-------------|
| **Hotspot** | You share internet | All client devices | ✅ Active | ON |
| **Wi-Fi Client** | Connected to WiFi | Own traffic only | ❌ Passive cache | OFF |
| **Ethernet** | Wired NIC | Subnet via ARP | ✅ Active | ON |
| **Port Mirror** | SPAN port | Full segment | ✅ Active | ON |
| **Public Network** | Untrusted WiFi | Own traffic only | ❌ Passive cache | OFF |
| **Disconnected** | No interface | Capture paused | — | — |

- "The system automatically picks the right mode on startup, adjusts
  BPF filters, toggles promiscuous mode, and enables or disables ARP
  scanning — no manual config needed."
- "If you unplug ethernet or turn off your hotspot, it detects the
  change in real time and transitions gracefully."

**Demo suggestion:** Show `GET /api/status` to display the current mode.

---

## Slide 4 — Packet Capture Engine (2 min)

> **Presenter: Manoj**

- Built on **Scapy 2.5** with Npcap (Windows) / libpcap (Linux/macOS).
- **CaptureEngine** runs in a dedicated thread with a configurable
  `PacketProcessor` queue (100 K packets deep).
- BPF filter is mode-aware:
  - WiFi Client → `ether host <MAC>` (captures IPv4 + IPv6)
  - Hotspot → `net <subnet>`
  - Port Mirror → empty (capture everything)
- **DatabaseWriter** batches inserts (1 000 rows per commit, 0.5 s flush).
- **BandwidthCalculator** uses a 10-second sliding window for smooth,
  responsive charts.
- Passive hostname learning from mDNS, NetBIOS-NS, DNS, DHCP, SSDP
  packets — no active lookups needed.

---

## Slide 5 — Database Layer (1.5 min)

> **Presenter: Deepika**

- **SQLite** in WAL mode for concurrent reads + writes.
- **Connection pool** (5 dev / 15 prod) prevents lock contention.
- Schema: `devices`, `traffic_summary`, `alerts`, `bandwidth_rollup`,
  `system_config`, plus migration tracking.
- **Rollup engine**: 1-minute aggregates for bandwidth history;
  24-hour retention for raw rows, 30-day retention for rollups.
- `run_full_cleanup()` prunes old data + `VACUUM` on schedule.

---

## Slide 6 — Backend & API (1.5 min)

> **Presenter: Chinmay**

- **Flask 3.0** application factory (`create_app()`).
- **7 blueprints**: bandwidth, devices, alerts, system, discovery,
  export, interface.
- **SSE (Server-Sent Events)** push every 3 seconds — no polling lag.
- **Security middleware** (single `register_middleware()` call):
  - API key auth (`X-API-Key` header or `?api_key=` query param)
  - Sliding-window rate limiter: 100 req/min + 2 000 req/hour per IP
  - Security headers: CSP (no unsafe-inline), HSTS, X-Frame-Options
  - Request ID tracing in production
- **Waitress** WSGI server (8 threads) in production; Flask dev server
  in development.

---

## Slide 7 — Frontend Dashboard (1.5 min)

> **Presenter: Likitha**

- **Vanilla JS SPA** — zero build tools, instant load.
- CSS custom properties for theming (dark/light).
- **Chart.js** for bandwidth line chart + protocol doughnut.
- **EventSource** (SSE) for real-time metric cards, device list, alerts.
- Responsive layout: works on tablet and desktop.
- Key views:
  - Dashboard: bandwidth chart, top devices, protocol dist, health score
  - Devices: searchable, sortable, editable hostnames
  - Alerts: severity filter, time range, resolve action

**Demo suggestion:** Open `http://localhost:5000` and narrate the
live-updating cards, bandwidth chart, and device list.

---

## Slide 8 — ML Anomaly Detection (1.5 min)

> **Presenter: Harsha**

- **Isolation Forest** (scikit-learn) with 200 estimators.
- **8 features** extracted from traffic:
  `total_bandwidth`, `active_connections`, `unique_protocols`,
  `tcp_retransmit_ratio`, `icmp_unreachable_rate`,
  `dns_queries_count`, `http_requests_count`, `https_requests_count`.
- **StandardScaler** normalization → sigmoid-based anomaly score (0–1).
- Trains after 60 samples (~15 min at 15 s intervals).
- Model persisted to `models/anomaly_model.joblib` — survives restarts.
- Sklearn version mismatch detection: auto-discards stale model and
  retrains from scratch.
- All alerts flow through `AlertEngine` with cooldown-based
  deduplication (5-min window).

---

## Slide 9 — Health Score & Alerting (1 min)

- **Composite health score** (0–100):
  | Factor | Weight |
  |--------|--------|
  | Bandwidth utilization | 30% |
  | Packet loss | 25% |
  | Latency | 25% |
  | Active anomalies | 20% |

- **Alert types**: bandwidth warning/critical, device count, anomaly,
  health score drop.
- **Severity levels**: low → medium → high → critical.
- Deduplication prevents alert fatigue (300 s cooldown per type).

---

## Slide 10 — DevOps & Deployment (1 min)

> **Presenter: Harsha**

- **Docker** support: `docker compose up -d` with `network_mode: host`
  and `NET_ADMIN` + `NET_RAW` capabilities.
- **Platform installers**:
  - Windows: PyInstaller → `.exe` + service via NSSM
  - Linux: `.deb` package + systemd unit
  - macOS: `.app` bundle + launchd plist
- **Production hardening**:
  - `SECRET_KEY` required (`RuntimeError` if missing)
  - `NETWATCH_ENV=production` enables auth, rate limiting, JSON logs
  - Reverse proxy (Nginx) for HTTPS termination
  - Log rotation: 50 MB × 5 files

---

## Slide 11 — Testing & Quality (1 min)

> **Presenter: Harsha**

- **590 tests** passing (pytest) — covers:
  - Unit: mode detection, packet parsing, protocol identification
  - Integration: mode switch lifecycle, capture start/stop
  - API: all endpoints, auth, rate limiting, SSE
  - Frontend: smoke tests, chart rendering
  - Performance: load simulation, DB stress
  - Security: middleware, HSTS, CSP, version stripping
- **Python 3.11 enforced** — hard startup guard rejects other versions.
- CI-ready: `pytest tests/ -q` completes in ~2 min.

---

## Slide 12 — Live Demo Script (3–5 min)

> If time allows, run the app live. Here's a suggested flow:

1. **Start:** `python main.py` (as Admin) → show banner, mode detection
   log line.
2. **Dashboard:** Open `http://localhost:5000` → point out health score,
   bandwidth chart auto-updating, protocol donut.
3. **Generate traffic:** Open YouTube / run `curl` in another terminal →
   watch bandwidth spike on the chart.
4. **Devices page:** Show your own device; explain hostname editing.
5. **Alerts page:** If an anomaly fired, show it; otherwise explain the
   deduplication.
6. **API:** `curl http://localhost:5000/api/status` → JSON with mode,
   uptime, version.
7. **Mode info:** `curl http://localhost:5000/api/interface/status` →
   show current mode and capabilities.
8. **Shutdown:** Press `Ctrl+C` → show graceful shutdown log
   ("Shutdown complete" in 2–3 s).

---

## Slide 13 — Challenges & Lessons Learned (1 min)

- **WiFi AP isolation**: Initially enabled active ARP scanning in WiFi
  client mode; discovered it was unnecessary and potentially noisy —
  switched to passive ARP cache reads only.
- **IPv6 blind spot**: Early BPF filter `host <ip>` only matched IPv4,
  silently dropping YouTube/Google IPv6 traffic — fixed with
  `ether host <mac>`.
- **Thread deadlocks**: Interface-lost callback fired from capture thread
  tried to `join()` itself — fixed by dispatching re-detection to a
  short-lived background thread.
- **Sklearn version drift**: Persisted model trained on an older sklearn
  version produced silent prediction errors — added version mismatch
  detection and auto-retrain.

---

## Slide 14 — Production Readiness Assessment (30 s)

| Area | Status | Score |
|------|--------|-------|
| Core functionality | All modes working, capture + DB + API + frontend | ✅ |
| Test coverage | 590 / 590 passing | ✅ |
| Security | Auth, rate limiting (min + hour), CSP, HSTS | ✅ |
| Documentation | README, Architecture, API Ref, User Manual, Security, Setup, Troubleshooting | ✅ |
| Deployment | Docker, Windows service, Linux .deb, macOS .app | ✅ |
| Observability | Structured JSON logs, request ID tracing, health monitor | ✅ |
| Interpreter guard | Hard-fails on non-3.11 Python | ✅ |
| CORS safety | Allowlisted origins; wildcard disables credentials | ✅ |

### **Overall Production Readiness: 92%**

**Remaining 8%:**
- End-to-end load testing in production-equivalent environment
- External security audit / pen-test
- Real-world soak test (72+ hours continuous operation)
- CI/CD pipeline with automated test gating

---

## Slide 15 — Q & A

- "Thank you! We're happy to take questions."
- Keep the app running for live Q&A demos.

---

## Appendix — Quick Reference for the Presenter

### Start the app
```powershell
cd C:\Users\manoj\Downloads\netwatchd
venv\Scripts\Activate.ps1
python main.py
```

### Run full test suite
```powershell
python -m pytest tests/ -q
```

### Key API endpoints for demo
| Endpoint | Purpose |
|----------|---------|
| `GET /api/status` | System status + mode |
| `GET /api/stats/realtime` | Live bandwidth + packet counts |
| `GET /api/devices` | Device list |
| `GET /api/alerts` | Alert feed |
| `GET /api/bandwidth/history` | Bandwidth chart data |
| `GET /api/stream` | SSE event stream |
| `GET /api/interface/status` | Current mode + capabilities |
| `GET /health` | Load-balancer health check |
