# NetWatch — AI-First Network Intelligence

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1304-green.svg)](#testing)

NetWatch watches your network, explains what it sees in plain English, and lets
you act on it — entirely on your own machine. It captures packets with Scapy,
tracks devices, fuses alerts into incidents, forecasts congestion, answers
questions about your own traffic, and enforces per-device controls.

**Nothing leaves your network.** Storage is local SQLite. The optional AI
features run against a local [Ollama](https://ollama.com) model. There is no
cloud account, no API key, and no telemetry.

---

## Overview

```
Packets (Scapy/Npcap)
   → packet_capture/   capture, parse, batch, write
   → event bus         packet.batch · flow.completed · dns.query · mode.changed
   → intelligence/     flows · twin · behavior · threats · incidents · forecast
   → backend/          Flask REST + SSE
   → frontend/         vanilla-JS SPA
```

Everything above the event bus is *deterministic*. The language model is used
only to **narrate and recommend** — never to decide. Every AI answer is
grounded in tool output the UI shows you, every recommendation is a proposal a
human approves, and every AI feature degrades to a deterministic fallback when
no model is running.

### Monitoring

- **Auto mode detection** — Hotspot, Ethernet, Wi-Fi Client, Port Mirror, Public Network
- **Real-time dashboard** — bandwidth, devices, protocols and alerts pushed over SSE
- **Device tracking** — MAC-keyed identity, OUI vendor, hostname resolution, passive fingerprinting (phone / laptop / TV / IoT / printer …)
- **Flow + DNS telemetry** — connections normalised into flow records with retention
- **Activity attribution** — which *site and app* a client is using, resolved offline from SNI/DNS via a bundled app catalog
- **Digital twin** — live who-talks-to-whom graph, rendered on the Topology page

### Detection

- **Threat detectors** — port scan, C2 beaconing, DNS tunnelling, rogue device, lateral movement — each alert carries its evidence and a confidence
- **Behavior baselines** — per-device hour-of-week profiles (Welford); deviations flagged by z-score
- **Anomaly detection** — Isolation Forest over traffic features
- **VPN / tunnel detection** — port signatures plus sustained-volume heuristics against an offline org database
- **Incident fusion** — related alerts for a device collapse into one incident with a risk score and band, so you triage 3 incidents instead of 300 alerts

### Intelligence

- **Ask NetWatch** — natural-language questions answered by a tool-calling loop over three read-only tools; the answer ships with the full tool trace so you can check it
- **Incident assessment** — the responder proposes `monitor` / `throttle` / `quarantine` / `dismiss_benign` with matched indicators; **nothing is auto-applied**
- **Briefing** — "what just happened in the last 10 minutes", facts gathered deterministically and only narrated by the model
- **Forecasting** — Holt double-exponential smoothing with confidence bands and a link-saturation ETA (pure math, no ML dependency)

### Control

- **Domain blocking** — per-device or network-wide, enforced by DNS sinkhole and, where available, kernel-level packet drop (WinDivert)
- **Parental controls** — daily data quotas, blocked time windows, and bounded pauses per device
- **Honest enforcement status** — every control endpoint reports whether it is *actually* being enforced and why not, rather than silently doing nothing

---

## Prerequisites

> **Python 3.11 or later is required.**

| Software | Platform | Purpose | Download |
|----------|----------|---------|----------|
| **Python 3.11+** | All | Runtime | [python.org](https://www.python.org/downloads/) |
| **Npcap** | Windows | Packet capture driver | [npcap.com](https://npcap.com/) |
| **Ollama** | All | *Optional* — local LLM for AI features | [ollama.com](https://ollama.com) |
| **pydivert** | Windows | *Optional* — packet-level blocking | `pip install pydivert` |

### Platform notes

- **Windows:** install Npcap with **"WinPcap API-compatible Mode"** checked, and run NetWatch from a terminal launched **as Administrator**.
- **Linux:** run with `sudo`; install `libpcap-dev` if missing (`apt install libpcap-dev`).
- **macOS:** run with `sudo`; Xcode command-line tools may be required (`xcode-select --install`).

> NetWatch refuses to start without Administrator/root privileges. Raw packet
> capture requires it and this cannot be bypassed.

---

## Quick Start

```bash
git clone https://github.com/your-team/netwatch.git
cd netwatch

# Virtual environment (use py -3.11 / python3.11 if you have several Pythons)
python -m venv venv
venv\Scripts\activate             # Windows
source venv/bin/activate          # Linux / macOS

pip install -r requirements.txt
python database/init_db.py
```

Run it (elevated):

```bash
python main.py                    # Windows — Administrator terminal
sudo venv/bin/python main.py      # Linux / macOS
```

Open **http://localhost:5000**.

### Enabling the AI features (optional)

The dashboard works fully without this. Ask NetWatch, incident assessment and
the briefing narrative need a local model:

```bash
# Install Ollama from ollama.com, then:
ollama pull llama3.2:3b
```

That is the whole setup — NetWatch talks to `http://127.0.0.1:11434` over plain
HTTP with no SDK and no API key. `GET /api/investigate/status` tells you whether
a model is reachable. When it isn't:

| Feature | Without a model |
|---|---|
| Ask NetWatch | reports `available: false` with install instructions |
| Incident assessment | deterministic rule verdict (`source: "rules"`) |
| Briefing | facts composed into a sentence without narration |
| Everything else | unaffected — detection and forecasting never use the model |

### Docker

> Packet capture requires `network_mode: host` and `NET_ADMIN` + `NET_RAW`.
> Bridge networking will **not** see host traffic.

```bash
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
docker compose up -d
docker compose logs -f netwatch
```

The bundled `docker-compose.yml` already sets those and persists the database in
a named volume.

### CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 5000 | Web server port |
| `--host` | 127.0.0.1 | Bind address |
| `--mode` | auto | Pin capture mode: `auto`, `hotspot`, `ethernet`, `public_network`, `port_mirror` |
| `--no-capture` | off | Dashboard only, no packet capture |
| `--reset-db` | off | Clear all stored data before starting |
| `--log-level` | INFO | DEBUG, INFO, WARNING, ERROR |
| `--log-file` | auto | Log to a specific file path |

`--mode` exists because port-mirror auto-detection is unreliable; pin it for
SPAN setups and for demos. It can also be set via `NETWATCH_FORCE_MODE`.

---

## Project Structure

```
netwatch/
├── main.py                    # Entry point (CLI, logging, startup wiring)
├── config.py                  # Central configuration — every setting, env-overridable
├── orchestration/             # Application lifecycle
│   ├── state.py               #   Shared singletons & sync primitives
│   ├── shutdown.py            #   Graceful shutdown with watchdog
│   ├── mode_handler.py        #   Mode-change callbacks, capture lifecycle
│   ├── discovery_manager.py   #   Device discovery loop, ARP/ping scanning
│   └── background_tasks.py    #   Intelligence startup, cleanup, policy enforcement
├── packet_capture/            # Capture engine & mode detection
│   ├── capture_engine.py      #   Scapy-based sniffing
│   ├── packet_processor.py    #   Batch processing & queue
│   ├── database_writer.py     #   Async DB writer thread
│   ├── parser.py              #   Protocol identification
│   ├── quic_sni.py            #   QUIC/TLS SNI extraction
│   ├── sni_ip_learner.py      #   Maps server IPs back to domains
│   ├── dns_blocker.py         #   DNS sinkhole enforcement
│   ├── traffic_blocker.py     #   Packet-level blocking (WinDivert/ARP)
│   ├── mode_detector.py       #   Auto network mode detection
│   └── modes/                 #   hotspot · ethernet · public_network · port_mirror
├── intelligence/              # The AI-first layer  (see docs/ARCHITECTURE.md)
│   ├── event_bus.py           #   In-process pub/sub, drop-oldest, never blocks
│   ├── flow_normalizer.py     #   packet.batch → flow records + DNS log
│   ├── twin.py                #   Live network graph
│   ├── behavior.py            #   Hour-of-week baselines, z-score deviations
│   ├── threats.py             #   Detector pack with evidence + confidence
│   ├── vpn_detector.py        #   Tunnel classification
│   ├── incidents.py           #   Alert→incident fusion, risk scoring
│   ├── forecast.py            #   Holt smoothing, saturation ETA
│   ├── device_fingerprint.py  #   Passive device typing
│   ├── app_catalog.py         #   Hostname → app/org
│   ├── ip_org.py              #   Offline IP → owning org
│   ├── investigator.py        #   Ask NetWatch tool-calling loop
│   ├── investigator_tools.py  #   The only data the model may touch
│   ├── responder.py           #   Incident verdicts + rule fallback
│   ├── briefing.py            #   "What just happened"
│   └── llm_runtime.py         #   Local Ollama client; None when unavailable
├── database/                  # Data layer
│   ├── connection.py          #   SQLite connection pool (WAL)
│   ├── schema.sql             #   Table definitions
│   ├── migrations/            #   Ordered schema migrations
│   └── queries/               #   device · flow · incident · blocking · policy · stats …
├── alerts/                    # Threshold engine, dedup, IsolationForest anomalies
├── backend/                   # Flask REST API
│   ├── app.py                 #   Application factory
│   └── blueprints/            #   15 blueprints — see docs/API_REFERENCE.md
├── frontend/                  # Vanilla-JS SPA
│   ├── index.html
│   ├── css/
│   └── js/components/         #   Dashboard · Devices · Alerts · Topology · Security
│                              #   · Forecast · Behavior · Activity · Controls · Ask
├── utils/                     # Health monitor, realtime state, cache, metrics
├── tests/                     # 1304 pytest tests
├── scripts/                   # Demo preflight, detector eval, red-team demo
├── evaluation/                # Detector & faithfulness evaluation harness
├── deploy/                    # Windows installer, .deb, .app, systemd, nginx
└── docs/                      # Documentation
```

---

## Dashboard Pages

| Page | Route | What it shows |
|---|---|---|
| Dashboard | `/` | Live bandwidth, protocol mix, top devices, health score, briefing |
| Devices | `/devices` | Every known device — vendor, type, usage; rename them |
| Alerts | `/alerts` | Raw alert feed with filters, plus custom alert rules |
| Topology | `/topology` | Digital-twin graph of who talks to whom |
| Security | `/security` | Incidents ranked by risk, with evidence and AI assessment |
| Forecast | `/forecast` | Bandwidth projection, confidence band, saturation ETA |
| Behavior | `/behavior` | Learned per-device baselines and deviations |
| Activity | `/activity` | Live per-client site/app feed |
| Controls | `/controls` | Blocking rules, quotas, schedules, pauses |
| Ask NetWatch | `/ask` | Natural-language questions with the tool trace |

`/incidents` and `/threats` are back-compat aliases for `/security`, which
merges both.

---

## Network Modes

NetWatch auto-detects your connection and adapts its capture strategy:

| Mode | Trigger | Visibility | Promiscuous | ARP Scan |
|------|---------|------------|-------------|----------|
| **Hotspot** | Mobile hotspot / ICS active | All connected clients | ON | Yes |
| **Wi-Fi Client** | Connected to WiFi or phone hotspot | Own traffic only (OS filters other stations) | OFF | No |
| **Ethernet** | Wired NIC with default gateway | Local subnet via ARP discovery | ON | Yes |
| **Port Mirror** | SPAN port (>50% foreign MACs seen) | Full segment — all devices, all traffic | ON | Yes |
| **Public Network** | Campus/hotel WiFi (fallback) | Own traffic only; passive ARP cache, no probing | OFF | No |
| **Disconnected** | No interface or no IP | Capture paused; dashboard stays up | — | No |

**Enforcement caveat:** blocking and parental controls only bite when clients
route *through* this host — i.e. **hotspot mode** — unless packet-level blocking
(WinDivert) is available. The API says so explicitly in the `status.reason`
field of every control response rather than pretending a saved rule is an
applied one.

**Supported connections:** Wi-Fi client, mobile hotspot, Ethernet (host, client
or direct link), USB tethering (RNDIS/NCM → detected as Ethernet), switch port
mirroring, public/campus Wi-Fi, and VPN tunnels (classified correctly, captured
on the physical interface).

---

## Configuration

Every setting lives in `config.py` and can be overridden by an environment
variable or a `.env` file. Copy `.env.example` to `.env` to start. Common ones:

| Variable | Default | Purpose |
|---|---|---|
| `NETWATCH_ENV` | development | `development` \| `production` \| `testing` |
| `FLASK_HOST` / `FLASK_PORT` | 127.0.0.1 / 5000 | Bind address |
| `SECRET_KEY` | — | **Required in production** |
| `NETWATCH_AUTH_ENABLED` | false | Require an API key on the API |
| `NETWATCH_API_KEY` | — | The key, when auth is on |
| `DATABASE_PATH` | `netwatch.db` | SQLite location |
| `NETWATCH_FORCE_MODE` | — | Pin capture mode (same as `--mode`) |
| `NETWATCH_LLM_MODEL` | `llama3.2:3b` | Ollama model for AI features |
| `NETWATCH_LLM_TIMEOUT` | 180 | Seconds before giving up on the model |
| `NETWATCH_LLM_MAX_STEPS` | 6 | Tool-call budget per question |
| `FORECAST_LINK_CAPACITY_MBPS` | 0 | Set your link speed to get saturation ETAs |
| `INCIDENT_WINDOW_MINUTES` | 30 | How long an incident stays open to new alerts |

Threat thresholds, flow timeouts, behavior windows, retention limits and pool
sizes are likewise env-overridable — see the grouped sections in `config.py`.

---

## Testing

```bash
pytest tests/ -v                                    # full suite (1304 tests)
pytest tests/ --cov=. --cov-report=term-missing     # with coverage
pytest tests/test_threats.py -v                     # one module
```

Evaluation and demo harnesses live in `scripts/`:

```bash
python scripts/eval_detectors.py       # detector precision/recall
python scripts/eval_faithfulness.py    # are AI answers grounded in tool output?
python scripts/demo_preflight.py       # pre-demo environment check
python scripts/redteam_demo.py         # synthetic attack traffic
```

---

## Deployment

| Platform | Method | Script |
|----------|--------|--------|
| Windows | PyInstaller → .exe + installer | `deploy/create_windows_installer.py` |
| Linux | .deb package + systemd unit | `deploy/create_deb_package.sh` |
| macOS | .app bundle | `deploy/create_macos_app.sh` |

See the [Production Deployment Guide](docs/PRODUCTION_DEPLOYMENT.md).

---

## Documentation

| Document | Description |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | System design, event flow, intelligence layer, threading |
| [API Reference](docs/API_REFERENCE.md) | Every REST endpoint with request/response examples |
| [User Manual](docs/USER_MANUAL.md) | Dashboard walkthrough, pages, alerts, FAQ |
| [Setup Guide](docs/SETUP_GUIDE.md) | Detailed installation for all connection types |
| [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md) | Services, security, backups |
| [Security](docs/SECURITY.md) | Threat model, auth, hardening |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and platform fixes |
| [Port Mirror Setup](docs/PORT_MIRROR_SETUP.md) | Configuring a SPAN port |
| [Ethernet Cable Guide](docs/ETHERNET_CABLE_GUIDE.md) | Direct-link and wired setups |
| [Idle Client Baseline](docs/IDLE_CLIENT_BASELINE.md) | What "idle" should look like |
| [Demo Runbook](docs/DEMO_RUNBOOK.md) | Running a live demo |
| [Contributing](CONTRIBUTING.md) | Dev workflow, code style, PR process |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Capture | Python 3.11, Scapy 2.5, Npcap (Windows) |
| API | Flask 3.0, Waitress |
| Database | SQLite (WAL) with connection pool |
| Detection | scikit-learn (Isolation Forest), Welford baselines, rule detectors |
| Forecasting | Holt double-exponential smoothing (stdlib math) |
| AI | Local Ollama (`llama3.2:3b` by default) over plain HTTP — optional |
| Frontend | Vanilla JS SPA, CSS custom properties, SSE |
| Data | pandas, numpy |
| System | psutil |

---

## Meet the Team

| Name | Role | GitHub |
|------|------|--------|
| **Harsha** | Project Lead · DevOps · ML · Integration & Testing | [@harsha](https://github.com/harshareddy-bathala) |
| **Likitha** | Frontend Development | [@likitha](https://github.com/likithajagan) |
| **Chinmay** | Backend Development | [@chinmay](https://github.com/chinmayichinnu56) |
| **Manoj** | Packet Capture Engine | [@manoj](https://github.com/manojpnaik2006-p) |
| **Deepika** | Database & Documentation | [@deepika](https://github.com/deepikakudum) |

---

## License

MIT — see [LICENSE](LICENSE).
