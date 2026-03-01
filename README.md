# NetWatch v3.0.0 — Intelligent Network Traffic Analysis System

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-641-green.svg)](#testing)

## What's New in v3.0.0

- **Accurate per-mode device filtering** — Multicast MACs (IPv4/IPv6/STP) are now rejected by the device tracker, eliminating phantom devices in WiFi Client and other modes.
- **Public IP exclusion** — Public IPs are no longer assigned to device objects in the SSE top-devices payload; only private/RFC1918 addresses are shown.
- **Stable bandwidth charts** — The DB-to-live data boundary uses a rounded 10-second cutoff, eliminating oscillation. The false zero-point bridge insertion has been removed.
- **Graceful Ctrl+C shutdown** — The signal handler now raises `KeyboardInterrupt` to break out of blocking server calls, ensuring clean shutdown within 2–3 seconds on all platforms.
- **CSS variable fix** — Corrected `--text-secondary` to `--color-text-secondary` for consistent theming.
- **Hostname resolver improvement** — The local machine's own IP is resolved instantly to its hostname without DNS lookup.

## Overview

NetWatch is a production-ready, real-time network traffic monitoring and analysis system. It automatically detects your network connection type, captures packets with Scapy, tracks devices, calculates bandwidth, detects anomalies with machine learning, and displays everything on a live web dashboard.

### Key Features

- **Auto Mode Detection** — Hotspot, Ethernet, Public Network, Port Mirror
- **Real-time Dashboard** — Bandwidth charts (SSE push @ 3s), device list, protocol distribution, alert feed
- **New Device Alerts** — MAC-based detection of unknown devices connecting to your hotspot
- **Anomaly Detection** — Isolation Forest ML algorithm flags unusual traffic patterns
- **Health Score** — Composite 0–100 network health rating
- **Alert System** — Threshold + ML alerts with deduplication and lifecycle management
- **Disconnected Detection** — Gracefully pauses capture when network drops (e.g., hotspot turned off)
- **Cross-platform** — Windows, Linux, macOS with platform-specific deployment packages
- **Zero Cloud** — Everything runs locally with SQLite; no external services required

---

## Prerequisites

> **Python 3.11 or later is required.** NetWatch has been tested and validated with Python 3.11+. Earlier versions are not supported.

### Required Software

| Software | Platform | Purpose | Download |
|----------|----------|---------|----------|
| **Python 3.11+** | All | Runtime | [python.org](https://www.python.org/downloads/) |
| **Npcap** | Windows | Packet capture driver | [npcap.com](https://npcap.com/) |
| **pip** | All | Package manager | Bundled with Python 3.11 |

### Platform Notes

- **Windows:** Install Npcap with **"WinPcap API-compatible Mode"** checked. **Run NetWatch as Administrator** (right-click terminal → "Run as administrator"). Packet capture requires raw socket access which is only available with elevated privileges.
- **Linux:** **Run with `sudo`**. Install `libpcap-dev` if not present (`apt install libpcap-dev`). Root is required for raw packet capture.
- **macOS:** **Run with `sudo`**. Xcode command-line tools may be required (`xcode-select --install`).

> **Important:** NetWatch will refuse to start without Administrator/root privileges. This is a hard requirement for packet capture and cannot be bypassed.

---

## Quick Start

### 1. Verify Python 3.11

```bash
python --version
# Expected: Python 3.11.x
```

If you have multiple Python versions, use the specific Python 3.11 path:
```bash
# Windows
py -3.11 --version

# Linux / macOS
python3.11 --version
```

### 2. Clone & Create Virtual Environment

```bash
git clone https://github.com/your-team/netwatch.git
cd netwatch

# Create venv with Python 3.11 specifically
python -m venv venv               # If 'python' is 3.11
py -3.11 -m venv venv             # Windows with multiple Python versions
python3.11 -m venv venv           # Linux / macOS with multiple versions
```

### 3. Activate & Install

```bash
# Activate the virtual environment
venv\Scripts\activate             # Windows (cmd)
venv\Scripts\Activate.ps1         # Windows (PowerShell)
source venv/bin/activate          # Linux / macOS

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python database/init_db.py
```

### 4. Run NetWatch

> **Administrator / root access is mandatory.** Packet capture requires raw socket
> privileges. NetWatch will exit with an error if not elevated.

```bash
# Windows — Run terminal as Administrator first
python main.py

# Linux / macOS
sudo venv/bin/python main.py

# With options
python main.py --port 8080 --log-level DEBUG --no-capture
```

Open **http://localhost:5000** in your browser.

### Docker

> Packet capture requires `network_mode: host` and `NET_ADMIN` + `NET_RAW`
> capabilities. Bridge networking will **not** see host traffic.

```bash
# Set a secret key (required in production)
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Build and start
docker compose up -d

# View logs
docker compose logs -f netwatch
```

The included `docker-compose.yml` already sets `network_mode: host`,
`cap_add: [NET_ADMIN, NET_RAW]`, and persists the database in a named
volume.  If you use a custom compose file, ensure those settings are
present or NetWatch will not be able to capture packets.

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 5000 | Web server port |
| `--host` | 127.0.0.1 | Bind address |
| `--no-capture` | off | Start without packet capture |
| `--log-level` | INFO | DEBUG, INFO, WARNING, ERROR |
| `--log-file` | auto | Custom log file path |

---

## Project Structure

```
netWatch/
├── main.py                    # Entry point (CLI, logging, server start)
├── config.py                  # Central configuration (all settings)
├── requirements.txt           # Dependencies
├── orchestration/             # Application lifecycle management
│   ├── state.py               # Shared singletons & sync primitives
│   ├── shutdown.py            # Graceful shutdown with watchdog
│   ├── mode_handler.py        # Mode change callbacks, capture lifecycle
│   ├── discovery_manager.py   # Device discovery loop, ARP/ping scanning
│   └── background_tasks.py    # Cleanup, anomaly detector, watchdog
├── packet_capture/            # Capture engine & mode detection
│   ├── capture_engine.py      # Scapy-based packet sniffing
│   ├── database_writer.py     # Async DB writer thread
│   ├── packet_processor.py    # Batch processing & queue
│   ├── bandwidth_calculator.py# Sliding-window bandwidth
│   ├── parser.py              # Protocol identification
│   ├── mode_detector.py       # Auto network mode detection
│   ├── interface_manager.py   # Interface enumeration & callbacks
│   ├── filter_manager.py      # BPF filter validation
│   ├── network_discovery.py   # ARP scanning
│   └── modes/                 # Mode implementations
│       ├── base_mode.py       #   Abstract base
│       ├── hotspot_mode.py    #   Mobile hotspot
│       ├── ethernet_mode.py   #   Wired connection
│       ├── public_network_mode.py # WiFi client / public Wi-Fi
│       └── port_mirror_mode.py#   SPAN port
├── database/                  # Data layer
│   ├── connection.py          # SQLite connection pool (WAL)
│   ├── models.py              # Data models
│   ├── schema.sql             # Table definitions
│   ├── init_db.py             # DB initialization
│   ├── rollup.py              # Traffic data rollup
│   └── queries/               # Separated query modules
│       ├── device_queries.py  #   Device CRUD & counting
│       ├── network_filters.py #   Subnet/IP/MAC validation
│       ├── packet_store.py    #   Packet batch writes
│       ├── stats_queries.py   #   Statistics queries
│       ├── traffic_queries.py #   Traffic data queries
│       └── maintenance.py     #   Cleanup & retention
├── alerts/                    # Alert system
│   ├── alert_engine.py        # Threshold engine
│   ├── deduplication.py       # Cooldown-based throttle
│   └── anomaly_detector.py    # IsolationForest ML
├── backend/                   # Flask REST API
│   ├── app.py                 # Application factory
│   └── blueprints/            # Modular API endpoints
├── frontend/                  # SPA dashboard
│   ├── index.html             # Single page app
│   ├── css/                   # Modular CSS
│   └── js/                    # Components & utils
├── utils/                     # Shared utilities
│   ├── health_monitor.py      # System health metrics
│   ├── realtime_state.py      # In-memory dashboard state
│   └── query_cache.py         # TTL cache for queries
├── tests/                     # 624 pytest tests
├── deploy/                    # Deployment scripts
│   ├── create_windows_installer.py
│   ├── create_deb_package.sh
│   └── create_macos_app.sh
└── docs/                      # Documentation
```

---

## Network Modes

NetWatch auto-detects your connection and optimizes capture:

| Mode | Trigger | Visibility | Promiscuous | ARP Scan | ARP Cache |
|------|---------|------------|-------------|----------|-----------|
| **Hotspot** | Mobile hotspot / ICS active | All connected client devices | ON | Yes | Yes |
| **Wi-Fi Client** | Connected to WiFi or phone hotspot | Own traffic only (OS filters other stations) | OFF | No | Yes |
| **Ethernet** | Wired NIC with default gateway | Local subnet traffic via ARP discovery | ON | Yes | Yes |
| **Port Mirror** | SPAN port detected (>50% foreign MACs in captured traffic) | Full network segment — all devices and all traffic | ON | Yes | Yes |
| **Public Network** | Campus/hotel WiFi (fallback when no other mode matches) | Own traffic only; passive ARP cache only, no active probing | OFF | No | Yes |
| **Disconnected** | No active network interface or no IP address | Capture paused; dashboard remains accessible | — | No | No |

**Supported connection types:**
- WiFi client (connecting to any WiFi/hotspot)
- Mobile hotspot (sharing internet from your phone/laptop)
- Ethernet cable (host, client, or direct link)
- USB tethering (RNDIS/NCM — detected as Ethernet)
- Switch port mirroring (SPAN)
- Public/campus WiFi networks
- VPN connections (tunnels classified correctly, captures on physical interface)

---

## Testing

```bash
# Full suite
pytest tests/ -v

# With coverage
pytest tests/ --cov=. --cov-report=term-missing

# Specific category
pytest tests/test_mode_detection.py -v
pytest tests/test_performance.py -v
```

---

## Deployment

| Platform | Method | Script |
|----------|--------|--------|
| Windows | PyInstaller → .exe + installer batch | `deploy/create_windows_installer.py` |
| Linux | .deb package + systemd service | `deploy/create_deb_package.sh` |
| macOS | .app bundle | `deploy/create_macos_app.sh` |

See [Production Deployment Guide](docs/PRODUCTION_DEPLOYMENT.md) for details.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System design, data flow, component diagram |
| [API Reference](docs/API_REFERENCE.md) | All REST endpoints with request/response examples |
| [User Manual](docs/USER_MANUAL.md) | Dashboard walkthrough, modes, alerts, FAQ |
| [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md) | Installation, services, security, backups |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and platform-specific fixes |
| [Setup Guide](docs/SETUP_GUIDE.md) | Detailed installation for all connection types |
| [Contributing](CONTRIBUTING.md) | Dev workflow, code style, PR process |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Capture | **Python 3.11**, Scapy 2.5 |
| API | Flask 3.0 |
| Database | SQLite (WAL mode) with connection pool |
| ML | scikit-learn (Isolation Forest) |
| Frontend | Vanilla JS SPA, CSS custom properties, SSE real-time push |
| Data | pandas, numpy |
| System | psutil (monitoring), Npcap (Windows capture driver) |

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
