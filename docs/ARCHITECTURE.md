# NetWatch System Architecture

This document describes the architecture of the NetWatch network traffic analysis system.

## Table of Contents

1. [Overview](#overview)
2. [Project File Structure](#project-file-structure)
3. [System Diagram](#system-diagram)
4. [Components](#components)
5. [Data Flow](#data-flow)
6. [Technology Stack](#technology-stack)
7. [Threading Model](#threading-model)
8. [Database Schema](#database-schema)
9. [Monitoring Modes & Network Topology](#monitoring-modes--network-topology)
10. [Production Hardening](#production-hardening)
11. [Security Considerations](#security-considerations)

---

## Overview

NetWatch is a monolithic application that runs entirely on a single machine. It consists of seven main component groups that work together to capture, store, analyze, and visualize network traffic data.

**Design Principles:**
- **Local-only:** No cloud dependencies, no external services
- **Real-time:** Data flows from capture to display in under 3 seconds
- **Modular:** Each component has clear responsibilities and interfaces
- **Simple:** Uses SQLite for storage, Flask for API, vanilla JavaScript for frontend
- **24/7 Production-ready:** Adaptive retention, connection pool validation, disk monitoring, and graceful shutdown with watchdog

---

## Project File Structure

```
netwatchd/
├── main.py                         # Application entry point (~500 lines)
├── config.py                       # All configuration constants, .env loading
├── VERSION                         # Single source of truth for app version
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── orchestration/                  # Application lifecycle (Phase 2.1)
│   ├── __init__.py
│   ├── state.py                    # Central registry: singletons, locks, events
│   ├── shutdown.py                 # Graceful shutdown with 15s watchdog timer
│   ├── mode_handler.py             # Mode change callbacks, capture engine lifecycle
│   ├── discovery_manager.py        # Device discovery loop, ARP/ping scanning
│   └── background_tasks.py         # Cleanup, anomaly detector, health monitor, watchdog
│
├── packet_capture/                 # Network packet capture & processing
│   ├── __init__.py
│   ├── capture_engine.py           # Core Scapy capture loop
│   ├── capture_base.py             # Base capture abstractions
│   ├── packet_processor.py         # Packet normalization pipeline
│   ├── parser.py                   # Raw packet field extraction
│   ├── protocols.py                # Port-to-protocol name mapping
│   ├── bandwidth_calculator.py     # Real-time bandwidth computation
│   ├── database_writer.py          # Async DB writer thread with queue overflow monitoring
│   ├── filter_manager.py           # BPF filter management
│   ├── hostname_resolver.py        # Background DNS + mDNS resolution
│   ├── network_discovery.py        # ARP scan, ping sweep, ARP cache reader
│   ├── interface_manager.py        # Background mode monitor with adaptive backoff
│   ├── mode_detector.py            # OS-level network mode detection
│   ├── platform_helpers.py         # Platform-specific (Win/Linux/macOS) helpers
│   ├── geoip.py                    # GeoIP lookups for external IPs
│   ├── modes/                      # Per-mode configuration classes
│   │   ├── base_mode.py            # BaseMode ABC, InterfaceInfo, ModeName enum
│   │   ├── hotspot_mode.py         # WiFi hotspot (full visibility)
│   │   ├── public_network_mode.py  # WiFi client / untrusted network
│   │   ├── ethernet_mode.py        # Wired Ethernet
│   │   └── port_mirror_mode.py     # SPAN / port mirror
│   └── strategies/                 # Per-mode capture strategies
│       ├── ethernet_strategy.py
│       └── mirror_strategy.py
│
├── database/                       # SQLite storage layer
│   ├── __init__.py
│   ├── schema.sql                  # Full DDL: 8 tables, indexes, rollups
│   ├── init_db.py                  # Database creation and migration runner
│   ├── connection.py               # Thread-safe connection pool (WAL, SELECT 1 validation)
│   ├── db_handler.py               # Legacy compatibility shim
│   ├── models.py                   # Data model definitions
│   ├── rollup.py                   # Hourly traffic aggregation
│   ├── migrate_add_direction.py    # One-off migration helper
│   ├── queries/                    # Query modules (Phase 2.2 decomposition)
│   │   ├── __init__.py
│   │   ├── device_queries.py       # Device CRUD, counting, active device logic (~1088 lines)
│   │   ├── network_filters.py      # Subnet detection, IP/MAC validation, SQL fragments (~862 lines)
│   │   ├── packet_store.py         # save_packets_batch, traffic writes, daily usage (~683 lines)
│   │   ├── stats_queries.py        # Dashboard stats, bandwidth history, protocol distribution
│   │   ├── traffic_queries.py      # Traffic search, filtering, export queries
│   │   ├── alert_queries.py        # Alert CRUD, resolution, acknowledgment
│   │   └── maintenance.py          # Retention, VACUUM, WAL checkpoint, adaptive cleanup
│   └── migrations/                 # Schema migration scripts
│       ├── 001_add_wal_mode.sql
│       ├── 002_cleanup_wrong_subnet.py
│       ├── 003_add_composite_indexes.sql
│       ├── 004_optimize_indexes.sql
│       ├── 005_fix_slow_queries.sql
│       ├── 006_drop_redundant_indexes.sql
│       ├── 007_extend_alert_type_check.py
│       ├── 008_mac_primary_key.py
│       └── cleanup_invalid_devices.py
│
├── alerts/                         # Anomaly detection & alerting
│   ├── __init__.py
│   ├── alert_engine.py             # AlertEngine: shared singleton, severity, routing
│   ├── anomaly_detector.py         # Isolation Forest ML anomaly detection
│   └── deduplication.py            # Alert deduplication logic
│
├── backend/                        # REST API (Flask)
│   ├── __init__.py
│   ├── app.py                      # Flask application factory, CORS, SSE
│   ├── helpers.py                  # Shared API helper functions
│   ├── middleware.py               # Request/response middleware
│   └── blueprints/                 # Modular API endpoint groups
│       ├── __init__.py
│       ├── bandwidth_bp.py         # /api/bandwidth/* endpoints
│       ├── devices_bp.py           # /api/devices/* endpoints
│       ├── alerts_bp.py            # /api/alerts/* endpoints
│       ├── system_bp.py            # /api/system/* endpoints (health, status)
│       ├── discovery_bp.py         # /api/discovery/* endpoints
│       ├── export_bp.py            # /api/export/* endpoints
│       └── interface_bp.py         # /api/interface/* endpoints
│
├── frontend/                       # Web dashboard (vanilla JS SPA)
│   ├── index.html                  # Single-page application shell
│   ├── css/
│   │   ├── variables.css           # CSS custom properties (theming)
│   │   ├── reset.css               # CSS reset / normalize
│   │   ├── layout.css              # Page layout, grid
│   │   ├── components.css          # UI component styles
│   │   └── animations.css          # Transitions and keyframes
│   ├── js/
│   │   ├── app.js                  # Main application, SSE, routing
│   │   ├── api.js                  # API client (fetch wrappers)
│   │   ├── store.js                # Reactive state management
│   │   ├── router.js               # Client-side routing
│   │   ├── theme-init.js           # Dark/light theme initialization
│   │   ├── utils/                  # Shared JS utilities
│   │   └── components/             # UI components
│   │       ├── Dashboard.js        # Main dashboard view
│   │       ├── DeviceList.js       # Device table/grid
│   │       ├── DeviceDetail.js     # Single device detail view
│   │       ├── BandwidthChart.js   # Bandwidth time-series chart
│   │       ├── ProtocolChart.js    # Protocol distribution chart
│   │       ├── AlertFeed.js        # Live alert feed
│   │       ├── AlertRules.js       # User-defined alert rule management
│   │       ├── Sidebar.js          # Navigation sidebar
│   │       └── StatsCard.js        # Summary statistic cards
│   └── assets/                     # Static assets (icons, images)
│
├── utils/                          # Shared utilities
│   ├── __init__.py
│   ├── logger.py                   # Structured logging (JSON file + console)
│   ├── metrics.py                  # Metrics collector
│   ├── performance_logger.py       # Performance timing utilities
│   ├── query_cache.py              # TTL cache and query timing decorator
│   ├── network_utils.py            # IP/MAC validation, private IP checks
│   ├── realtime_state.py           # In-memory dashboard state (LRU eviction)
│   ├── health_monitor.py           # System health: CPU, memory, disk, pool stats
│   ├── error_handling.py           # Global error handling
│   ├── exceptions.py               # Custom exception classes
│   ├── formatters.py               # Data formatting helpers
│   └── resilience.py               # Retry logic, circuit breaker patterns
│
├── models/                         # ML model artifacts
│   ├── anomaly_model.joblib        # Trained Isolation Forest model
│   └── anomaly_scaler.joblib       # Feature scaler for anomaly detection
│
├── tests/                          # Test suite
│   ├── conftest.py                 # Shared fixtures
│   ├── test_mode_detection.py
│   ├── test_mode_change_restart.py
│   ├── test_mode_switch_integration.py
│   ├── test_phase_d_verification.py
│   ├── test_realtime_state.py
│   └── test_self_ip_exclusion.py
│
├── docs/                           # Documentation
│   ├── ARCHITECTURE.md             # This file
│   ├── API_REFERENCE.md
│   ├── SETUP_GUIDE.md
│   └── PORT_MIRROR_SETUP.md
│
├── deploy/                         # Deployment configuration
├── logs/                           # Runtime log directory
└── venv/                           # Python virtual environment
```

---

## System Diagram

```
+-----------------------------------------------------------------------------+
|                              NETWATCH SYSTEM                                |
+-----------------------------------------------------------------------------+
|                                                                             |
|  +-------------------+                                                      |
|  |  NETWORK          |                                                      |
|  |  INTERFACE        |                                                      |
|  |  (eth0/wlan0)     |                                                      |
|  +--------+----------+                                                      |
|           | Raw Packets                                                     |
|           v                                                                 |
|  +----------------------------------------------+                          |
|  |         PACKET CAPTURE MODULE                 | <-- Capture Thread       |
|  |  +----------+  +-----------+  +------------+  |                          |
|  |  | Scapy    |->| processor |->| bandwidth  |  |                          |
|  |  | engine   |  |           |  | calculator |  |                          |
|  |  +----------+  +-----------+  +------------+  |                          |
|  +---------------------+------------------------+                          |
|                        | Packet Batch Queue                                 |
|                        v                                                    |
|  +----------------------------------------------+                          |
|  |         DATABASE WRITER THREAD                |                          |
|  |  Async bulk INSERT via save_packets_batch()   |                          |
|  |  Updates realtime_state in-memory snapshot     |                          |
|  +---------------------+------------------------+                          |
|                        |                                                    |
|                        v                                                    |
|  +----------------------------------------------+                          |
|  |         DATABASE MODULE (SQLite + WAL)        |                          |
|  |  +------------------------------------------+ |                          |
|  |  |       Connection Pool (connection.py)     | |                          |
|  |  |  - SELECT 1 validation on borrow          | |                          |
|  |  |  - pool_stats() for health monitoring     | |                          |
|  |  +------------------------------------------+ |                          |
|  |  +------------------------------------------+ |                          |
|  |  |       Query Modules (queries/)            | |                          |
|  |  |  device_queries  | network_filters        | |                          |
|  |  |  packet_store    | stats_queries          | |                          |
|  |  |  traffic_queries | alert_queries          | |                          |
|  |  |  maintenance                              | |                          |
|  |  +------------------------------------------+ |                          |
|  |  +------------------------------------------+ |                          |
|  |  |       netwatch.db                         | |                          |
|  |  |  devices | traffic_summary | alerts       | |                          |
|  |  |  bandwidth_stats | protocol_stats         | |                          |
|  |  |  daily_usage | traffic_rollup             | |                          |
|  |  |  alert_rules | system_config              | |                          |
|  |  +------------------------------------------+ |                          |
|  +---------------------+------------------------+                          |
|                        |                                                    |
|        +---------------+--------------+                                     |
|        |                              |                                     |
|        v                              v                                     |
|  +---------------------+   +---------------------+                         |
|  |   ALERTS MODULE     |   |   BACKEND MODULE    |                         |
|  |   <-- Detector Thd  |   |   <-- Main Thread   |                         |
|  |                     |   |                     |                         |
|  |  +--------------+   |   |  +--------------+   |                         |
|  |  | anomaly      |   |   |  | Flask /      |   |                         |
|  |  | detector     |   |   |  | Waitress     |   |                         |
|  |  | (Isolation   |   |   |  | Port 5000    |   |                         |
|  |  |  Forest ML)  |   |   |  +--------------+   |                         |
|  |  +--------------+   |   |       |             |                         |
|  |       |              |   |       | REST API   |                         |
|  |       v              |   |       v             |                         |
|  |  +--------------+   |   |  +--------------+   |                         |
|  |  | alert_engine |---+---+->| blueprints/  |   |                         |
|  |  +--------------+   |   |  +--------------+   |                         |
|  +---------------------+   +--------+-----------+                         |
|                                      | JSON + SSE                          |
|                                      v                                     |
|  +------------------------------------------------------------------+     |
|  |                    FRONTEND MODULE                                |     |
|  |  +------------------------------------------------------------+  |     |
|  |  |                     Browser (SPA)                          |  |     |
|  |  |  +----------+  +----------+  +----------+  +----------+   |  |     |
|  |  |  |Dashboard |  |DeviceList|  |AlertFeed |  |Bandwidth |   |  |     |
|  |  |  +----------+  +----------+  +----------+  |Chart     |   |  |     |
|  |  |                                             +----------+   |  |     |
|  |  |  JavaScript: api.js, store.js, router.js, app.js          |  |     |
|  |  |  - SSE push for real-time updates                          |  |     |
|  |  |  - Chart.js for visualizations                             |  |     |
|  |  +------------------------------------------------------------+  |     |
|  +------------------------------------------------------------------+     |
|                                                                             |
|  +------------------------------------------------------------------+     |
|  |              ORCHESTRATION MODULE (orchestration/)                 |     |
|  |  state.py         -- singletons, locks, shutdown_event           |     |
|  |  shutdown.py      -- graceful teardown + 15s watchdog            |     |
|  |  mode_handler.py  -- capture engine lifecycle, mode callbacks    |     |
|  |  discovery_manager.py -- ARP/ping device scanning loop           |     |
|  |  background_tasks.py  -- cleanup, health, anomaly, watchdog      |     |
|  +------------------------------------------------------------------+     |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## Components

### 1. Orchestration Module (`orchestration/`)

**Purpose:** Application lifecycle management. Decomposed from a monolithic `main.py` (formerly ~1832 lines, now ~500 lines) into focused modules.

| File | Responsibility |
|------|---------------|
| `state.py` | Central registry for runtime singletons (`shutdown_event`, `interface_manager`, `capture_engine`, `detector`, `health_monitor`), synchronization primitives (`engine_lock`, `mode_transition_lock`), and background thread references |
| `shutdown.py` | Graceful shutdown sequence protected by a lock so only the first caller runs teardown; 15-second watchdog forces `os._exit(1)` if any step hangs |
| `mode_handler.py` | Mode change callbacks from `InterfaceManager`, creates/restarts `CaptureEngine` for new modes, resets caches and subnet filters, sends SSE events for frontend mode transitions, `start_packet_capture()` entry point |
| `discovery_manager.py` | Periodic device discovery loop using ARP scans, ARP cache reads, and ping sweeps; `_upsert_devices()` inserts discovered devices; shared helpers `get_all_local_ips()`, `get_all_local_macs()`, `resolve_scapy_iface()` |
| `background_tasks.py` | Starts and manages background daemon threads: anomaly detector, health monitor, periodic cleanup scheduler, and thread watchdog that restarts dead threads |

**Input:** Configuration, runtime events, mode changes
**Output:** Coordinated startup/shutdown of all subsystems

### 2. Packet Capture Module (`packet_capture/`)

**Purpose:** Capture, parse, and process network packets from the active interface.

| File | Responsibility |
|------|---------------|
| `capture_engine.py` | Core Scapy sniff loop, manages capture thread lifecycle |
| `capture_base.py` | Base capture abstractions |
| `packet_processor.py` | Normalizes raw packets into structured dictionaries |
| `parser.py` | Extracts fields from raw packets (IPs, ports, MACs, size) |
| `protocols.py` | Maps port numbers to protocol names (HTTP, DNS, etc.) |
| `bandwidth_calculator.py` | Real-time per-device and aggregate bandwidth computation |
| `database_writer.py` | Async writer thread: drains a packet-batch queue and bulk-INSERTs to SQLite; includes write queue overflow monitoring that drops batches when the queue is full |
| `filter_manager.py` | BPF filter management for mode-specific packet filtering |
| `hostname_resolver.py` | Background DNS resolution and mDNS browser for device naming |
| `network_discovery.py` | ARP scan, ping sweep, and ARP cache reader implementations |
| `interface_manager.py` | Background daemon that polls `ModeDetector` and fires callbacks on mode change; implements progressive detection interval backoff (15s -> 30s -> 60s -> 120s), mode transition cooldown (60s between transitions), and interface loss notification that bypasses cooldown |
| `mode_detector.py` | Stateless OS-level detection: inspects interfaces, hotspot state, Wi-Fi SSID, ARP tables to determine the current `BaseMode` |
| `platform_helpers.py` | Platform-specific subprocess wrappers (Windows/Linux/macOS) |
| `geoip.py` | GeoIP lookups for external IP addresses |
| `modes/` | Per-mode configuration classes: `BaseMode` ABC, `HotspotMode`, `PublicNetworkMode`, `EthernetMode`, `PortMirrorMode` |
| `strategies/` | Per-mode capture strategies: `EthernetCaptureStrategy`, `MirrorCaptureStrategy` |

**Input:** Raw network packets from interface
**Output:** Normalized packet dictionaries enqueued to `DatabaseWriter`

### 3. Database Module (`database/`)

**Purpose:** Store and retrieve all data using SQLite with WAL mode.

| File | Responsibility |
|------|---------------|
| `schema.sql` | Table definitions (8 tables: `devices`, `traffic_summary`, `alerts`, `bandwidth_stats`, `protocol_stats`, `daily_usage`, `traffic_rollup`, `alert_rules`, `system_config`), indexes, and rollup structures |
| `init_db.py` | Creates database file, applies schema, runs migrations |
| `connection.py` | Thread-safe connection pool with WAL mode; validates connections with `SELECT 1` on borrow; exposes `pool_stats()` for health monitoring; provides `wal_checkpoint()` for WAL management |
| `db_handler.py` | Legacy compatibility shim |
| `models.py` | Data model definitions |
| `rollup.py` | Hourly traffic aggregation from `traffic_summary` into `traffic_rollup` |
| `migrations/` | Numbered migration scripts (001-008) for schema evolution |

**Query Sub-modules (`database/queries/`)** -- decomposed from a monolithic `device_queries.py` (formerly ~2583 lines):

| File | Responsibility |
|------|---------------|
| `device_queries.py` (~1088 lines) | Device CRUD operations, `get_active_device_count()` (single source of truth for device counting), MAC-primary device identification, re-exports public symbols from `network_filters` and `packet_store` for backward compatibility |
| `network_filters.py` (~862 lines) | Subnet detection (`_detect_subnet`, `_detect_our_ip`), IP/MAC validation (`is_valid_device_ip`, `is_valid_mac`), mode-aware device filtering, reusable SQL WHERE clause fragments, multicast/broadcast filtering |
| `packet_store.py` (~683 lines) | `save_packet()` for single writes, `save_packets_batch()` for optimized bulk inserts with pre-aggregation, device upserts, daily usage tracking |
| `stats_queries.py` | Dashboard statistics, bandwidth history, protocol distribution, TTL-cached queries |
| `traffic_queries.py` | Traffic search, filtering, pagination, export queries |
| `alert_queries.py` | Alert CRUD, resolution, acknowledgment |
| `maintenance.py` | Data retention (default: 7 days raw, 90 days rollups), adaptive retention that halves retention when DB exceeds `MAX_DATABASE_SIZE_GB`, VACUUM after large deletions, WAL checkpoint wired into cleanup cycle, disk space reporting |

**Input:** Packet dictionaries, alert data, API queries
**Output:** Query results as Python lists/dicts

### 4. Alerts Module (`alerts/`)

**Purpose:** Detect anomalies and manage alerts.

| File | Responsibility |
|------|---------------|
| `alert_engine.py` | Shared `AlertEngine` singleton: alert creation, severity routing, known IP/MAC registration to suppress false positives |
| `anomaly_detector.py` | ML-based anomaly detection using Isolation Forest; runs periodically in a background thread |
| `deduplication.py` | Alert deduplication to prevent duplicate alerts for the same condition |

**Input:** Bandwidth/traffic data from database
**Output:** Alert records saved to database

### 5. Backend Module (`backend/`)

**Purpose:** REST API and SSE push for frontend data access.

| File | Responsibility |
|------|---------------|
| `app.py` | Flask application factory, CORS setup, SSE endpoint registration |
| `helpers.py` | Shared API helper functions |
| `middleware.py` | Request/response middleware |
| `blueprints/` | Modular API endpoint definitions: `bandwidth_bp`, `devices_bp`, `alerts_bp`, `system_bp`, `discovery_bp`, `export_bp`, `interface_bp` |

**Input:** HTTP requests from frontend
**Output:** JSON responses, SSE event streams

### 6. Frontend Module (`frontend/`)

**Purpose:** Single-page web dashboard for visualization.

| File | Responsibility |
|------|---------------|
| `index.html` | SPA shell |
| `css/` | Modular CSS: variables (theming), reset, layout, components, animations |
| `js/app.js` | Main application entry, SSE connection, routing |
| `js/api.js` | API client with fetch wrappers |
| `js/store.js` | Reactive state management |
| `js/router.js` | Client-side hash routing |
| `js/components/` | Dashboard, DeviceList, DeviceDetail, BandwidthChart, ProtocolChart, AlertFeed, AlertRules, Sidebar, StatsCard |

**Input:** JSON data from API, SSE events
**Output:** Visual dashboard in browser

### 7. Utilities Module (`utils/`)

**Purpose:** Shared cross-cutting concerns.

| File | Responsibility |
|------|---------------|
| `realtime_state.py` | In-memory dashboard state snapshot updated by `DatabaseWriter`; SSE hot path does zero DB queries; LRU eviction prunes stale devices when `MAX_DEVICES` is reached |
| `health_monitor.py` | System health monitoring: CPU, memory, database size/growth, disk space with auto-response (triggers emergency cleanup when disk is critically low), connection pool utilization, thread health |
| `query_cache.py` | TTL-based query result cache and `@time_query` decorator |
| `network_utils.py` | IP/MAC validation, private IP detection |
| `logger.py` | Structured logging (JSON file output, console, error file) |
| `metrics.py` | Metrics collector for internal performance tracking |
| `performance_logger.py` | Performance timing utilities |
| `error_handling.py` | Global error handling |
| `exceptions.py` | Custom exception classes |
| `formatters.py` | Data formatting helpers |
| `resilience.py` | Retry logic, circuit breaker patterns |

---

## Data Flow

### Packet Capture Flow

```
1. Network Interface captures raw packet
2. Scapy sniff() in CaptureEngine receives packet
3. packet_processor.py normalizes: src/dst IP, ports, MACs, size, protocol, direction
4. bandwidth_calculator.py updates real-time bandwidth counters
5. Normalized batch enqueued to DatabaseWriter queue
6. DatabaseWriter thread drains queue:
   a. packet_store.save_packets_batch() bulk-INSERTs to traffic_summary
   b. Device upserts into devices table (private IPs only)
   c. daily_usage table updated
   d. realtime_state.dashboard_state.update_from_batch() refreshes in-memory snapshot
```

### Dashboard Refresh Flow

```
1. SSE connection pushes real-time state from in-memory snapshot (zero DB queries)
2. Fallback: JavaScript polls GET /api/stats/realtime every 3 seconds
3. Flask blueprint handler serves from realtime_state or database
4. JSON response returned to frontend
5. store.js updates reactive state; components re-render
```

### Anomaly Detection Flow

```
1. Detector thread wakes up periodically (background_tasks.py)
2. Queries bandwidth history from database
3. Isolation Forest model predicts anomalies
4. If anomaly detected, AlertEngine.create_alert()
5. Alert stored in database via alert_queries
6. SSE pushes new alert to frontend; AlertFeed component displays it
```

### Device Discovery Flow

```
1. discovery_manager.py loop runs periodically (interval depends on mode)
2. Performs ARP scan (hotspot/ethernet) or ARP cache read (public network)
3. Optional ping sweep for additional discovery
4. _upsert_devices() inserts/updates devices in database
5. Discovered devices enqueued for background hostname resolution
6. Self-IPs (all local adapters) excluded to prevent false device entries
```

### Mode Detection Flow

```
1. InterfaceManager background thread polls ModeDetector.detect()
2. Progressive interval backoff: 15s (startup) -> 30s -> 60s -> 120s (stable)
3. Stability threshold: same mode must be detected 2 consecutive times before switching
4. Mode transition cooldown: 60s minimum between transitions
5. Interface loss notification bypasses both cooldown and stability threshold
6. On mode change: callbacks fire -> CaptureEngine restarts with new BPF filter
   and promiscuous mode setting -> subnet/gateway reconfigured -> SSE event sent
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Packet Capture | Scapy 2.5 + Npcap | Raw packet sniffing |
| Web Framework | Flask 3.0 / Waitress | REST API (dev / production) |
| Database | SQLite 3 (WAL mode) | Local data storage with connection pooling |
| ML | scikit-learn (Isolation Forest) | Anomaly detection |
| Frontend | HTML5 / CSS3 / Vanilla JS | Single-page application |
| Charts | Chart.js | Data visualization |
| Hostname Resolver | dnspython, zeroconf | DNS and mDNS resolution |
| System Info | psutil | CPU, memory, disk, NIC enumeration |

---

## Threading Model

NetWatch uses multiple daemon threads coordinated through `orchestration/state.py`:

| Thread | Component | Purpose |
|--------|-----------|---------|
| Main Thread | Flask / Waitress Server | Handles HTTP requests and SSE streams |
| Capture Thread | `CaptureEngine` | Runs Scapy sniff loop on the active interface |
| Processor Thread | `PacketProcessor` | Normalizes packets, feeds bandwidth calculator |
| DB Writer Thread | `DatabaseWriter` | Drains batch queue, bulk-INSERTs to SQLite |
| Anomaly Detector | `AnomalyDetector` | Periodic ML analysis of bandwidth patterns |
| Health Monitor | `HealthMonitor` | Periodic system health checks (CPU, disk, pool) |
| Interface Monitor | `InterfaceManager` | Polls mode detector, fires mode change callbacks |
| Discovery Thread | `discovery_manager` | Periodic ARP/ping device scanning |
| Cleanup Thread | `background_tasks` | Daily data retention, VACUUM, WAL checkpoint |
| Thread Watchdog | `background_tasks` | Monitors other threads, restarts dead ones |
| Hostname Resolver | `hostname_resolver` | Background DNS/mDNS resolution queue |
| CPU Sampler | `health_monitor` | Samples `psutil.cpu_percent()` every 2 seconds |

```python
# Simplified thread architecture (see main.py for full implementation)
def main():
    # Orchestration modules coordinate all thread startup:

    # 1. Packet capture (creates capture + processor + DB writer threads)
    start_packet_capture()

    # 2. Background services (each starts its own daemon thread)
    start_anomaly_detector(alert_engine)
    start_health_monitor(alert_engine)
    start_thread_watchdog()
    start_cleanup_task()
    start_discovery_task()

    # 3. Main thread: Flask / Waitress server
    if IS_PRODUCTION:
        waitress_serve(app, host=host, port=port)
    else:
        app.run(host=host, port=port)
```

**Synchronization primitives** (defined in `orchestration/state.py`):
- `shutdown_event` (threading.Event) -- checked by all background threads for clean exit
- `engine_lock` (threading.Lock) -- protects `capture_engine` mutations during mode transitions
- `mode_transition_lock` (threading.Lock) -- held during mode transitions; `DatabaseWriter` skips writes while held
- `cached_discovery_lock` (threading.Lock) -- protects the shared `NetworkDiscovery` instance

**Shutdown sequence** (`orchestration/shutdown.py`):
1. `shutdown_event` is set (signals all threads to exit)
2. Capture engine stopped
3. Interface manager stopped
4. Health monitor stopped
5. Connection pool drained
6. 15-second watchdog forces `os._exit(1)` if any step hangs

---

## Database Schema

The database uses SQLite in WAL (Write-Ahead Logging) mode for concurrent read/write access. MAC address is the primary device identifier.

```sql
-- 1. DEVICES: Network devices keyed by MAC address
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL UNIQUE,
    ip_address TEXT, ipv4_address TEXT, ipv6_address TEXT,
    hostname TEXT, device_name TEXT, vendor TEXT,
    first_seen TIMESTAMP, last_seen TIMESTAMP,
    total_bytes_sent INTEGER, total_bytes_received INTEGER, total_packets INTEGER,
    is_local INTEGER, device_type TEXT, notes TEXT,
    detected_mode TEXT, active_mode TEXT
);

-- 2. TRAFFIC_SUMMARY: Individual packet/connection records
CREATE TABLE traffic_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP, source_ip TEXT, dest_ip TEXT,
    source_mac TEXT, dest_mac TEXT,
    source_port INTEGER, dest_port INTEGER,
    protocol TEXT, raw_protocol TEXT,
    bytes_transferred INTEGER, packets_count INTEGER,
    direction TEXT, session_id TEXT, device_name TEXT, vendor TEXT
);

-- 3. ALERTS: System alerts with severity and resolution tracking
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP, alert_type TEXT, severity TEXT,
    message TEXT, details TEXT, source_ip TEXT, dest_ip TEXT,
    resolved INTEGER, resolved_at TIMESTAMP,
    acknowledged INTEGER, acknowledged_at TIMESTAMP
);

-- 4. BANDWIDTH_STATS: Per-minute aggregated bandwidth
-- 5. PROTOCOL_STATS: Per-protocol aggregated stats
-- 6. DAILY_USAGE: Per-device daily usage (keyed by date + MAC)
-- 7. TRAFFIC_ROLLUP: Hourly aggregation for long-term queries
-- 8. ALERT_RULES: User-defined custom alert rules
-- 9. SYSTEM_CONFIG: Key-value system metadata
```

**Index strategy:** Composite covering indexes on `traffic_summary` (8 indexes) cover all common query patterns. Single-column indexes were dropped (migration 006) as they were strict prefixes of composite ones, reducing write amplification. A covering index on `devices` supports `get_active_device_count()` without touching the main table.

---

## Monitoring Modes & Network Topology

### Understanding Traffic Visibility

NetWatch's ability to capture traffic depends on **network topology** and **connection type**. This section explains why you might not see all devices and how to configure for full visibility.

### Automatic Mode Detection

NetWatch automatically detects your connection type using `ModeDetector` (called by `InterfaceManager`):

```python
from packet_capture.interface_manager import InterfaceManager

mgr = InterfaceManager()
mgr.start_monitoring()
mode = mgr.get_current_mode()
print(f"Mode: {mode.get_mode_name()}")
print(f"Interface: {mode.interface.name}")
print(f"BPF Filter: {mode.get_bpf_filter()}")
```

### Mode Detection Improvements (Phase 4)

The `InterfaceManager` implements several reliability features:

- **Progressive detection interval backoff:** Starts at 15 seconds for fast initial convergence, then backs off to 30s, 60s, and 120s as the mode remains stable. Reduces unnecessary subprocess calls (ipconfig, netsh, etc.) during steady-state operation.
- **Stability threshold:** A new mode must be detected in 2 consecutive polls before a transition fires. Prevents rapid flip-flopping from transient network glitches.
- **Mode transition cooldown:** 60-second minimum gap between allowed transitions. Prevents cascading restarts when the network is briefly unstable.
- **Interface loss bypass:** When the capture engine reports that its interface has disappeared, `notify_interface_lost()` bypasses both the stability threshold and the cooldown timer, forcing an immediate re-detection so the system can switch to a working interface without delay.

### Monitoring Modes

| Mode | Connection Type | Visibility | Use Case |
|------|----------------|------------|----------|
| `ETHERNET` | Wired connection | Own + broadcasts + ARP discovery | Office networks |
| `PUBLIC_NETWORK` | Connected TO WiFi / Untrusted WiFi | Own traffic + passive ARP cache | Personal monitoring, Coffee shops, airports |
| `HOTSPOT` | Laptop IS hotspot | All connected devices | Full network monitoring |
| `PORT_MIRROR` | SPAN port | Full network segment | Enterprise monitoring |
| `DISCONNECTED` | No network | Capture paused | Dashboard-only |

### Mode 1: Public Network Mode (WiFi Client) -- Own Traffic + Passive Discovery

**When It Happens:**
```
You -> WiFi Router -> Internet
```

**What You See:**
- Your laptop's traffic (outgoing/incoming)
- Nearby devices via passive ARP cache reads (no packets sent)
- NOT other clients' unicast traffic (phones, tablets, etc.)

**Why Limited:**
WiFi Access Points implement **client isolation** for security. Each client can only see:
1. Packets sent TO the AP
2. Packets received FROM the AP
3. Broadcast/multicast packets

NetWatch does **not** send active ARP scans in this mode. It reads the OS's existing ARP cache to list neighbors passively.

**Network Diagram:**
```
Phone           Tablet          Laptop (NetWatch)
  |               |                  |
  +---------------+------------------+
                  |
           [WiFi Router/AP]
                  |
              Internet

Phone <-> Router <-> Internet:  [not visible] Laptop cannot see
Tablet <-> Router <-> Internet: [not visible] Laptop cannot see
Laptop <-> Router <-> Internet: [visible]     Laptop can see
```

---

### Mode 2: WiFi Hotspot Mode -- Full Visibility

**When It Happens:**
```
Other Devices -> Your Laptop (Hotspot) -> Internet
```

**What You See:**
- ALL traffic from connected devices
- Complete packet visibility
- Real-time per-device bandwidth

**How to Enable:**

**Windows:**
1. Settings -> Network & Internet -> Mobile Hotspot
2. Share: WiFi or Ethernet connection
3. Turn on Mobile Hotspot
4. Other devices connect to your laptop

**macOS:**
1. System Preferences -> Sharing
2. Internet Sharing: Check box
3. Share connection from: Ethernet/WiFi
4. To computers using: WiFi
5. WiFi Options: Set name and password

**Linux:**
```bash
# Using NetworkManager
nmcli con add type wifi ifname wlan0 con-name Hotspot ssid NetWatch
nmcli con modify Hotspot wifi-sec.key-mgmt wpa-psk
nmcli con modify Hotspot wifi-sec.psk "yourpassword"
nmcli con up Hotspot
```

**Network Diagram:**
```
Phone           Tablet          Smart TV
  |               |                |
  +---------------+----------------+
                  |
      [Laptop (NetWatch Hotspot)]
                  |
            [Router/Internet]

Phone <-> Laptop <-> Internet:    [visible] Laptop sees everything
Tablet <-> Laptop <-> Internet:   [visible] Laptop sees everything
Smart TV <-> Laptop <-> Internet: [visible] Laptop sees everything
```

**Technical Details:**
- Laptop acts as Layer 2 bridge
- All packets pass through laptop's interface
- NetWatch captures before forwarding
- Enables full packet inspection

---

### Mode 3: Ethernet -- Switch-Dependent

**When It Happens:**
```
You -> Switch -> Router -> Internet
```

**What You See:**
- Your laptop's traffic
- Broadcast/multicast traffic
- Other devices (depends on switch configuration)

**Modern Switches:**
Modern managed switches use **port isolation**:
- Each port is a separate collision domain
- Unicast traffic only goes to destination port
- You only see: your traffic + broadcasts

**Network Diagram (Switch with Port Isolation):**
```
Port 1: Desktop    Port 2: Laptop (NetWatch)    Port 3: Server
    |                      |                         |
    +----------------------+-------------------------+
                           |
                      [Managed Switch]
                           |
                       [Router]

Desktop <-> Server:    [not visible] Laptop cannot see (unicast)
Desktop <-> Router:    [not visible] Laptop cannot see
Laptop <-> Anywhere:   [visible]     Laptop can see
Broadcast (DHCP):      [visible]     All ports see
```

**Solution: Port Mirroring (SPAN)**

Configure switch to mirror traffic:

**Cisco:**
```
monitor session 1 source interface Gi1/0/1 - 10
monitor session 1 destination interface Gi1/0/24
# Now port 24 sees all traffic from ports 1-10
```

**HP/Aruba:**
```
mirror-port 24
interface 1-10
  monitor-port 24
```

**Network Diagram (With Port Mirroring):**
```
Port 1-10: All devices          Port 24: Laptop (NetWatch)
        |                                |
        +----[Mirrored]-----------------+
                    |
             [Managed Switch]
                    |
                [Router]

All traffic from ports 1-10:  [visible] Mirrored to port 24
Laptop sees everything:       [visible] Full visibility
```

---

### Mode 4: Mobile Hotspot (Phone as AP) -- Limited

**When It Happens:**
```
Your Laptop -> Phone's Hotspot -> Cell Tower -> Internet
```

**What You See:**
- Laptop's internet traffic
- NOT phone's own traffic (YouTube, apps, etc.)

**Why Phone's Traffic Is Invisible:**

The phone has TWO network paths:

**Path 1: Laptop's Traffic**
```
Laptop -> WiFi -> Phone's Hotspot Interface -> Cell Modem -> Internet
[visible] Passes through phone's WiFi interface
```

**Path 2: Phone's Own Traffic**
```
Phone Apps -> Cell Modem -> Internet
[not visible] Does not pass through WiFi interface
```

**Technical Explanation:**
- Phone's WiFi interface and cellular modem are separate
- Hotspot bridges WiFi to Cellular
- Phone's own apps use cellular modem directly
- Laptop's interface never sees phone's app traffic

**Solution:**
Reverse the setup:
1. Enable hotspot ON LAPTOP
2. Connect phone TO laptop's hotspot
3. Now phone's traffic goes through laptop

---

### Limitations by Mode

| Limitation | Public Network | Hotspot | Ethernet | Port Mirror |
|------------|---------------|---------|----------|-------------|
| See other devices (passive) | ARP cache | Full | ARP scan | Full |
| Active ARP scanning | No | Yes | Yes | Yes |
| Full bandwidth visibility | No | Yes | Partial | Yes |
| Monitor phone's traffic | No | Yes | N/A | Yes |
| Production ready | Yes (self) | Yes (all) | Yes | Yes |

---

### Recommended Setups

| Goal | Recommended Mode | Setup |
|------|------------------|-------|
| Monitor own laptop | Public Network / Ethernet | Any connection |
| Monitor home devices | WiFi Hotspot | Enable hotspot on laptop |
| Monitor office network | Ethernet + SPAN | Port mirroring |
| Monitor classroom | WiFi Hotspot | Laptop as access point |

---

## Production Hardening

### Phase 3: 24/7 Operation

The following features ensure NetWatch runs reliably for extended periods without manual intervention:

**Adaptive Data Retention** (`database/queries/maintenance.py`):
- Default retention: 7 days for raw traffic, 90 days for rollups
- When the database exceeds `MAX_DATABASE_SIZE_GB`, retention is automatically halved
- WAL checkpoint (`PASSIVE` after each cleanup, `TRUNCATE` after major cleanups) is wired into the cleanup cycle
- VACUUM runs only after large deletions to avoid unnecessary I/O

**Connection Pool Validation** (`database/connection.py`):
- Connections are validated with `SELECT 1` on borrow from the pool
- Invalid connections are discarded and replaced transparently
- `pool_stats()` exposes pool utilization for health monitoring

**Disk Space Monitoring** (`utils/health_monitor.py`):
- Periodic checks of available disk space on the database partition
- Low disk warning alerts raised through `AlertEngine`
- Critical disk triggers emergency cleanup (accelerated retention)

**Stale Device Pruning** (`utils/realtime_state.py`):
- In-memory device list enforces a `MAX_DEVICES` limit via LRU eviction
- Devices not seen recently are pruned first to keep memory bounded

**Write Queue Overflow** (`packet_capture/database_writer.py`):
- `DatabaseWriter` uses a bounded queue; when the queue is full, batches are dropped with a warning
- Prevents unbounded memory growth during sustained high packet rates or slow disk I/O

---

## Security Considerations

1. **Root/Admin Required:** Packet capture requires elevated privileges
2. **Local Only:** No external network access needed
3. **No Authentication:** Designed for trusted local network
4. **CORS Enabled:** For development; restrict in production
5. **Self-IP Exclusion:** All local adapter IPs/MACs are excluded from device discovery to prevent false entries
6. **Known MAC/IP Registration:** `AlertEngine` accepts known MACs and IPs at startup to suppress false security alerts
