# Changelog

All notable changes to NetWatch are documented here.

## [2.1.0] - 2025-07-13

### Production Hardening & Documentation Consolidation

#### Bug Fixes
- **Dashboard query performance**: Added 3-second TTLCache to `get_dashboard_data()` to prevent slow-query escalation as `traffic_summary` grows (avg dropped from 160 ms → <5 ms on cache hit)
- **Duplicate startup migration**: Removed redundant `run_startup_migrations()` call in `main.py` — `initialize_database()` already applies all migrations via `_run_migrations()` and tracks them in `system_config`
- **Duplicate BPF filter log**: `_capture_loop()` no longer re-calls `get_validated_filter()` / `get_promiscuous_setting()` — values are passed from `start()`, eliminating duplicate log lines
- **CSP header**: Added `https://cdn.jsdelivr.net` to Content-Security-Policy `script-src` so Chart.js CDN loads correctly
- **SSE bandwidth merge**: Fixed `app.js` merge logic so `bandwidth_history` from SSE payload is used when `bandwidth_live` is present

#### Production Environment
- `.env` / `.env.example` files for production configuration
- Lightweight `.env` loader in `config.py` (no external dependency) — real environment variables take precedence
- Version bumped to 2.1.0

#### Documentation
- **Removed duplicates**: `docs/API_DOCS.md` (kept `API_REFERENCE.md`), `docs/USER_GUIDE.md` (kept `USER_MANUAL.md`), `docs/PRODUCTION_READINESS.md` (kept `PRODUCTION_DEPLOYMENT.md`), `docs/CONTRIBUTING.md` (kept root `CONTRIBUTING.md`)
- **Removed team guides**: `docs/guides/` folder (member1–5 guides)
- **Fixed outdated references**: `routes.py` → `blueprints/` in ARCHITECTURE.md and CONTRIBUTING.md; Python 3.10 → 3.11 in SETUP_GUIDE.md and TROUBLESHOOTING.md
- **Updated docs/README.md**: Rebuilt documentation index with all remaining docs
- **Updated root README.md**: Corrected test count (469), project structure, and documentation table

## [2.0.0] - 2026-02-06

### Phase 6 — Production Readiness & Final Phase
- Complete test suite with 100+ tests (modes, capture, database, alerts, API, integration, performance)
- Deployment packages for Windows (.exe installer), Linux (.deb), macOS (.app)
- Production documentation (deployment guide, troubleshooting, user guide, API reference)
- Production-aware `config.py` with platform detection and environment flags
- Rewritten `main.py` with logging, CLI args, admin checks, graceful shutdown
- Distribution files: LICENSE, CHANGELOG, .gitignore, CONTRIBUTING

### Phase 5 — Frontend Dashboard
- Single-page application with vanilla JS (no framework dependencies)
- Real-time stats cards: active devices, bandwidth, health score, alert badge
- Bandwidth chart with upload/download split
- Device list with search, sort, and rename
- Protocol distribution pie chart
- Alert feed with acknowledge/resolve actions
- Sidebar navigation with auto-refresh controls
- CSS architecture: variables, reset, layout, components, animations
- Responsive design for desktop and tablet

### Phase 4 — Alert System
- `AlertEngine` with configurable thresholds (bandwidth, device count, anomaly)
- `AlertDeduplicator` with cooldown-based throttle to prevent alert storms
- `AnomalyDetector` using scikit-learn IsolationForest
- Alert lifecycle: create → acknowledge → resolve
- Alert severity levels: info, warning, critical
- Alert summary and statistics queries
- Integration with capture pipeline for real-time alerting

### Phase 3 — Database Layer
- SQLite with WAL mode for concurrent reads
- `ConnectionPool` with configurable size and timeout
- Schema: `devices`, `traffic_log`, `alerts` tables
- Separated query modules: device, traffic, alert, stats queries
- Batch insert support for high-throughput packet storage
- Database initialization and migration framework
- Direction column migration for upload/download tracking

### Phase 2 — Packet Capture Engine
- `CaptureEngine` with Scapy-based packet sniffing
- `PacketProcessor` with batch processing and queue management
- `BandwidthCalculator` with sliding window (configurable)
- `parser.py` for protocol identification (TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP, DHCP)
- Direction detection (inbound/outbound/internal)
- BPF filter generation per mode
- Configurable buffer sizes and batch intervals

### Phase 1 — Mode Detection & Network Discovery
- `ModeDetector` with automatic network mode identification
- Five connection modes:
  - **HotspotMode** — Mobile hotspot (192.168.137.x)
  - **WiFiClientMode** — Standard Wi-Fi client
  - **EthernetMode** — Wired connection
  - **PublicNetworkMode** — Public/campus Wi-Fi
  - **PortMirrorMode** — SPAN port monitoring
- `InterfaceManager` with background detection and mode change callbacks
- `FilterManager` for BPF filter validation
- `NetworkDiscovery` with ARP scanning
- Platform-specific interface enumeration (Windows/Linux/macOS)

## [1.0.0] - Initial Release
- Basic network monitoring prototype
- Single-interface packet capture
- Simple device tracking
- Minimal web dashboard
