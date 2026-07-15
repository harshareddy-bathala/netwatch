# NetWatch — AI-First Migration Roadmap

> Companion to [NETWATCH_AI_FIRST_ROADMAP.md](NETWATCH_AI_FIRST_ROADMAP.md) (product vision +
> feature catalogue). This document is the **execution plan**: phased roadmap, sprint
> mapping, gap analysis, and a live Phase 0 checklist.
>
> Positioning: packet capture and the dashboard are the *sensor* and the *lens*;
> the product becomes the **intelligence layer** between them. Everything stays
> local-first / offline-capable.

---

## Gap Analysis (repo today → AI-ready target)

| Dimension | Target | Repo today | Gap | Strategy |
|---|---|---|---|---|
| Capture | Privileged micro-daemon, flow-native, eBPF-capable | Scapy threads in the monolith; mode detection is excellent | Medium | **Keep the mode system**; extract capture process in Phase 2.5 |
| Telemetry model | Immutable event stream; flows + DNS + names | Row-per-batch `traffic_summary`; no flow records, no DNS capture | Large | Phase 0: normalizer + `flows`/`dns_queries` tables + event bus |
| Storage | DuckDB/Parquet (features) + SQLite (entities) + graph (twin) | SQLite only; 9 indexes on hottest table | Large | Additive — SQLite stays for entities/alerts/config |
| State/coupling | Projections from events | Global singletons + locks + generation counters | Large | Contain, don't rewrite: bus taps existing writer hooks |
| ML | Evaluated detector ensemble, per-device baselines, ONNX | One IsolationForest with a feature-enrichment defect; no eval harness | Large | Fix enrichment bug now; replace detector in Phase 1–2 |
| LLM / agents | Tool-grounded local LLM (triage, investigator, historian, reporter) | None | Total | Net-new `intelligence/` service in Phase 3 |
| API / UI | Same + chat/topology/incident views | Solid REST+SSE, clean SPA | Small | Best-preserved layer — extend only |
| Security | Privilege separation, auto-escaped rendering, fail-closed auth | Root monolith, manual escaping, auth fails open silently | Medium | Cheap wins in Phase 0; privilege separation Phase 2.5 |
| Ops / testing | Replayable event log; model evaluation gates | ~640 tests, CI, installers | Small | Add pcap-replay fixtures as the bridge |

---

## Phases

### Phase 0 — Stabilize the substrate (Sprints 1–2, weeks 1–4)  ← **current**

Goal: trustworthy telemetry + an event stream every AI feature can subscribe to.

- [x] **P0.1** Repo hygiene: dead `package-lock.json` removed; root `logs.txt`/`test_output.txt` gitignored (`.env` was already covered)
- [x] **P0.2** `config.py` duplicate/shadowed constants removed (`DB_BUSY_TIMEOUT` ×2, `HEALTH_SCORE_WARNING` ×2, `PACKET_QUEUE_MAX_SIZE`, `TRAFFIC_STATS_AGGREGATION_INTERVAL`)
- [x] **P0.3** Auth fail-open fixed: explicit `NETWATCH_AUTH_ENABLED=true` without a key now **fails closed** (503); production-implied auth without a key warns loudly at startup
- [x] **P0.4** Anomaly-detector feature enrichment fixed — per-minute-bucket features (single `GROUP BY` query) instead of one aggregate copied to every training row; regression tests in `tests/test_anomaly_detector.py::TestEnrichmentPerBucket`
- [x] **P0.5** In-process **event bus** (`intelligence/event_bus.py`): bounded, drop-oldest, never blocks the capture path; publishers wired in `DatabaseWriter` (`packet.batch`) and mode transitions (`mode.changed`); `device.seen` reserved for Phase 1
- [x] **P0.6** **Flow telemetry**: migration 010 adds `flows` + `dns_queries`; `intelligence/flow_normalizer.py` consumes `packet.batch` events into flow records (idle/max-age flush, self-contained 72h retention); DNS query names captured in `PacketData.extra` and persisted; `flow.completed` / `dns.query` published on the bus
- [x] **P0.7** Chart.js 4.4.0 vendored at `frontend/vendor/` (SRI-verified byte-identical to the CDN copy); CSP tightened to `script-src 'self'`
- [x] **P0.8** Test suite green after all of the above (751 passed, 0 failed — includes 27 new tests for enrichment, event bus, and flow normalizer)

**Phase 0 complete (2026-07-14).** Next: Phase 1 — twin builder subscribing to
`packet.batch` / `flow.completed` / `mode.changed`, topology view, behavior profiles.

*Exit criteria:* flow records + DNS events streaming on the bus; the old detector's
baseline measured; dashboard runs fully offline.

### Phase 1 — Digital twin + device behavior (Sprints 3–5, weeks 5–10)

- [x] **P1.1** Twin builder (`intelligence/twin.py`): MAC-keyed device nodes with
  self/gateway/external roles, communication edges with byte/packet/protocol stats,
  DNS enrichment per device, mode timeline, DB seeding on start, stale pruning,
  noise filtering (broadcast/multicast MACs and IPs)
- [x] **P1.2** `/api/twin`, `/api/twin/stats`, `/api/flows/recent`, `/api/dns/recent`,
  `/api/behavior/profiles/<mac>` (`backend/blueprints/twin_bp.py`) — all degrade
  gracefully when intelligence services are off
- [x] **P1.3** Dashboard **Topology** view (`TopologyView.js`): dependency-free SVG
  radial layout (gateway center, device inner ring, external outer ring), edges
  weighted by bytes, hover tooltips, theme-aware; new sidebar nav entry
- [x] **P1.4** Behavior profiles (migration 011 `behavior_profiles`): Welford
  baselines per (device × hour-of-week × metric) over bytes / flows /
  unique-destinations / DNS-query metrics, persisted across restarts
- [x] **P1.5** Behavior anomaly detector (`intelligence/behavior.py`): z-score
  scoring with warm-up guard, per-device deduped alerts through
  `AlertEngine.create_behavior_alert` carrying `evidence[]` + `confidence`,
  baseline-poisoning protection (anomalous windows are never learned)

*Exit criteria met (2026-07-14): live topology view; device-level anomalies with
evidence fields. Remaining for later sprints: SSE push for twin deltas (currently
10s polling), hostname enrichment on behavior alerts from the twin.*

### Phase 2 — Detection + prediction (Sprints 6–7, weeks 11–14)  ← **complete (2026-07-15)**

- [x] **P2.1** Threat detector pack (`intelligence/threats.py`): port-scan
  (vertical/horizontal), beaconing (low-jitter C2 heartbeat), DNS-tunneling
  (query burst + long/high-entropy qnames), rogue device (unknown MAC),
  lateral movement (internal fan-out on admin ports) — subscribes to
  `flow.completed`/`dns.query`, alerts with `evidence[]`+`confidence` via
  `AlertEngine.create_threat_alert`, `THREAT_*` config
- [x] **P2.2** Forecasting (`intelligence/forecast.py`): Holt bandwidth
  forecast with confidence band + saturation ETA, least-squares device-count
  trend; `/api/forecast/bandwidth`, `/api/forecast/devices`; dashed overlay
  on BandwidthChart with shaded band (`--chart-forecast`); `FORECAST_*` config
- [x] **P2.3** Incident triage (`intelligence/incidents.py`): alert→incident
  fusion by device + rolling window (migration 012 `incidents` +
  `alerts.incident_id`), `/api/incidents*`; fixes the dedup-by-type weakness

*Exit met:* named threats fire with evidence; forecast line + band on the
chart; related alerts collapse into incidents. Remaining polish for later:
red-team demo script in `scripts/`, incident timeline UI view (API is ready).

### Phase 2.5 — Privilege separation (parallel with Phase 2)

- Capture moves behind a local socket as a minimal privileged process; API/intelligence run unprivileged
- pcap-replay through the normalizer becomes the primary test strategy

### Phase 3 — LLM investigations (Sprints 8–10, weeks 15–20)

- Knowledge-graph projection (twin + time + provenance)
- Local LLM runtime (Ollama/llama.cpp, quantized 4–8B) in a **separate process**, strict JSON tool calls only: `query_metrics`, `query_graph`, `list_incidents`
- "Ask NetWatch" chat view + incident timeline view
- Explainability: every alert/incident carries `evidence[]`, `confidence`, feature attributions

*Exit:* "Why did the lab Wi-Fi degrade at 10:42?" answered with citations, fully offline.

### Phase 4 — Evaluation + packaging (Sprints 11–12, weeks 21–24)

- Labeled evaluation dataset from lab traffic; precision/recall tables; ablations (LLM with vs without tool grounding)
- Installer updates (models ship beside `models/`); thesis material

---

## Research contributions (capstone-defensible)

1. Passive-only digital-twin construction on commodity hardware, evaluated across all six capture modes.
2. Tool-grounded local-LLM network investigation with citation-faithfulness measurement.
3. Per-device behavioral baselining without payload inspection, with a published labeled dataset.

## Differentiation vs Zabbix / PRTG / Nagios / Grafana / SolarWinds

All are metric/poll-based (SNMP/agents/thresholds), dashboards-first. NetWatch differs by:
passive packet-level sensing with zero agents on monitored devices; a live behavioral twin
rather than a static inventory; natural-language, evidence-cited investigations running
fully offline; learned per-device baselines instead of hand-set thresholds; RCA that names
causes; edge deployment on a laptop.
