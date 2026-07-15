# Idle Client Baseline Guide

## Purpose

This guide defines expected traffic behavior for connected but idle hotspot clients.

The dashboard defaults to app-only bandwidth. Control traffic (ARP, DHCP, mDNS, IPv6 ND) is tracked separately.

## Baseline Targets

- App bytes per hour: less than 100 KB/h per idle client
- App packets per second: less than 5 pps
- Control bytes per hour: typically 1 to 5 MB/h depending on client count and network chatter
- Mode transitions: 0 in stable hotspot operation (or less than 2 in 24h during maintenance)

## Health Endpoint

Use:

- GET /api/health/idle-client-baseline
- Optional query: hours (default 24)

Response fields include:

- app_bytes_per_hour
- control_bytes_per_hour
- app_pps
- control_pps
- control_overhead_ratio
- mode_transition_count
- active_devices_realtime
- checks
- status

## Exporting Baseline Metrics

Run:

```bash
python scripts/export_baseline_metrics.py --hours 24
```

Outputs:

- docs/baseline_metrics.json
- docs/baseline_metrics.csv

These files can be committed and compared across releases.

## Troubleshooting High Idle Usage

If app bytes stay above baseline while clients are "idle":

1. Verify control-overhead toggle in UI is off for app-only view.
2. Check if clients are performing cloud sync, updates, or captive portal probes.
3. Check /api/health/idle-client-baseline for app_pps and control ratio.
4. Inspect top talkers and protocol distribution for persistent app protocols.
5. Confirm mode is stable and transition count is low.

## Connected Clients Realtime Behavior

Hotspot discovery continuously upserts connected clients into in-memory state.
Disconnected clients are pruned using HOTSPOT_STALE_DEVICE_SECONDS (default 60s).
