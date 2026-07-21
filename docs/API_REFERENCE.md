# NetWatch API Reference

**Base URL:** `http://localhost:5000`
**Content-Type:** `application/json`

---

## Table of Contents

- [Authentication](#authentication)
- [Response Envelope](#response-envelope)
- [Health & Status](#health--status)
- [Dashboard](#dashboard)
- [Devices](#devices)
- [Alerts](#alerts)
- [Alert Rules (CRUD)](#alert-rules-crud)
- [Bandwidth & Traffic](#bandwidth--traffic)
- [Interface Management](#interface-management)
- [Network Discovery](#network-discovery)
- [GeoIP](#geoip)
- [Digital Twin & Intelligence](#digital-twin--intelligence)
- [Forecasting](#forecasting)
- [Incidents & AI Response](#incidents--ai-response)
- [Ask NetWatch](#ask-netwatch)
- [Briefing](#briefing)
- [Blocking Rules](#blocking-rules)
- [Parental Controls](#parental-controls)
- [Export](#export)
- [System & Metrics](#system--metrics)
- [Server-Sent Events (SSE)](#server-sent-events-sse)
- [Error Codes](#error-codes)
- [Configuration Reference](#configuration-reference)

---

## Authentication

When `NETWATCH_AUTH_ENABLED` is set (always on in production), pass your API
key in the `X-API-Key` header:

```
X-API-Key: <your-key>
```

Exempt routes (no key required): `/health`, `/`, `/index.html`,
`/api/status`, `/api/info`, and all static assets (`/css/`, `/js/`,
`/assets/`).

---

## Response Envelope

Most API responses follow a common envelope:

```json
{
  "data": { ... },
  "meta": { "count": 5 }
}
```

Error responses use:

```json
{
  "error": "Description of what went wrong",
  "code": "ERROR_CODE"
}
```

---

## Health & Status

### `GET /health`

Lightweight health check for load balancers. Always returns 200 when the
server is up.

**Response:**
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "timestamp": "2026-02-06T10:30:00.123456"
}
```

### `GET /api/info`

Application metadata and uptime.

**Response:**
```json
{
  "name": "NetWatch",
  "version": "3.0.0",
  "environment": "production",
  "uptime_seconds": 18900.52,
  "uptime_formatted": "5h 15m 0s"
}
```

### `GET /api/status`

Complete system status. Version is only included for authenticated callers.

**Response:**
```json
{
  "uptime_seconds": 18900.1,
  "timestamp": "2026-02-06T10:30:00",
  "version": "3.0.0",
  "health": {
    "status": "good",
    "cpu_percent": 12.3,
    "memory": { "rss_mb": 125.4, "percent": 3.2 },
    "database": { "size_mb": 48.2 }
  },
  "metrics": { ... },
  "capture": { "running": true, "packets_per_second": 850 },
  "database": { "size_mb": 48.2 },
  "system_alerts": []
}
```

### `GET /api/system/healthcheck`

Comprehensive health check for monitoring systems. Returns HTTP 200 when
healthy, 503 when degraded.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-02-06T10:30:00",
  "version": "3.0.0",
  "components": {
    "database": { "status": "UP" },
    "packet_capture": { "status": "UP" },
    "anomaly_detector": { "status": "UP", "trained": true, "samples": 500 }
  },
  "resources": {
    "cpu_percent": 12.3,
    "memory_mb": 125.4,
    "disk_usage_percent": 45.2
  }
}
```

---

## Dashboard

### `GET /api/dashboard`

Aggregated dashboard data in a single call. When the capture engine is
running, stats are served from an in-memory snapshot (zero DB queries).

**Response:**
```json
{
  "stats": {
    "today_bytes": 1073741824,
    "today_packets": 250000,
    "active_devices": 5,
    "bandwidth_bps": 13107200,
    "bandwidth_mbps": 12.5,
    "upload_bps": 2621440,
    "download_bps": 10485760,
    "upload_mbps": 2.5,
    "download_mbps": 10.0,
    "packets_per_second": 850
  },
  "health": {
    "score": 85,
    "status": "good"
  },
  "devices": [
    {
      "ip_address": "192.168.137.100",
      "device_name": "Johns-Laptop",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "total_bytes": 524288000,
      "last_seen": "2026-02-06T10:30:00"
    }
  ],
  "protocols": [
    { "protocol": "HTTPS", "bytes": 419430400, "percentage": 80.0 }
  ],
  "alerts": [
    {
      "id": 1,
      "severity": "warning",
      "message": "High bandwidth usage",
      "timestamp": "2026-02-06T10:25:00"
    }
  ],
  "alert_stats": {
    "total_unresolved": 3,
    "unacknowledged": 2,
    "by_severity": { "warning": 2, "critical": 1 }
  },
  "mode": {
    "mode": "hotspot",
    "mode_display": "Mobile Hotspot",
    "interface": "Wi-Fi",
    "ip_address": "192.168.137.1"
  },
  "bandwidth": {
    "history": [
      {
        "timestamp": "2026-02-06T10:29:50",
        "upload_mbps": 2.3,
        "download_mbps": 9.8
      }
    ]
  }
}
```

### `GET /api/stats/realtime`

Real-time network statistics.

**Response:**
```json
{
  "data": {
    "bandwidth_bps": 13107200,
    "bandwidth_mbps": 12.5,
    "active_devices": 5,
    "packets_per_second": 850,
    "total_bytes_today": 1073741824,
    "timestamp": "2026-02-06T10:30:00"
  }
}
```

### `GET /api/health`

Network health score and contributing factors.

**Response:**
```json
{
  "data": {
    "score": 85,
    "status": "good",
    "factors": {
      "bandwidth": 90,
      "packet_loss": 95,
      "latency": 80,
      "anomalies": 75
    },
    "device_count": 5,
    "critical_alerts": 0,
    "warning_alerts": 2
  }
}
```

### `GET /api/metrics`

Combined real-time metrics for dashboard widgets.

**Response:**
```json
{
  "data": {
    "bandwidth_bps": 13107200,
    "active_devices": 5,
    "packets_per_second": 850,
    "total_bytes_today": 1073741824
  }
}
```

---

## Devices

### `GET /api/devices`

List all tracked devices (paginated).

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max devices to return |
| `offset` | int | 0 | Pagination offset |

**Response:**
```json
{
  "data": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "ip_address": "192.168.137.100",
      "hostname": "johns-laptop",
      "device_name": "John's Laptop",
      "vendor": "Apple Inc",
      "first_seen": "2026-02-06T08:00:00",
      "last_seen": "2026-02-06T10:30:00",
      "total_bytes_sent": 104857600,
      "total_bytes_received": 419430400,
      "total_packets": 35000
    }
  ],
  "meta": { "count": 1, "limit": 50, "offset": 0 }
}
```

### `GET /api/devices/top`

Top devices by bandwidth usage.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 10 | Number of top devices |
| `hours` | int | 1 | Time window (1-168) |

**Response:**
```json
{
  "data": [
    {
      "ip_address": "192.168.137.100",
      "device_name": "John's Laptop",
      "total_bytes": 524288000,
      "total_bytes_formatted": "500.0 MB"
    }
  ],
  "meta": { "count": 1, "limit": 10, "hours": 1 }
}
```

### `GET /api/devices/<ip_address>`

Get details for a specific device.

**Response:**
```json
{
  "data": {
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "ip_address": "192.168.137.100",
    "device_name": "John's Laptop",
    "vendor": "Apple Inc",
    "total_bytes_sent": 104857600,
    "total_bytes_received": 419430400,
    "total_packets": 35000,
    "protocols": ["HTTPS", "DNS", "HTTP"],
    "today_bytes": 104857600
  }
}
```

**Error (404):**
```json
{ "error": "Device not found", "code": "NOT_FOUND" }
```

### `POST /api/devices/update-name`

Rename a device. Accepts IP address or MAC address as the identifier.

**Request:**
```json
{
  "ip_address": "192.168.137.100",
  "hostname": "Living Room TV"
}
```

**Response:**
```json
{
  "data": {
    "success": true,
    "message": "Device 192.168.137.100 renamed to Living Room TV"
  }
}
```

---

## Alerts

### `GET /api/alerts`

List alerts with optional filtering.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max alerts (1-500) |
| `severity` | string | all | Filter: `info`, `warning`, `critical` |
| `acknowledged` | bool | all | Filter by acknowledgment state |

**Response:**
```json
{
  "data": [
    {
      "id": 1,
      "timestamp": "2026-02-06T10:25:00",
      "alert_type": "bandwidth",
      "severity": "warning",
      "message": "High bandwidth usage: 15.2 Mbps",
      "acknowledged": false,
      "resolved": false
    }
  ],
  "meta": { "count": 1, "limit": 50 }
}
```

### `GET /api/alerts/summary`

Alert summary counts.

**Response:**
```json
{
  "data": {
    "total": 25,
    "active": 3,
    "acknowledged": 5,
    "resolved": 17,
    "by_severity": {
      "critical": 1,
      "warning": 4,
      "info": 20
    }
  }
}
```

### `GET /api/alerts/stats`

Detailed alert statistics.

**Response:**
```json
{
  "data": {
    "total_24h": 15,
    "by_type": {
      "bandwidth": 8,
      "anomaly": 4,
      "device_count": 2,
      "health": 1
    },
    "unresolved": 3
  }
}
```

### `GET /api/alerts/recent`

Recent unacknowledged alerts (for the dashboard widget).

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 5 | Max alerts (1-20) |

**Response:**
```json
{
  "data": [ ... ],
  "meta": { "count": 3 }
}
```

### `POST /api/alerts`

Create a new alert manually (useful for testing).

**Request:**
```json
{
  "type": "custom",
  "severity": "warning",
  "message": "Manual alert message",
  "source_ip": "192.168.137.100",
  "details": {}
}
```

Allowed types: `bandwidth`, `anomaly`, `device_count`, `health`, `protocol`,
`connection`, `security`, `new_device`, `custom`.

Allowed severities: `info`, `low`, `medium`, `warning`, `high`, `critical`.

**Response (201):**
```json
{
  "data": { "success": true, "alert_id": 42, "message": "Alert created" }
}
```

### `POST /api/alerts/<id>/acknowledge`

Acknowledge an alert.

**Response:**
```json
{
  "data": { "success": true, "message": "Alert 1 acknowledged" }
}
```

### `POST /api/alerts/<id>/resolve`

Resolve an alert.

**Response:**
```json
{
  "data": { "success": true, "message": "Alert 1 resolved" }
}
```

---

## Alert Rules (CRUD)

Custom alert rules define thresholds that the alert engine evaluates
periodically.

### `GET /api/alert-rules`

List all custom alert rules.

**Response:**
```json
{
  "data": [
    {
      "id": 1,
      "name": "High bandwidth",
      "description": "Alert when bandwidth exceeds 50 Mbps",
      "metric": "bandwidth_mbps",
      "operator": ">",
      "threshold": 50,
      "severity": "warning",
      "enabled": true,
      "cooldown_seconds": 300,
      "created_at": "2026-02-06T08:00:00"
    }
  ],
  "meta": { "count": 1 }
}
```

### `POST /api/alert-rules`

Create a custom alert rule.

**Request:**
```json
{
  "name": "High bandwidth",
  "description": "Alert when bandwidth exceeds 50 Mbps",
  "metric": "bandwidth_mbps",
  "operator": ">",
  "threshold": 50,
  "severity": "warning",
  "cooldown_seconds": 300
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Rule display name (max 200 chars) |
| `metric` | yes | Metric to evaluate (see valid metrics below) |
| `operator` | yes | Comparison operator (`>`, `<`, `>=`, `<=`, `==`, `!=`) |
| `threshold` | yes | Numeric threshold value |
| `severity` | no | `info`, `warning`, `critical` (default: `warning`) |
| `description` | no | Free-text description |
| `cooldown_seconds` | no | Seconds between repeat alerts (default: 300) |

**Response (201):**
```json
{
  "data": { "success": true, "id": 1 }
}
```

### `PUT /api/alert-rules/<rule_id>`

Update an existing alert rule. Only send the fields you want to change.

**Request:**
```json
{
  "threshold": 100,
  "enabled": false
}
```

Updatable fields: `name`, `description`, `metric`, `operator`, `threshold`,
`severity`, `enabled`, `cooldown_seconds`.

**Response:**
```json
{
  "data": { "success": true, "id": 1 }
}
```

### `DELETE /api/alert-rules/<rule_id>`

Delete an alert rule.

**Response:**
```json
{
  "data": { "success": true }
}
```

---

## Bandwidth & Traffic

### `GET /api/bandwidth/history`

Historical bandwidth data for charting.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 1 | Hours of history (1-168) |
| `interval` | string | `minute` | Aggregation: `minute`, `hour`, `day` |

**Response:**
```json
{
  "data": [
    {
      "timestamp": "2026-02-06T09:00:00",
      "bandwidth_bps": 5242880,
      "bandwidth_mbps": 5.0
    }
  ],
  "meta": { "count": 60, "hours": 1, "interval": "minute" }
}
```

### `GET /api/bandwidth/dual`

Upload/download bandwidth split.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 1 | Hours of history (1-168) |
| `interval` | string | `minute` | `10s`, `30s`, `minute`, `hour`, `day` |

**Response:**
```json
{
  "data": [
    {
      "timestamp": "2026-02-06T10:29:00",
      "upload_mbps": 2.3,
      "download_mbps": 9.8
    }
  ],
  "meta": { "count": 60, "hours": 1, "interval": "minute" }
}
```

### `GET /api/stats/bandwidth/realtime`

Real-time bandwidth directly from the capture engine.

**Response:**
```json
{
  "data": {
    "total_bps": 1638400,
    "total_mbps": 12.5,
    "upload_bps": 327680,
    "upload_mbps": 2.5,
    "download_bps": 1310720,
    "download_mbps": 10.0,
    "packets_per_second": 850,
    "engine_running": true,
    "engine_stats": { ... }
  }
}
```

### `GET /api/protocols`

Protocol distribution statistics.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 1 | Time window (1-168) |

**Response:**
```json
{
  "data": [
    { "protocol": "HTTPS", "bytes": 419430400, "percentage": 80.0 },
    { "protocol": "DNS", "bytes": 52428800, "percentage": 10.0 },
    { "protocol": "HTTP", "bytes": 26214400, "percentage": 5.0 },
    { "protocol": "Other", "bytes": 26214400, "percentage": 5.0 }
  ],
  "meta": { "count": 4, "hours": 1 }
}
```

### `GET /api/traffic`

Traffic summary data.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 24 | Time window (1-168) |

**Response:**
```json
{
  "data": { ... }
}
```

### `GET /api/activity`

Recent network activity feed.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 20 | Max entries (1-100) |

**Response:**
```json
{
  "data": [ ... ],
  "meta": { "count": 20 }
}
```

---

## Interface Management

### `GET /api/interface/status`

Current network interface and monitoring mode.

**Response:**
```json
{
  "data": {
    "interface": "Wi-Fi",
    "mode": "hotspot",
    "mode_display": "Mobile Hotspot",
    "ip_address": "192.168.137.1",
    "bpf_filter": "net 192.168.137.0/24",
    "promiscuous": true,
    "capabilities": {
      "can_see_other_devices": true,
      "can_arp_scan": true,
      "scope": "connected_clients"
    }
  }
}
```

### `POST /api/interface/refresh`

Force re-detection of the network mode.

**Response:**
```json
{
  "data": {
    "success": true,
    "message": "Interface detection refreshed",
    "status": { ... }
  }
}
```

### `GET /api/interface/list`

List all available network interfaces.

**Response:**
```json
{
  "data": {
    "interfaces": [
      {
        "name": "Wi-Fi",
        "friendly_name": "Wi-Fi",
        "ip_address": "192.168.1.50",
        "is_active": true
      },
      {
        "name": "Ethernet",
        "friendly_name": "Ethernet",
        "ip_address": null,
        "is_active": false
      }
    ],
    "count": 2,
    "current": "Wi-Fi",
    "mode": "hotspot"
  }
}
```

### `POST /api/interface/select`

Manually select a network interface for monitoring.

**Request:**
```json
{
  "interface": "Ethernet"
}
```

**Response:**
```json
{
  "data": {
    "success": true,
    "message": "Switched to interface Ethernet",
    "mode": "ethernet",
    "status": { ... }
  }
}
```

---

## Network Discovery

### `GET /api/discovery/devices`

All devices found by active/passive discovery.

**Response:**
```json
{
  "data": [
    {
      "ip": "192.168.137.100",
      "mac": "AA:BB:CC:DD:EE:FF",
      "hostname": "johns-laptop",
      "vendor": "Apple Inc"
    }
  ],
  "meta": {
    "count": 5,
    "network": "192.168.137.0/24",
    "interface": "Wi-Fi",
    "discovery_methods": ["arp", "ping", "mdns", "passive"]
  }
}
```

### `POST /api/discovery/scan`

Trigger an immediate ARP network scan.

**Response:**
```json
{
  "data": [ ... ],
  "meta": {
    "count": 8,
    "success": true,
    "network": "192.168.137.0/24",
    "interface": "Wi-Fi",
    "scan_type": "arp",
    "message": "Discovered 8 devices"
  }
}
```

### `GET /api/discovery/capabilities`

Current discovery capabilities based on the active monitoring mode.

**Response:**
```json
{
  "data": {
    "mode": "hotspot",
    "mode_display": "Mobile Hotspot",
    "interface": "Wi-Fi",
    "ip_address": "192.168.137.1",
    "capabilities": {
      "can_arp_scan": true,
      "promiscuous_available": true,
      "can_see_all_traffic": true,
      "can_discover_devices": true
    },
    "features": {
      "arp_scanning": true,
      "promiscuous_mode": true,
      "full_traffic_capture": true,
      "device_discovery": true,
      "port_mirror_support": false
    },
    "description": "..."
  }
}
```

### `GET /api/discovery/port-mirror-status`

Check if the current interface is connected to a port mirror/SPAN port.

**Response:**
```json
{
  "data": {
    "detected": false,
    "interface": "Wi-Fi",
    "description": "Normal connection detected",
    "recommendation": "Normal connection - use ARP scanning for device discovery"
  }
}
```

---

## GeoIP

### `GET /api/geoip/<ip_address>`

Get geographic location data for an external IP address.

**Response:**
```json
{
  "data": {
    "ip": "8.8.8.8",
    "country": "United States",
    "country_code": "US",
    "region": "California",
    "city": "Mountain View",
    "latitude": 37.386,
    "longitude": -122.0838,
    "org": "Google LLC"
  }
}
```

**Error (404):**
```json
{ "error": "No GeoIP data available", "code": "NOT_FOUND" }
```

### `POST /api/geoip/batch`

Batch GeoIP lookup for up to 100 IP addresses.

**Request:**
```json
{
  "ips": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
}
```

**Response:**
```json
{
  "data": {
    "8.8.8.8": { "country": "United States", "city": "Mountain View", ... },
    "1.1.1.1": { "country": "Australia", "city": "Sydney", ... }
  }
}
```

---

## Digital Twin & Intelligence

Phase 1 (AI-first) read-only endpoints over the intelligence layer. All of
them degrade to empty payloads when the intelligence services are not
running (e.g. `--no-capture`).

### `GET /api/twin`

Live digital-twin graph snapshot.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_edges` | int | 500 | Cap on returned edges (1-2000), highest-traffic first |

**Response:**

```json
{
  "data": {
    "generated_at": 1783468800.0,
    "mode": "hotspot",
    "stats": {"node_count": 12, "edge_count": 48, "device_count": 5,
               "external_count": 7, "events_consumed": 1042},
    "mode_timeline": [{"timestamp": 1783468000.0, "old_mode": "none", "new_mode": "hotspot"}],
    "nodes": [{"id": "mac:aa:bb:cc:00:00:01", "type": "device",
               "mac": "aa:bb:cc:00:00:01", "ip": "192.168.137.42",
               "hostname": "pixel-7", "vendor": "Google",
               "bytes_in": 1048576, "bytes_out": 65536, "packets": 900,
               "protocols": ["HTTPS", "DNS"], "recent_dns": ["example.com"],
               "first_seen": 1783460000.0, "last_seen": 1783468790.0}],
    "edges": [{"source": "mac:aa:bb:cc:00:00:01", "target": "ip:93.184.216.34",
               "bytes": 1048576, "packets": 800, "protocols": ["HTTPS"],
               "first_seen": 1783460000.0, "last_seen": 1783468790.0}]
  }
}
```

Node `type` is one of `self`, `gateway`, `device`, `external`.

### `GET /api/twin/stats`

Diagnostics for the intelligence layer: twin size, behavior-analyzer counters,
and event-bus subscription stats (pending/delivered/dropped per consumer).

### `GET /api/flows/recent`

Recent flow records from the `flows` table.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Max rows (1-1000) |
| `mac` | string | — | Filter by source or dest MAC |
| `since` | string | — | Lower bound `YYYY-MM-DD HH:MM:SS` |

### `GET /api/dns/recent`

Recent DNS query events from the `dns_queries` table. Same parameters as
`/api/flows/recent` (`mac` filters the querying device).

### `GET /api/behavior/profiles/<mac>`

Learned hour-of-week baselines for one device.

**Response:**

```json
{
  "data": {
    "mac": "aa:bb:cc:00:00:01",
    "metrics": {
      "bytes":        [{"hour_of_week": 34, "samples": 18, "mean": 1048576.0, "std": 20480.5}],
      "flows":        [{"hour_of_week": 34, "samples": 18, "mean": 42.1, "std": 6.3}],
      "unique_dests": [{"hour_of_week": 34, "samples": 18, "mean": 9.5, "std": 2.1}],
      "dns_queries":  [{"hour_of_week": 34, "samples": 18, "mean": 12.0, "std": 4.4}]
    }
  }
}
```

Behavior anomalies surface as regular alerts (`alert_type: "anomaly"`) whose
`details` JSON carries `detector: "behavior_baseline"`, `device_mac`,
`confidence` (0-1), and an `evidence[]` array of
`{metric, observed, baseline_mean, baseline_std, baseline_samples, z_score, hour_of_week}`.

### `GET /api/activity/recent`

Live per-client activity feed: which site and app each device is using, resolved
offline from SNI/DNS through the bundled app catalog.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Max rows |
| `mac` | string | — | Filter to one device |

### `GET /api/threats/recent`

Recent threat detections, including VPN/tunnel classifications, each with its
`evidence[]` and `confidence`.

---

## Forecasting

Computed on demand from the telemetry tables and TTL-cached. Pure math (Holt
double-exponential smoothing) — no model and no ML dependency. When there is not
enough history yet these return `available: false` with a `reason` instead of
failing.

### `GET /api/forecast/bandwidth`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `horizon` | int | `FORECAST_HORIZON_MINUTES` (30) | Minutes to project forward |

**Response:**

```json
{
  "data": {
    "available": true,
    "horizon_minutes": 30,
    "points": [{"minute": 1, "mbps": 12.4, "lower": 9.1, "upper": 15.7}],
    "saturation_eta_minutes": null,
    "link_capacity_mbps": 0
  }
}
```

The confidence band widens as `±1.96·σ·√k` with the step count `k`.
`saturation_eta_minutes` is only meaningful once you set
`FORECAST_LINK_CAPACITY_MBPS` to your actual link speed; it stays `null`
otherwise.

### `GET /api/forecast/devices`

Active-device-count trend from a least-squares fit.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `horizon` | int | 6 | Hours to project forward |

---

## Incidents & AI Response

An incident groups alerts that belong to the same story: alerts for one device
(or network-wide) arriving within `INCIDENT_WINDOW_MINUTES` of an open incident
join it rather than piling up separately. Reads work even when the
`IncidentManager` is not attached — incidents are plain rows; only *fusion of new
alerts* needs the manager.

### `GET /api/incidents`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | — | `open` or `resolved`; anything else → 400 `BAD_STATUS` |
| `limit` | int | 50 | Max incidents |

Returned highest-risk-first. Every incident carries a computed `risk_score` and
`risk_band`.

### `GET /api/incidents/stats`

```json
{ "data": { "open_count": 3, "triage": { } } }
```

`triage` is `null` when the incident manager is not running.

### `GET /api/incidents/<id>`

One incident plus its member alerts. `404 NOT_FOUND` if it does not exist.

### `POST /api/incidents/<id>/resolve`

Mark an incident resolved. `404` if it does not exist or is already resolved.

### `GET /api/incidents/<id>/assess`

The AI assessment: what this incident looks like, and what to do about it.

| Parameter | Type | Description |
|-----------|------|-------------|
| `refresh` | `1`/`true`/`yes` | Recompute, bypassing the cache |
| `wait` | `1`/`true`/`yes` | Block until the assessment is ready |

A background assessor normally has a verdict ready before anyone opens the
incident. If it does, you get it immediately with `"cached": true`. If not, the
default is to return a placeholder rather than block a request behind a model
run:

```json
{ "data": { "incident_id": 12, "pending": true,
            "reason": "Assessment is being prepared." } }
```

A completed verdict looks like:

```json
{
  "data": {
    "incident_id": 12,
    "assessment": "A device is contacting one host on a fixed 60s interval …",
    "confidence": 0.72,
    "indicators_matched": ["beaconing", "unknown_destination_org"],
    "recommended_action": "quarantine",
    "source": "model"
  }
}
```

`source` is `"model"` when a local LLM produced it and `"rules"` when it came
from the deterministic fallback — those deserve different levels of trust, so
the API states which one you got. `recommended_action` is always one of
`monitor`, `throttle`, `quarantine`, `dismiss_benign`.

### `POST /api/incidents/<id>/apply`

Act on a recommendation **the operator approved**. Nothing in the assessment
path applies itself; this call is the only thing that changes state.

```json
{ "action": "quarantine", "minutes": 60 }
```

| Action | Effect |
|---|---|
| `quarantine` | Pauses the incident's device for `minutes` (default 60) via the ordinary policy path, then kicks the enforcer |
| `dismiss_benign` | Resolves the incident |
| `monitor` / `throttle` | Advisory — `applied: false`, nothing changes on the wire |

A quarantine is deliberately routed through the same timed-pause machinery as
any other block: it shows up on the Controls page and is released by the same
button. An action a human cannot see or undo is not one an AI should be allowed
to take.

`400 BAD_REQUEST` if `action` is not one of the four, or if `quarantine` is
requested for an incident with no device MAC.

---

## Ask NetWatch

Natural-language questions answered by a tool-calling loop over three read-only
tools. Fully local — the investigator only ever talks to a local Ollama server.
When no model is reachable these return `available: false` with a reason rather
than failing.

### `GET /api/investigate/status`

```json
{ "data": { "available": true, "model": "llama3.2:3b",
            "tools": ["query_metrics", "query_graph", "list_incidents"] } }
```

When unavailable, `available: false` plus a `reason` explaining how to install
Ollama and pull the model.

### `GET /api/investigate/tools`

The JSON schema of the grounding tools the model is allowed to call. These are
the *only* data surface it can touch, and all three are read-only.

### `POST /api/investigate`

```json
{ "question": "which device used the most data in the last hour?" }
```

| Error | Condition |
|---|---|
| `400 NO_QUESTION` | Empty or missing `question` |
| `400 QUESTION_TOO_LONG` | Over 1000 characters |

The response carries the answer *and* the full tool-call trace — every tool
invoked, its arguments, and what it returned — so any claim can be checked
against the data it came from. The loop stops at the first answer or after
`NETWATCH_LLM_MAX_STEPS` (default 6) steps.

---

## Briefing

### `GET /api/briefing`

A short plain-English account of what just happened on the network.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `minutes` | int | 10 | Window length, clamped to 1–120 |
| `force` | `1`/`true`/`yes` | — | Bypass the short cache |

The facts are gathered deterministically; the model is only asked to *narrate*
them. The response says whether the narrative was written by the model or
composed from the facts, and the raw facts travel with it so the claim can be
checked. With no model running you still get a briefing — just an unnarrated
one.

---

## Blocking Rules

Domain blocking, enforced by `packet_capture.dns_blocker` on the capture thread
and, where available, by kernel-level packet drop. Every mutation reloads the
running blockers so a rule takes effect on the next lookup rather than at the
next restart.

Every response includes a `status` object alongside `data`:

```json
{
  "status": {
    "enforcing": true,
    "level": "packet",
    "mode": "hotspot",
    "packet_mode": "windivert",
    "reason": null
  }
}
```

`level` is `packet` (WinDivert — cannot be bypassed), `dns` (sinkhole only —
apps using DoH or cached IPs over QUIC *can* bypass it), or `none`. When
`enforcing` is false, `reason` says exactly why: capture is not running, or the
current mode is not `hotspot` so rules are **saved but not enforced**.

### `GET /api/blocking/rules`

List all rules plus the enforcement status above.

### `POST /api/blocking/rules`

```json
{ "domain": "example.com", "device_mac": "aa:bb:cc:00:00:01",
  "scope": "device", "note": "optional" }
```

`scope` is `device` (default — drops only this client's traffic to the domain)
or `network` (every client, and this host too). Returns `201`, or `400` if the
domain is not a valid domain name.

### `PATCH /api/blocking/rules/<id>`

`{ "enabled": false }` — enable or disable a rule. `400` if `enabled` is absent,
`404` if the rule does not exist.

### `DELETE /api/blocking/rules/<id>`

Remove a rule. `404` if it does not exist.

---

## Parental Controls

Per-device policy: daily data caps, blocked time windows, and pauses. Enforced
by the same machinery as domain blocking but at the whole-device level, so the
same hotspot-mode caveat applies — and the same `status` object is returned by
every endpoint here, extended with:

| Field | Meaning |
|---|---|
| `enforcement_level` | `windivert` \| `arp` \| `off` \| `unavailable` |
| `windivert_available` | Whether packet-level blocking is installed |
| `enforcement_note` | How to get packet-level blocking, when it's missing |

### `GET /api/parental/policies`

Every policy, each annotated with live state: `usage_today_bytes`,
`blocked_now`, and `block_reason` (which rule is currently biting — quota,
window, or pause).

### `PUT /api/parental/policies/<mac>`

```json
{ "daily_quota_mb": 2048,
  "blocked_windows": [{"start": "22:00", "end": "07:00"}],
  "paused": false,
  "note": "kids' tablet" }
```

All fields optional. `400` if `daily_quota_mb` is not a number or
`blocked_windows` is not a list.

### `POST /api/parental/policies/<mac>/pause`

```json
{ "minutes": 60 }
```

Defaults to 60 minutes; maximum 1440 (24 h). Pass `"minutes": null` explicitly
for an open-ended pause.

> Pauses are bounded by default on purpose. An unbounded pause outlives the
> session that created it — one set at 10:12 was still dropping a phone's
> traffic hours later, across restarts, with nothing in the UI explaining why.
> Open-ended is still available, but you have to ask for it.

`400` if `minutes` is not a number or falls outside 1–1440.

### `POST /api/parental/policies/<mac>/resume`

Lift the pause.

### `DELETE /api/parental/policies/<mac>`

Clear the device's policy entirely. `404` if there was none.

---

## Export

### `GET /api/export/<fmt>`

Export traffic or device data. `fmt` must be `csv` or `json`.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | string | `devices` | Export type: `devices` or `traffic` |
| `hours` | int | 24 | Time window for traffic export (1-168) |
| `device_ip` | string | all | Filter traffic by device IP |

**Response:**

Returns a file download with `Content-Disposition: attachment`.

- `csv` — `text/csv` with headers
- `json` — `application/json` pretty-printed

**Example:**
```
GET /api/export/csv?type=traffic&hours=12&device_ip=192.168.137.100
GET /api/export/json?type=devices
```

**Error (403):**
```json
{ "error": "Data export is disabled", "code": "DISABLED" }
```

---

## System & Metrics

### `GET /api/system/health`

System-level health metrics (CPU, memory, disk, threads).

**Response:**
```json
{
  "data": {
    "status": "good",
    "cpu_percent": 12.3,
    "memory": { "rss_mb": 125.4, "percent": 3.2 },
    "database": { "size_mb": 48.2, "row_counts": { "devices": 50, "traffic_summary": 100000 } },
    "threads": { "count": 12 },
    "timestamp": "2026-02-06T10:30:00"
  }
}
```

### `GET /api/system/health/history`

System health metrics history over time.

**Response:**
```json
{
  "data": [ ... ],
  "meta": { "count": 60 }
}
```

### `GET /api/system/metrics`

Aggregated system metrics from all subsystems.

**Response:**
```json
{
  "data": {
    "timestamp": "2026-02-06T10:30:00",
    "capture": { "running": true, "packets_captured": 150000 },
    "database": { "size_mb": 48.2, "wal_size_mb": 2.1, "row_counts": { ... } },
    "pool": { "size": 15, "in_use": 3, "available": 12 },
    "memory": { "rss_mb": 125.4, "percent": 3.2 },
    "device_count_in_memory": 12,
    "mode": { "name": "hotspot", "interface": "Wi-Fi" },
    "threads": { "count": 12, "names": ["MainThread", "CaptureThread", ...] },
    "requests": { ... }
  }
}
```

### `GET /api/metrics/internal`

Raw application performance metrics from the metrics collector.

**Response:**
```json
{
  "data": { ... }
}
```

### `GET /api/anomaly/status`

ML anomaly detector status.

**Response:**
```json
{
  "data": {
    "available": true,
    "model_trained": true,
    "training_samples": 500,
    "anomalies_detected": 3,
    "last_check": "2026-02-06T10:29:30"
  }
}
```

### `GET /api/system/maintenance`

Database maintenance report (sizes, retention, cleanup history).

**Response:**
```json
{
  "data": { ... }
}
```

### `POST /api/system/maintenance/cleanup`

Trigger a manual database cleanup.

**Request (optional):**
```json
{
  "traffic_retention_days": 7,
  "alert_retention_days": 30
}
```

**Response:**
```json
{
  "data": {
    "success": true,
    "message": "Cleanup completed",
    "result": { ... }
  }
}
```

### `GET /api/health/idle-client-baseline`

Baseline app-vs-control traffic metrics used to validate that a genuinely idle
client reads as idle — i.e. that background chatter (ARP, mDNS, DHCP, NTP) is
being classified as control traffic rather than inflating a device's usage. See
[IDLE_CLIENT_BASELINE.md](IDLE_CLIENT_BASELINE.md) for the thresholds and what
a passing baseline looks like.

---

## Server-Sent Events (SSE)

### `GET /api/stream`

Push real-time updates via Server-Sent Events. The server sends a JSON
payload at the configured interval. Maximum 10 simultaneous connections
(configurable via `SSE_MAX_CONNECTIONS`).

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interval` | int | 3 | Push interval in seconds (1-30) |

**Connection:**
```
GET /api/stream?interval=3
Accept: text/event-stream
```

**Event format:**
```
data: {"stats":{"bandwidth_mbps":12.5,...},"health":{...},"devices":[...],...}

event: mode_changed
data: {"mode":"ethernet","interface":"Ethernet","ip_address":"192.168.1.50"}
```

**SSE payload fields:**

| Field | Description |
|-------|-------------|
| `stats` | Real-time bandwidth, device count, packet rate |
| `health` | Network health score and status |
| `alert_stats` | Unresolved/unacknowledged alert counts by severity |
| `alerts` | Recent unacknowledged alerts |
| `protocols` | Protocol distribution |
| `devices` | Top devices by bandwidth |
| `mode` | Current monitoring mode and interface info |
| `bandwidth_history` | Merged DB + live bandwidth time series |

**Error (429):**
```json
{ "error": "Too many SSE connections" }
```

---

## Error Codes

| HTTP Code | Meaning | When |
|-----------|---------|------|
| 200 | Success | Request completed |
| 201 | Created | Resource created (alert, alert rule) |
| 400 | Bad Request | Invalid JSON, missing fields, validation error |
| 403 | Forbidden | Export disabled, insufficient permissions |
| 404 | Not Found | Unknown endpoint, device, or GeoIP miss |
| 405 | Method Not Allowed | Wrong HTTP method |
| 429 | Too Many Requests | SSE connection limit reached |
| 500 | Server Error | Internal error (check logs) |
| 503 | Service Unavailable | Component not running (interface manager, etc.) |

### Error Response Format

```json
{
  "error": "Not Found",
  "code": "NOT_FOUND",
  "message": "Device with IP 10.0.0.1 not found"
}
```

---

## Configuration Reference

The following configuration values are defined in `config.py` and can be
overridden via environment variables where noted.

### Database Size and Disk Management

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `MAX_DATABASE_SIZE_GB` | float | `20` | `MAX_DATABASE_SIZE_GB` | Maximum database size in GB before emergency cleanup triggers |
| `EMERGENCY_RETENTION_HOURS` | int | `6` | `EMERGENCY_RETENTION_HOURS` | Minimum hours of data to keep when disk space is critically low |
| `DISK_SPACE_WARNING_PERCENT` | int | `10` | `DISK_SPACE_WARNING_PERCENT` | Free disk space percentage that triggers a warning alert |
| `DISK_SPACE_CRITICAL_PERCENT` | int | `5` | `DISK_SPACE_CRITICAL_PERCENT` | Free disk space percentage that triggers a critical alert |

### SSE (Server-Sent Events)

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `SSE_MAX_CONNECTIONS` | int | `10` | `SSE_MAX_CONNECTIONS` | Maximum simultaneous SSE connections allowed (prevents resource exhaustion) |

### Port Mirror Settings

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `PORT_MIRROR_MAX_PPS` | int | `5000` | `PORT_MIRROR_MAX_PPS` | Maximum packets per second when operating in port-mirror mode |
| `PORT_MIRROR_MAX_UNIQUE_MACS_PER_MINUTE` | int | `500` | `PORT_MIRROR_MAX_UNIQUE_MACS` | Maximum unique MAC addresses accepted per minute in port-mirror mode |
| `PORT_MIRROR_CONNECTION_TIMEOUT` | int | `300` | `PORT_MIRROR_CONNECTION_TIMEOUT` | Seconds before an idle port-mirror connection is considered timed out |

### Memory Management and Device Pruning

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `STALE_DEVICE_PRUNE_INTERVAL` | int | `300` | `STALE_DEVICE_PRUNE_INTERVAL` | How often (seconds) the stale-device pruning task runs |
| `STALE_DEVICE_TIMEOUT_HOURS` | int | `2` | `STALE_DEVICE_TIMEOUT_HOURS` | Hours of inactivity after which a device is considered stale and eligible for pruning |
| `MAX_IN_MEMORY_DEVICES` | int | `10000` | `MAX_IN_MEMORY_DEVICES` | Upper limit on devices held in memory; oldest entries are evicted when exceeded |

### Local AI Model

All AI features talk to a local Ollama server at `http://127.0.0.1:11434` over
plain HTTP. No SDK, no API key, no outbound traffic. When no server answers,
these settings are simply unused and every AI endpoint degrades gracefully.

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `LLM_MODEL` | str | `llama3.2:3b` | `NETWATCH_LLM_MODEL` | Ollama model tag to use |
| `LLM_TIMEOUT_SECONDS` | int | `180` | `NETWATCH_LLM_TIMEOUT` | Seconds before a generation is abandoned |
| `LLM_KEEP_ALIVE` | str | `30m` | `NETWATCH_LLM_KEEP_ALIVE` | How long Ollama keeps the model resident |
| `LLM_NUM_PREDICT` | int | `512` | `NETWATCH_LLM_NUM_PREDICT` | Max tokens per generation |
| `LLM_MAX_STEPS` | int | `6` | `NETWATCH_LLM_MAX_STEPS` | Tool-call budget per Ask NetWatch question |

### Flows and Telemetry

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `FLOW_IDLE_TIMEOUT_SECONDS` | int | `30` | `FLOW_IDLE_TIMEOUT_SECONDS` | Idle time before an active flow is flushed |
| `FLOW_MAX_AGE_SECONDS` | int | `300` | `FLOW_MAX_AGE_SECONDS` | Hard cap on a flow's lifetime before flushing |
| `FLOW_FLUSH_INTERVAL_SECONDS` | int | `5` | `FLOW_FLUSH_INTERVAL_SECONDS` | How often the flow table is swept |
| `FLOW_RETENTION_HOURS` | int | `72` | `FLOW_RETENTION_HOURS` | How long flow records are kept |
| `FLOW_MAX_ACTIVE` | int | `50000` | `FLOW_MAX_ACTIVE` | Cap on simultaneously tracked flows |

### Behavior Baselines

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `BEHAVIOR_WINDOW_SECONDS` | int | `600` | `BEHAVIOR_WINDOW_SECONDS` | Accumulation window per sample |
| `BEHAVIOR_MIN_BASELINE_SAMPLES` | int | `12` | `BEHAVIOR_MIN_BASELINE_SAMPLES` | Samples needed before an hour-of-week bucket is trusted |
| `BEHAVIOR_Z_THRESHOLD` | float | `4.0` | `BEHAVIOR_Z_THRESHOLD` | Z-score at which a deviation becomes an alert |
| `BEHAVIOR_MAX_DEVICES` | int | `1000` | `BEHAVIOR_MAX_DEVICES` | Cap on devices profiled |

### Threat Detection

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `THREAT_PORTSCAN_WINDOW_SECONDS` | int | `120` | same | Port-scan observation window |
| `THREAT_PORTSCAN_PORT_THRESHOLD` | int | `15` | same | Distinct ports that trigger a port-scan alert |
| `THREAT_PORTSCAN_HOST_THRESHOLD` | int | `10` | same | Distinct hosts that trigger a sweep alert |
| `THREAT_BEACON_MIN_OBSERVATIONS` | int | `6` | same | Repeat connections needed to call it beaconing |
| `THREAT_BEACON_MAX_JITTER_RATIO` | float | `0.25` | same | Interval jitter allowed while still counting as periodic |
| `THREAT_DNS_TUNNEL_WINDOW_SECONDS` | int | `300` | same | DNS-tunnelling observation window |
| `THREAT_DNS_TUNNEL_QUERY_THRESHOLD` | int | `25` | same | Queries in window that trigger inspection |
| `THREAT_DNS_TUNNEL_QNAME_LENGTH` | int | `40` | same | Query-name length considered suspicious |
| `THREAT_DNS_TUNNEL_ENTROPY` | float | `3.8` | same | Shannon entropy above which a name looks encoded |
| `THREAT_LATERAL_WINDOW_SECONDS` | int | `300` | same | Lateral-movement observation window |
| `THREAT_LATERAL_HOST_THRESHOLD` | int | `3` | same | Internal hosts contacted that trigger an alert |

### VPN Detection

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `VPN_MIN_TUNNEL_BYTES` | int | `2000000` | `VPN_MIN_TUNNEL_BYTES` | Sustained volume before a flow is called a tunnel |
| `VPN_WINDOW_SECONDS` | int | `600` | `VPN_WINDOW_SECONDS` | Observation window |
| `VPN_MIN_TUNNEL_SECONDS` | int | `120` | `VPN_MIN_TUNNEL_SECONDS` | Minimum duration to qualify |

### Forecasting

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `FORECAST_ALPHA` | float | `0.5` | `FORECAST_ALPHA` | Holt level smoothing factor |
| `FORECAST_BETA` | float | `0.1` | `FORECAST_BETA` | Holt trend smoothing factor |
| `FORECAST_MIN_SAMPLES` | int | `20` | `FORECAST_MIN_SAMPLES` | Minutes of history required before forecasting |
| `FORECAST_HISTORY_HOURS` | int | `3` | `FORECAST_HISTORY_HOURS` | How far back the fit looks |
| `FORECAST_HORIZON_MINUTES` | int | `30` | `FORECAST_HORIZON_MINUTES` | Default projection horizon |
| `FORECAST_LINK_CAPACITY_MBPS` | float | `0` | `FORECAST_LINK_CAPACITY_MBPS` | Your link speed; `0` disables saturation ETAs |
| `FORECAST_CACHE_TTL_SECONDS` | int | `30` | `FORECAST_CACHE_TTL_SECONDS` | Forecast cache lifetime |

### Incidents

| Variable | Type | Default | Env Override | Description |
|----------|------|---------|--------------|-------------|
| `INCIDENT_WINDOW_MINUTES` | int | `30` | `INCIDENT_WINDOW_MINUTES` | How long an open incident keeps absorbing related alerts |
