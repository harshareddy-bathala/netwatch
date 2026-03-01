# NetWatch API Reference

**Base URL:** `http://localhost:5000`
**Content-Type:** `application/json`
**Requires:** Python 3.11+

---

## Table of Contents

- [Health & Status](#health--status)
- [Dashboard](#dashboard)
- [Devices](#devices)
- [Alerts](#alerts)
- [Bandwidth & Traffic](#bandwidth--traffic)
- [Interface Management](#interface-management)
- [Network Discovery](#network-discovery)
- [Metrics](#metrics)
- [Error Codes](#error-codes)
- [Configuration Reference (Phase 3)](#configuration-reference-phase-3)

---

## Health & Status

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "timestamp": "2026-02-06T10:30:00"
}
```

### `GET /api/status`

Application status overview.

**Response:**
```json
{
  "status": "running",
  "capture_active": true,
  "mode": "hotspot",
  "interface": "Wi-Fi",
  "uptime_seconds": 18900
}
```

### `GET /api/info`

Application information.

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

---

## Dashboard

### `GET /api/dashboard`

Aggregated dashboard data (single endpoint for all dashboard widgets).

**Response:**
```json
{
  "stats": {
    "active_devices": 5,
    "total_bandwidth_mbps": 12.5,
    "health_score": 85,
    "active_alerts": 2
  },
  "top_devices": [...],
  "recent_alerts": [...],
  "bandwidth_history": [...],
  "protocol_distribution": [...]
}
```

### `GET /api/stats/realtime`

Real-time statistics.

**Response:**
```json
{
  "bandwidth_bps": 13107200,
  "bandwidth_mbps": 12.5,
  "active_devices": 5,
  "packets_per_second": 850,
  "total_bytes_today": 1073741824,
  "timestamp": "2026-02-06T10:30:00"
}
```

### `GET /api/health`

Network health score and factors.

**Response:**
```json
{
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
```

---

## Devices

### `GET /api/devices`

List all tracked devices.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Max devices to return |
| `sort` | string | `last_seen` | Sort field |

**Response:**
```json
[
  {
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "ip_address": "192.168.1.100",
    "hostname": "johns-laptop",
    "device_name": "John's Laptop",
    "vendor": "Apple Inc",
    "first_seen": "2026-02-06T08:00:00",
    "last_seen": "2026-02-06T10:30:00",
    "total_bytes": 524288000,
    "bytes_sent": 104857600,
    "bytes_received": 419430400,
    "packet_count": 35000
  }
]
```

### `GET /api/devices/top`

Top devices by bandwidth usage.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 10 | Number of top devices |

**Response:**
```json
[
  {
    "ip_address": "192.168.1.100",
    "device_name": "John's Laptop",
    "total_bytes": 524288000,
    "total_bytes_formatted": "500.0 MB"
  }
]
```

### `GET /api/devices/<ip_address>`

Get details for a specific device.

**Response:**
```json
{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "ip_address": "192.168.1.100",
  "device_name": "John's Laptop",
  "vendor": "Apple Inc",
  "total_bytes": 524288000,
  "packet_count": 35000,
  "protocols": ["HTTPS", "DNS", "HTTP"],
  "today_bytes": 104857600
}
```

### `POST /api/devices/update-name`

Rename a device.

**Request:**
```json
{
  "ip_address": "192.168.1.100",
  "name": "John's Laptop"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Device name updated"
}
```

---

## Alerts

### `GET /api/alerts`

List alerts.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max alerts to return |
| `severity` | string | all | Filter: `warning`, `critical` |
| `resolved` | bool | all | Filter by resolution state |

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2026-02-06T10:25:00",
    "alert_type": "bandwidth",
    "severity": "warning",
    "message": "High bandwidth usage: 15.2 Mbps",
    "acknowledged": false,
    "resolved": false
  }
]
```

### `GET /api/alerts/summary`

Alert summary counts.

**Response:**
```json
{
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
```

### `GET /api/alerts/stats`

Detailed alert statistics.

**Response:**
```json
{
  "total_24h": 15,
  "by_type": {
    "bandwidth": 8,
    "anomaly": 4,
    "device_count": 2,
    "health": 1
  },
  "unresolved": 3,
  "avg_resolution_time_minutes": 45
}
```

### `GET /api/alerts/recent`

Recent alerts feed.

### `POST /api/alerts`

Create a new alert manually.

**Request:**
```json
{
  "alert_type": "custom",
  "severity": "warning",
  "message": "Manual alert message"
}
```

**Response:**
```json
{
  "success": true,
  "alert_id": 42
}
```

### `POST /api/alerts/<id>/acknowledge`

Acknowledge an alert.

**Response:**
```json
{
  "success": true,
  "message": "Alert acknowledged"
}
```

### `POST /api/alerts/<id>/resolve`

Resolve an alert.

**Response:**
```json
{
  "success": true,
  "message": "Alert resolved"
}
```

---

## Bandwidth & Traffic

### `GET /api/bandwidth/history`

Historical bandwidth data.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 24 | Hours of history |
| `interval` | int | 60 | Aggregation interval (seconds) |

**Response:**
```json
[
  {
    "timestamp": "2026-02-06T09:00:00",
    "bandwidth_bps": 5242880,
    "bandwidth_mbps": 5.0
  }
]
```

### `GET /api/bandwidth/dual`

Upload/download bandwidth split.

**Response:**
```json
{
  "upload_mbps": 2.5,
  "download_mbps": 10.0,
  "total_mbps": 12.5,
  "history": [
    {
      "timestamp": "2026-02-06T10:29:00",
      "upload_mbps": 2.3,
      "download_mbps": 9.8
    }
  ]
}
```

### `GET /api/protocols`

Protocol distribution.

**Response:**
```json
[
  {"protocol": "HTTPS", "bytes": 419430400, "percentage": 80.0},
  {"protocol": "DNS", "bytes": 52428800, "percentage": 10.0},
  {"protocol": "HTTP", "bytes": 26214400, "percentage": 5.0},
  {"protocol": "Other", "bytes": 26214400, "percentage": 5.0}
]
```

### `GET /api/traffic`

Traffic summary data.

### `GET /api/activity`

Recent network activity feed.

---

## Interface Management

### `GET /api/interface/status`

Current network interface and mode.

**Response:**
```json
{
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
```

### `POST /api/interface/refresh`

Force re-detection of network mode.

**Response:**
```json
{
  "success": true,
  "mode": "public_network",
  "interface": "Wi-Fi"
}
```

### `GET /api/interface/list`

List all available network interfaces.

**Response:**
```json
[
  {
    "name": "Wi-Fi",
    "type": "wifi",
    "ip_address": "192.168.1.50",
    "is_active": true
  },
  {
    "name": "Ethernet",
    "type": "ethernet",
    "ip_address": null,
    "is_active": false
  }
]
```

### `POST /api/interface/select`

Select a specific network interface.

**Request:**
```json
{
  "interface": "Ethernet"
}
```

---

## Network Discovery

### `GET /api/discovery/devices`

Devices found by active/passive discovery.

### `POST /api/discovery/scan`

Trigger an active network scan (ARP).

### `GET /api/discovery/capabilities`

Current discovery capabilities based on mode.

### `GET /api/discovery/port-mirror-status`

Port mirror detection status.

---

## Metrics

### `GET /api/metrics`

Application performance metrics.

**Response:**
```json
{
  "packets_processed": 150000,
  "packets_per_second": 850,
  "queue_size": 42,
  "queue_max": 10000,
  "db_queries_count": 5000,
  "uptime_seconds": 18900,
  "memory_mb": 125.4
}
```

---

## Error Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | Success | Request completed |
| 400 | Bad Request | Invalid JSON or missing fields |
| 404 | Not Found | Unknown endpoint or device |
| 405 | Method Not Allowed | Wrong HTTP method |
| 500 | Server Error | Internal error (check logs) |

### Error Response Format

```json
{
  "error": "Not Found",
  "message": "Device with IP 10.0.0.1 not found",
  "status": 404
}
```

---

## Configuration Reference (Phase 3)

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
