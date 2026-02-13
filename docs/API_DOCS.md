# NetWatch REST API Documentation

This document describes all REST API endpoints provided by the NetWatch backend.

## Table of Contents

1. [Overview](#overview)
2. [Base URL](#base-url)
3. [Response Format](#response-format)
4. [Endpoints](#endpoints)
   - [System Status](#system-status)
   - [Real-time Statistics](#real-time-statistics)
   - [Top Devices](#top-devices)
   - [Protocol Distribution](#protocol-distribution)
   - [Bandwidth History](#bandwidth-history)
   - [Alerts](#alerts)
   - [Health Score](#health-score)
   - [Update Device Name](#update-device-name)
   - [Network Discovery (NEW)](#network-discovery-new)
5. [Error Handling](#error-handling)

---

## Overview

The NetWatch API is a RESTful JSON API that provides access to network traffic data, device information, and system alerts. All endpoints return JSON responses.

**Key Features:**
- All responses are JSON
- GET requests for reading data
- POST requests for modifications
- Query parameters for filtering
- Consistent error format

---

## Base URL

```
http://localhost:5000/api
```

All endpoints are prefixed with `/api`.

---

## Response Format

### Success Response

```json
{
    "field1": "value1",
    "field2": "value2"
}
```

### Error Response

```json
{
    "error": "Error message description",
    "code": 404
}
```

---

## Endpoints

### System Status

Returns the current system status and version information.

**Endpoint:** `GET /api/status`

**Parameters:** None

**Response:**

```json
{
    "status": "running",
    "uptime": 3600,
    "version": "1.0.0",
    "capture_active": true,
    "database_connected": true
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| status | string | "running" or "stopped" |
| uptime | integer | Seconds since start |
| version | string | Application version |
| capture_active | boolean | Is packet capture running |
| database_connected | boolean | Is database accessible |

**Example:**

```bash
curl http://localhost:5000/api/status
```

---

### Real-time Statistics

Returns current network statistics calculated from recent traffic.

**Endpoint:** `GET /api/stats/realtime`

**Parameters:** None

**Response:**

```json
{
    "bandwidth_bps": 1234567,
    "bandwidth_formatted": "1.23 MB/s",
    "active_devices": 42,
    "packets_per_second": 156,
    "timestamp": "2026-02-01T14:30:00Z"
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| bandwidth_bps | integer | Current bandwidth in bytes per second |
| bandwidth_formatted | string | Human-readable bandwidth |
| active_devices | integer | Devices seen in last 5 minutes |
| packets_per_second | integer | Current packet rate |
| timestamp | string | ISO 8601 timestamp |

**Example:**

```bash
curl http://localhost:5000/api/stats/realtime
```

---

### Top Devices

Returns the devices consuming the most bandwidth.

**Endpoint:** `GET /api/devices/top`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 10 | Number of devices to return (1-100) |
| hours | integer | 1 | Time window in hours |

**Response:**

```json
{
    "devices": [
        {
            "ip_address": "192.168.1.105",
            "hostname": "Johns-MacBook",
            "total_bytes": 524288000,
            "total_bytes_formatted": "500 MB",
            "first_seen": "2026-02-01T08:00:00Z",
            "last_seen": "2026-02-01T14:30:00Z",
            "is_active": true
        },
        {
            "ip_address": "192.168.1.42",
            "hostname": null,
            "total_bytes": 104857600,
            "total_bytes_formatted": "100 MB",
            "first_seen": "2026-02-01T10:15:00Z",
            "last_seen": "2026-02-01T14:28:00Z",
            "is_active": true
        }
    ],
    "count": 2,
    "time_window_hours": 1
}
```

**Example:**

```bash
# Get top 5 devices from last 24 hours
curl "http://localhost:5000/api/devices/top?limit=5&hours=24"
```

---

### Protocol Distribution

Returns the distribution of network protocols.

**Endpoint:** `GET /api/protocols`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| hours | integer | 1 | Time window in hours |

**Response:**

```json
{
    "protocols": [
        {
            "name": "HTTPS",
            "count": 15000,
            "bytes": 52428800,
            "percentage": 45.5
        },
        {
            "name": "HTTP",
            "count": 8000,
            "bytes": 20971520,
            "percentage": 24.2
        },
        {
            "name": "DNS",
            "count": 5000,
            "bytes": 512000,
            "percentage": 15.1
        },
        {
            "name": "TCP",
            "count": 3000,
            "bytes": 10485760,
            "percentage": 9.1
        },
        {
            "name": "UDP",
            "count": 2000,
            "bytes": 2097152,
            "percentage": 6.1
        }
    ],
    "total_packets": 33000,
    "total_bytes": 86495232,
    "time_window_hours": 1
}
```

**Example:**

```bash
curl "http://localhost:5000/api/protocols?hours=24"
```

---

### Bandwidth History

Returns bandwidth measurements over time for charting.

**Endpoint:** `GET /api/bandwidth/history`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| hours | integer | 1 | Time window (1, 6, 12, 24) |

**Response:**

```json
{
    "history": [
        {
            "timestamp": "2026-02-01T14:00:00Z",
            "bytes_per_second": 1234567,
            "formatted": "1.23 MB/s"
        },
        {
            "timestamp": "2026-02-01T14:01:00Z",
            "bytes_per_second": 1345678,
            "formatted": "1.35 MB/s"
        }
    ],
    "interval_seconds": 60,
    "time_window_hours": 1
}
```

**Notes:**
- Data is aggregated per minute for hours=1
- Data is aggregated per 5 minutes for hours=6 or more
- Maximum 500 data points returned

**Example:**

```bash
curl "http://localhost:5000/api/bandwidth/history?hours=6"
```

---

### Alerts

Returns system alerts with optional filtering.

**Endpoint:** `GET /api/alerts`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | integer | 50 | Maximum alerts to return |
| severity | string | null | Filter: "info", "warning", "critical" |
| resolved | boolean | null | Filter by resolved status |

**Response:**

```json
{
    "alerts": [
        {
            "id": 42,
            "timestamp": "2026-02-01T14:25:00Z",
            "alert_type": "bandwidth",
            "severity": "warning",
            "message": "High bandwidth usage detected: 45 MB/s exceeds threshold of 10 MB/s",
            "resolved": false,
            "resolved_at": null
        },
        {
            "id": 41,
            "timestamp": "2026-02-01T14:10:00Z",
            "alert_type": "anomaly",
            "severity": "critical",
            "message": "Unusual traffic pattern detected by ML model",
            "resolved": true,
            "resolved_at": "2026-02-01T14:20:00Z"
        }
    ],
    "count": 2,
    "unresolved_count": 1
}
```

**Severity Levels:**

| Level | Color | Description |
|-------|-------|-------------|
| info | Green | Informational, no action needed |
| warning | Orange | Attention recommended |
| critical | Red | Immediate attention required |

**Example:**

```bash
# Get only critical alerts
curl "http://localhost:5000/api/alerts?severity=critical&limit=10"
```

---

### Health Score

Returns the calculated network health score.

**Endpoint:** `GET /api/health`

**Parameters:** None

**Response:**

```json
{
    "score": 85,
    "status": "good",
    "factors": {
        "bandwidth_utilization": {
            "value": 0.25,
            "status": "good",
            "weight": 0.3
        },
        "active_alerts": {
            "value": 2,
            "status": "warning",
            "weight": 0.2
        },
        "device_count": {
            "value": 42,
            "status": "good",
            "weight": 0.25
        },
        "packet_loss": {
            "value": 0.01,
            "status": "good",
            "weight": 0.25
        }
    },
    "timestamp": "2026-02-01T14:30:00Z"
}
```

**Status Thresholds:**

| Score Range | Status |
|-------------|--------|
| 80-100 | good |
| 50-79 | warning |
| 0-49 | critical |

**Example:**

```bash
curl http://localhost:5000/api/health
```

---

### Update Device Name

Updates the hostname for a device.

**Endpoint:** `POST /api/devices/update-name`

**Request Body:**

```json
{
    "ip_address": "192.168.1.105",
    "hostname": "Johns-MacBook-Pro"
}
```

**Response (Success):**

```json
{
    "success": true,
    "message": "Device hostname updated successfully",
    "device": {
        "ip_address": "192.168.1.105",
        "hostname": "Johns-MacBook-Pro"
    }
}
```

**Response (Error - Device not found):**

```json
{
    "success": false,
    "error": "Device not found",
    "code": 404
}
```

**Example:**

```bash
curl -X POST http://localhost:5000/api/devices/update-name \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.105", "hostname": "My-Laptop"}'
```

---

### Network Discovery (NEW)

The discovery endpoints provide advanced network device discovery regardless of connection type.

#### Get Discovered Devices

Returns all devices discovered through network scanning methods (ARP, mDNS, passive analysis).

**Endpoint:** `GET /api/discovery/devices`

**Parameters:** None

**Response:**

```json
{
    "devices": [
        {
            "ip": "192.168.1.1",
            "mac": "AA:BB:CC:DD:EE:FF",
            "hostname": "router.local",
            "vendor": "Cisco Systems",
            "discovery_method": "arp",
            "last_seen": "2024-01-15T10:30:00"
        }
    ],
    "count": 15,
    "network": "192.168.1.0/24",
    "interface": "Wi-Fi",
    "discovery_methods": ["arp", "ping", "mdns", "passive"]
}
```

**Example:**

```bash
curl http://localhost:5000/api/discovery/devices
```

---

#### Trigger Network Scan

Performs an immediate ARP scan to discover devices on the local network. Requires administrator privileges.

**Endpoint:** `POST /api/discovery/scan`

**Parameters:** None

**Response:**

```json
{
    "success": true,
    "devices": [
        {
            "ip": "192.168.1.100",
            "mac": "11:22:33:44:55:66",
            "vendor": "Apple Inc"
        }
    ],
    "count": 8,
    "network": "192.168.1.0/24",
    "interface": "Wi-Fi",
    "scan_type": "arp",
    "message": "Discovered 8 devices"
}
```

**Error Response (No Admin):**

```json
{
    "success": false,
    "error": "Administrator/root privileges required for network scanning",
    "devices": []
}
```

**Example:**

```bash
curl -X POST http://localhost:5000/api/discovery/scan
```

---

#### Get Discovery Capabilities

Returns the current monitoring capabilities based on network connection type.

**Endpoint:** `GET /api/discovery/capabilities`

**Response:**

```json
{
    "mode": "wifi",
    "mode_display": "📶 WiFi Mode (Enhanced Discovery)",
    "interface": "Wi-Fi",
    "ip_address": "192.168.1.50",
    "capabilities": {
        "device_discovery": true,
        "full_traffic_capture": false,
        "promiscuous_mode": true,
        "arp_scanning": true,
        "port_mirror_support": true
    },
    "features": {
        "arp_scanning": true,
        "promiscuous_mode": true,
        "full_traffic_capture": false,
        "device_discovery": true,
        "port_mirror_support": true
    },
    "description": "WiFi adapter connected to network"
}
```

**Example:**

```bash
curl http://localhost:5000/api/discovery/capabilities
```

---

#### Check Port Mirror Status

Analyzes traffic patterns to detect if connected to a port mirror/SPAN port.
Note: Takes 5-10 seconds to analyze traffic patterns.

**Endpoint:** `GET /api/discovery/port-mirror-status`

**Response (Mirror Detected):**

```json
{
    "detected": true,
    "interface": "Ethernet",
    "description": "Port mirror detected: 65.3% foreign traffic from 12 unique MACs",
    "recommendation": "Full network monitoring available - all traffic visible"
}
```

**Response (Normal Connection):**

```json
{
    "detected": false,
    "interface": "Wi-Fi",
    "description": "Normal traffic pattern (5.2% foreign)",
    "recommendation": "Normal connection - use ARP scanning for device discovery"
}
```

**Example:**

```bash
curl http://localhost:5000/api/discovery/port-mirror-status
```

---

## Error Handling

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request (invalid parameters) |
| 404 | Not Found (resource doesn't exist) |
| 500 | Internal Server Error |

### Error Response Format

```json
{
    "error": "Description of what went wrong",
    "code": 400
}
```

### Common Errors

**Invalid Query Parameter:**
```json
{
    "error": "Invalid value for 'hours': must be a positive integer",
    "code": 400
}
```

**Database Error:**
```json
{
    "error": "Database connection failed",
    "code": 500
}
```

---

## CORS

The API has CORS enabled for development. All origins are allowed by default. For production, configure specific allowed origins in `backend/app.py`.

---

## Rate Limiting

Currently, there is no rate limiting. For production use, consider adding rate limiting to prevent abuse.

---

## Testing the API

You can test the API using:

1. **Browser:** Navigate to any GET endpoint
2. **curl:** Command-line HTTP client
3. **Postman:** GUI API testing tool
4. **Python requests:**

```python
import requests

response = requests.get('http://localhost:5000/api/stats/realtime')
data = response.json()
print(data['bandwidth_bps'])
```
