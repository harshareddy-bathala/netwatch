# NetWatch System Architecture

This document describes the architecture of the NetWatch network traffic analysis system.

## Table of Contents

1. [Overview](#overview)
2. [System Diagram](#system-diagram)
3. [Components](#components)
4. [Data Flow](#data-flow)
5. [Technology Stack](#technology-stack)
6. [Threading Model](#threading-model)

---

## Overview

NetWatch is a monolithic application that runs entirely on a single machine. It consists of five main components that work together to capture, store, analyze, and visualize network traffic data.

**Design Principles:**
- **Local-only:** No cloud dependencies, no external services
- **Real-time:** Data flows from capture to display in under 3 seconds
- **Modular:** Each component has clear responsibilities and interfaces
- **Simple:** Uses SQLite for storage, Flask for API, vanilla JavaScript for frontend

---

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              NETWATCH SYSTEM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐                                                       │
│  │  NETWORK         │                                                       │
│  │  INTERFACE       │                                                       │
│  │  (eth0/wlan0)    │                                                       │
│  └────────┬─────────┘                                                       │
│           │ Raw Packets                                                     │
│           ▼                                                                 │
│  ┌──────────────────────────────────────────┐                              │
│  │         PACKET CAPTURE MODULE            │ ◄── Thread 1                 │
│  │  ┌──────────┐  ┌──────────┐  ┌────────┐ │                              │
│  │  │ monitor  │→ │ parser   │→ │protocol│ │                              │
│  │  │ (Scapy)  │  │          │  │detector│ │                              │
│  │  └──────────┘  └──────────┘  └────────┘ │                              │
│  └────────────────────┬─────────────────────┘                              │
│                       │ Parsed Packet Dict                                  │
│                       ▼                                                     │
│  ┌──────────────────────────────────────────┐                              │
│  │           DATABASE MODULE                │                              │
│  │  ┌──────────────────────────────────┐   │                              │
│  │  │         db_handler.py            │   │                              │
│  │  │  • save_packet()                 │   │                              │
│  │  │  • get_top_devices()             │   │                              │
│  │  │  • get_bandwidth_history()       │   │                              │
│  │  │  • get_protocol_distribution()   │   │                              │
│  │  │  • get_realtime_stats()          │   │                              │
│  │  │  • get_health_score()            │   │                              │
│  │  │  • create_alert()                │   │                              │
│  │  │  • get_alerts()                  │   │                              │
│  │  └──────────────────────────────────┘   │                              │
│  │                    │                     │                              │
│  │                    ▼                     │                              │
│  │  ┌──────────────────────────────────┐   │                              │
│  │  │         netwatch.db              │   │                              │
│  │  │  ┌─────────┐ ┌─────────────────┐│   │                              │
│  │  │  │ devices │ │ traffic_summary ││   │                              │
│  │  │  └─────────┘ └─────────────────┘│   │                              │
│  │  │  ┌─────────┐                    │   │                              │
│  │  │  │ alerts  │                    │   │                              │
│  │  │  └─────────┘                    │   │                              │
│  │  └──────────────────────────────────┘   │                              │
│  └────────────────────┬─────────────────────┘                              │
│                       │                                                     │
│        ┌──────────────┴──────────────┐                                     │
│        │                             │                                     │
│        ▼                             ▼                                     │
│  ┌─────────────────────┐   ┌─────────────────────┐                        │
│  │   ALERTS MODULE     │   │   BACKEND MODULE    │                        │
│  │   ◄── Thread 2      │   │   ◄── Main Thread   │                        │
│  │                     │   │                     │                        │
│  │  ┌───────────────┐  │   │  ┌───────────────┐  │                        │
│  │  │ detector.py   │  │   │  │ Flask App     │  │                        │
│  │  │ (IsolationFor │  │   │  │ Port 5000     │  │                        │
│  │  │  est ML)      │  │   │  └───────────────┘  │                        │
│  │  └───────────────┘  │   │         │          │                        │
│  │         │           │   │         │ REST API │                        │
│  │         ▼           │   │         ▼          │                        │
│  │  ┌───────────────┐  │   │  ┌───────────────┐  │                        │
│  │  │alert_manager  │──┼───┼─▶│ blueprints/   │  │                        │
│  │  └───────────────┘  │   │  └───────────────┘  │                        │
│  └─────────────────────┘   └──────────┬──────────┘                        │
│                                       │ JSON                              │
│                                       ▼                                   │
│  ┌──────────────────────────────────────────────────────────────┐        │
│  │                    FRONTEND MODULE                            │        │
│  │  ┌─────────────────────────────────────────────────────────┐ │        │
│  │  │                     Browser                              │ │        │
│  │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐        │ │        │
│  │  │  │ index.html │  │devices.html│  │alerts.html │        │ │        │
│  │  │  │ Dashboard  │  │ Device List│  │ Alert Feed │        │ │        │
│  │  │  └────────────┘  └────────────┘  └────────────┘        │ │        │
│  │  │                                                         │ │        │
│  │  │  ┌─────────────────────────────────────────────────┐   │ │        │
│  │  │  │ JavaScript: api.js, charts.js, dashboard.js     │   │ │        │
│  │  │  │ • fetch() every 3 seconds                        │   │ │        │
│  │  │  │ • Chart.js for visualizations                    │   │ │        │
│  │  │  │ • Bootstrap 5 for layout                         │   │ │        │
│  │  │  └─────────────────────────────────────────────────┘   │ │        │
│  │  └─────────────────────────────────────────────────────────┘ │        │
│  └──────────────────────────────────────────────────────────────┘        │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Packet Capture Module (`packet_capture/`)

**Purpose:** Capture and parse network packets from the network interface.

| File | Responsibility |
|------|---------------|
| `monitor.py` | Main capture engine using Scapy, runs in background thread |
| `parser.py` | Extracts fields from raw packets (IPs, ports, size) |
| `protocols.py` | Maps port numbers to protocol names (HTTP, DNS, etc.) |

**Input:** Raw network packets from interface  
**Output:** Python dictionaries with parsed packet data

### 2. Database Module (`database/`)

**Purpose:** Store and retrieve all data using SQLite.

| File | Responsibility |
|------|---------------|
| `schema.sql` | Table definitions (devices, traffic_summary, alerts) |
| `init_db.py` | Creates database file and tables |
| `db_handler.py` | All CRUD operations, aggregations, statistics |

**Input:** Packet dictionaries, alert data  
**Output:** Query results as Python lists/dicts

### 3. Alerts Module (`alerts/`)

**Purpose:** Detect anomalies and create alerts.

| File | Responsibility |
|------|---------------|
| `detector.py` | ML-based anomaly detection using Isolation Forest |
| `alert_manager.py` | Alert creation, severity levels, deduplication |

**Input:** Bandwidth/traffic data from database  
**Output:** Alert records saved to database

### 4. Backend Module (`backend/`)

**Purpose:** REST API for frontend data access.

| File | Responsibility |
|------|---------------|
| `app.py` | Flask application factory, CORS setup |
| `blueprints/` | Modular API endpoint definitions (bandwidth, devices, alerts, system, discovery, export, interface) |

**Input:** HTTP requests from frontend  
**Output:** JSON responses

### 5. Frontend Module (`frontend/`)

**Purpose:** Web dashboard for visualization.

| File | Responsibility |
|------|---------------|
| `index.html` | Single-page application shell |
| `css/` | Modular CSS (variables, layout, components) |
| `js/app.js` | Main application, SSE, routing |
| `js/store.js` | Reactive state management |
| `js/components/` | Dashboard, devices, alerts, bandwidth views |

**Input:** JSON data from API  
**Output:** Visual dashboard in browser

---

## Data Flow

### Packet Capture Flow

```
1. Network Interface captures packet
2. Scapy sniff() receives packet
3. parser.py extracts: src_ip, dst_ip, ports, size, timestamp
4. protocols.py detects: HTTP, HTTPS, DNS, etc.
5. db_handler.save_packet() stores in traffic_summary
6. db_handler updates devices table
```

### Dashboard Refresh Flow

```
1. JavaScript setInterval() triggers every 3 seconds
2. api.js calls GET /api/stats/realtime
3. Flask blueprint handler receives request
4. db_handler.get_realtime_stats() queries database
5. JSON response returned to frontend
6. dashboard.js updates DOM and charts
```

### Anomaly Detection Flow

```
1. Detector thread wakes up every 60 seconds
2. Queries bandwidth history from database
3. Isolation Forest model predicts anomalies
4. If anomaly detected, alert_manager.create_alert()
5. Alert stored in database
6. Frontend polls /api/alerts and displays
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Packet Capture | Scapy 2.5 | Raw packet sniffing |
| Web Framework | Flask 3.0 | REST API |
| Database | SQLite 3 | Local data storage |
| ML | scikit-learn | Anomaly detection |
| Frontend | HTML5/CSS3/JS | User interface |
| UI Framework | Bootstrap 5 | Responsive layout |
| Charts | Chart.js | Data visualization |

---

## Threading Model

NetWatch uses three threads:

| Thread | Component | Purpose |
|--------|-----------|---------|
| Main Thread | Flask Server | Handles HTTP requests |
| Thread 1 | Packet Capture | Runs Scapy sniff loop |
| Thread 2 | Anomaly Detector | Periodic ML analysis |

```python
# Simplified thread structure in main.py
def main():
    # Thread 1: Packet capture
    capture_thread = Thread(target=network_monitor.start, daemon=True)
    capture_thread.start()
    
    # Thread 2: Anomaly detection
    detector_thread = Thread(target=anomaly_detector.run, daemon=True)
    detector_thread.start()
    
    # Main thread: Flask server
    app.run(host='0.0.0.0', port=5000)
```

**Note:** Threads are daemon threads, so they stop when the main program exits.

---

## Database Schema

```sql
-- Stores known network devices
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,
    hostname TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    total_bytes INTEGER
);

-- Stores every captured packet summary
CREATE TABLE traffic_summary (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP,
    source_ip TEXT,
    dest_ip TEXT,
    protocol TEXT,
    bytes_transferred INTEGER
);

-- Stores system alerts
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP,
    alert_type TEXT,
    severity TEXT,
    message TEXT,
    resolved BOOLEAN
);
```

---

## Monitoring Modes & Network Topology

### Understanding Traffic Visibility

NetWatch's ability to capture traffic depends on **network topology** and **connection type**. This section explains why you might not see all devices and how to configure for full visibility.

### Automatic Mode Detection

NetWatch automatically detects your connection type using `InterfaceDetector`:

```python
from packet_capture.monitor import get_interface_detector

detector = get_interface_detector()
print(f"Mode: {detector.detected_mode}")
print(f"Interface: {detector.detected_interface}")
print(f"Description: {detector.interface_description}")
```

### Monitoring Modes

| Mode | Connection Type | Visibility | Use Case |
|------|----------------|------------|----------|
| `ETHERNET` | Wired connection | Own + broadcasts | Office networks |
| `WIFI_CLIENT` | Connected TO WiFi | Own device only | Personal monitoring |
| `WIFI_HOTSPOT` | Laptop IS hotspot | All connected devices | Full network monitoring |
| `VIRTUAL` | VPN/Docker/VM | Virtual network only | Development/testing |
| `LOOPBACK` | 127.0.0.1 | Local only | Not useful for monitoring |

### Mode 1: WiFi Client Mode ⚠️ Limited

**When It Happens:**
```
You → WiFi Router → Internet
```

**What You See:**
- ✅ Your laptop's traffic (outgoing/incoming)
- ✅ Broadcast packets (ARP, mDNS, DHCP)
- ❌ Other clients' traffic (phones, tablets, etc.)

**Why Limited:**
WiFi Access Points implement **client isolation** for security. Each client can only see:
1. Packets sent TO the AP
2. Packets received FROM the AP
3. Broadcast/multicast packets

This prevents WiFi clients from sniffing each other's traffic.

**Network Diagram:**
```
Phone           Tablet          Laptop (NetWatch)
  │               │                  │
  └───────────────┴──────────────────┘
                  │
           [WiFi Router/AP]
                  │
              Internet

• Phone ↔ Router ↔ Internet:  ❌ Laptop cannot see
• Tablet ↔ Router ↔ Internet: ❌ Laptop cannot see
• Laptop ↔ Router ↔ Internet: ✅ Laptop can see
```

**UI Warning:**
Dashboard displays:
> ⚠️ WiFi Client Mode: Monitoring limited to this device only. Other devices on the network are not visible.

---

### Mode 2: WiFi Hotspot Mode ✅ Full Visibility

**When It Happens:**
```
Other Devices → Your Laptop (Hotspot) → Internet
```

**What You See:**
- ✅ ALL traffic from connected devices
- ✅ Complete packet visibility
- ✅ Real-time per-device bandwidth

**How to Enable:**

**Windows:**
1. Settings → Network & Internet → Mobile Hotspot
2. Share: WiFi or Ethernet connection
3. Turn on Mobile Hotspot
4. Other devices connect to your laptop

**macOS:**
1. System Preferences → Sharing
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
  │               │                │
  └───────────────┴────────────────┘
                  │
      [Laptop (NetWatch Hotspot)]
                  │
            [Router/Internet]

• Phone ↔ Laptop ↔ Internet:   ✅ Laptop sees everything
• Tablet ↔ Laptop ↔ Internet:  ✅ Laptop sees everything
• Smart TV ↔ Laptop ↔ Internet: ✅ Laptop sees everything
```

**Technical Details:**
- Laptop acts as Layer 2 bridge
- All packets pass through laptop's interface
- NetWatch captures before forwarding
- Enables full packet inspection

---

### Mode 3: Ethernet ⚠️ Switch-Dependent

**When It Happens:**
```
You → Switch → Router → Internet
```

**What You See:**
- ✅ Your laptop's traffic
- ✅ Broadcast/multicast traffic
- ⚠️ Other devices (depends on switch configuration)

**Modern Switches:**
Modern managed switches use **port isolation**:
- Each port is a separate collision domain
- Unicast traffic only goes to destination port
- You only see: your traffic + broadcasts

**Legacy Hubs:**
Old hubs broadcast all traffic to all ports:
- You can see all devices
- Rare in modern networks

**Network Diagram (Switch with Port Isolation):**
```
Port 1: Desktop    Port 2: Laptop (NetWatch)    Port 3: Server
    │                      │                         │
    └──────────────────────┴─────────────────────────┘
                           │
                      [Managed Switch]
                           │
                       [Router]

• Desktop ↔ Server:    ❌ Laptop cannot see (unicast)
• Desktop ↔ Router:    ❌ Laptop cannot see
• Laptop ↔ Anywhere:   ✅ Laptop can see
• Broadcast (DHCP):    ✅ All ports see
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
        │                                │
        └────────[Mirrored]─────────────┘
                    │
             [Managed Switch]
                    │
                [Router]

• All traffic from ports 1-10:  ✅ Mirrored to port 24
• Laptop sees everything:        ✅ Full visibility
```

---

### Mode 4: Mobile Hotspot (Phone as AP) ⚠️ Limited

**When It Happens:**
```
Your Laptop → Phone's Hotspot → Cell Tower → Internet
```

**What You See:**
- ✅ Laptop's internet traffic
- ❌ Phone's own traffic (YouTube, apps, etc.)

**Why Phone's Traffic Is Invisible:**

The phone has TWO network paths:

**Path 1: Laptop's Traffic**
```
Laptop → WiFi → Phone's Hotspot Interface → Cell Modem → Internet
✅ Visible to laptop (passes through phone's WiFi interface)
```

**Path 2: Phone's Own Traffic**
```
Phone Apps → Cell Modem → Internet
❌ Not visible to laptop (doesn't pass through WiFi interface)
```

**Network Diagram:**
```
                    [Phone]
                   /      \
          WiFi Interface  Cell Modem
                 /            \
            [Laptop]       [Cell Tower]
                               |
                          [Internet]

Laptop traffic:  Laptop → WiFi → Phone → Cell → Internet  ✅
Phone traffic:   Phone → Cell → Internet                  ❌
```

**Technical Explanation:**
- Phone's WiFi interface and cellular modem are separate
- Hotspot bridges WiFi → Cellular
- Phone's own apps use cellular modem directly
- Laptop's interface never sees phone's app traffic

**Solution:**
Reverse the setup:
1. Enable hotspot ON LAPTOP
2. Connect phone TO laptop's hotspot
3. Now phone's traffic goes through laptop

---

### Implementation Details

#### InterfaceDetector Class

```python
class InterfaceDetector:
    """Automatically detects connection type and monitoring capabilities."""
    
    def detect_mode(self) -> MonitoringMode:
        """
        Determines monitoring mode based on interface characteristics.
        
        Detection Logic:
        1. Check if interface name contains 'hotspot', 'ap', or 'mobile'
        2. Check if interface is sharing internet (ICS on Windows)
        3. Check if interface has connected clients
        4. Fallback to connection type (WiFi vs Ethernet)
        """
        if self._is_hotspot_mode():
            return MonitoringMode.WIFI_HOTSPOT
        elif self._is_wifi_interface():
            return MonitoringMode.WIFI_CLIENT
        elif self._is_ethernet_interface():
            return MonitoringMode.ETHERNET
        elif self._is_virtual_interface():
            return MonitoringMode.VIRTUAL
        else:
            return MonitoringMode.LOOPBACK
```

#### Status API Response

```json
{
  "interface": "wlan0",
  "monitoring_mode": "WIFI_CLIENT",
  "monitoring_scope": "This device only",
  "is_full_network_mode": false,
  "warning": "⚠️ WiFi Client Mode: Monitoring limited to this device only. Other devices on the network are not visible.",
  "description": "WiFi client connected to external network"
}
```

#### Frontend Warning Display

```javascript
// dashboard.js
if (status.warning) {
    const warningDiv = document.getElementById('monitoring-warning');
    warningDiv.innerHTML = status.warning;
    warningDiv.style.display = 'block';
}
```

---

### Limitations by Mode

| Limitation | WiFi Client | WiFi Hotspot | Ethernet | Mobile Hotspot |
|------------|-------------|--------------|----------|----------------|
| See other devices | ❌ | ✅ | ⚠️ | ❌ |
| Full bandwidth visibility | ❌ | ✅ | ⚠️ | ❌ |
| Monitor phone's traffic | ❌ | ✅ | N/A | ❌ |
| Production ready | ✅ (self) | ✅ (all) | ⚠️ | ✅ (self) |

---

### Recommended Setups

| Goal | Recommended Mode | Setup |
|------|------------------|-------|
| Monitor own laptop | WiFi Client / Ethernet | Any connection |
| Monitor home devices | WiFi Hotspot | Enable hotspot on laptop |
| Monitor office network | Ethernet + SPAN | Port mirroring |
| Monitor classroom | WiFi Hotspot | Laptop as access point |

---

## Security Considerations

1. **Root/Admin Required:** Packet capture requires elevated privileges
2. **Local Only:** No external network access needed
3. **No Authentication:** Designed for trusted local network
4. **CORS Enabled:** For development; restrict in production
