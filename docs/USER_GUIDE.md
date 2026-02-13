# NetWatch User Guide

## Getting Started

### Launching NetWatch

1. Open a terminal **as Administrator** (Windows) or with `sudo` (Linux/macOS)
2. Run: `python main.py`
3. Open your browser: **http://localhost:5000**

### First-Time Setup

On first launch, NetWatch will:
1. Create the database
2. Detect your network interface and mode
3. Start capturing packets
4. Begin building traffic statistics

Give it 30-60 seconds to populate initial data.

---

## Dashboard Overview

The main dashboard shows a real-time view of your network:

### Stats Cards (Top Row)
- **Active Devices** — Number of currently active network devices
- **Total Bandwidth** — Current network throughput (upload + download)
- **Health Score** — Overall network health (0-100)
- **Active Alerts** — Number of unresolved alerts

### Bandwidth Chart
- Real-time upload/download bandwidth over time
- Blue line = download, green line = upload
- Updates every 3 seconds

### Device List
- Shows all detected network devices
- Sortable by bandwidth, last seen, or name
- Click a device for detailed stats

### Protocol Distribution
- Pie chart showing traffic by protocol (HTTP, HTTPS, DNS, etc.)
- Helps identify unusual protocol usage

### Alert Feed
- Recent alerts sorted by time
- Color-coded by severity (warning, critical)
- Click to acknowledge or resolve

---

## Understanding Network Modes

NetWatch automatically detects how your computer connects to the network:

### Hotspot Mode
- **When:** Your computer is sharing its internet (mobile hotspot)
- **What you see:** All devices connected to YOUR hotspot
- **Device count:** Only phones/tablets/laptops connected to your hotspot
- **Bandwidth:** Traffic from each connected device

### WiFi Client Mode
- **When:** Your computer is connected to a WiFi network
- **What you see:** Only YOUR device's traffic
- **Device count:** 1 (yourself) + gateway router
- **Bandwidth:** Your own upload/download

### Ethernet Mode
- **When:** Your computer is connected via Ethernet cable
- **What you see:** Local network devices (via ARP)
- **Device count:** Devices on your local subnet
- **Bandwidth:** Local network traffic

### Public Network / Safe Mode
- **When:** Connected to a public WiFi (café, airport)
- **What NetWatch does:** Restricts to own traffic only, no promiscuous mode
- **Device count:** 1 (yourself)
- **Why:** Privacy and safety on untrusted networks

### Port Mirror Mode
- **When:** Connected to a managed switch with port mirroring/SPAN
- **What you see:** All traffic on the mirrored port
- **Device count:** Many devices (entire network segment)
- **Bandwidth:** Aggregate network traffic

---

## Managing Alerts

### Alert Types

| Type | Meaning |
|------|---------|
| **Bandwidth Warning** | Traffic exceeds 10 Mbps |
| **Bandwidth Critical** | Traffic exceeds 50 Mbps |
| **Device Count** | Unusual number of devices |
| **Anomaly** | ML model detected unusual patterns |
| **Health Score** | Network health below threshold |

### Alert Actions

1. **Acknowledge** — Mark as "seen" (reduces badge count)
   - Click the alert → "Acknowledge" button
   - Or: `POST /api/alerts/{id}/acknowledge`

2. **Resolve** — Mark as "fixed" (removes from active list)
   - Click the alert → "Resolve" button
   - Or: `POST /api/alerts/{id}/resolve`

### Alert Deduplication
- Same alert type won't repeat within 5 minutes
- Prevents alert fatigue during sustained issues

---

## Working with Devices

### Device Information
Each detected device shows:
- **IP Address** — Network address
- **MAC Address** — Hardware address
- **Vendor** — Device manufacturer (from MAC lookup)
- **Bandwidth** — Current and total traffic
- **Last Seen** — When the device was last active

### Renaming Devices
1. Click a device in the device list
2. Click the name to edit
3. Enter a friendly name (e.g., "John's Phone")
4. The name persists across sessions

### Device Discovery
- **Passive:** Devices seen from packet traffic
- **Active:** ARP scan (Ethernet/Hotspot modes)
- Trigger a scan: `POST /api/discovery/scan`

---

## Interpreting Bandwidth Charts

### Reading the Chart
- **X-axis:** Time (scrolling window)
- **Y-axis:** Bandwidth in Mbps
- **Blue area:** Download traffic
- **Green area:** Upload traffic

### Normal Patterns
- Web browsing: ~1-5 Mbps download, 0.1-1 Mbps upload
- Video streaming: ~5-25 Mbps download
- File upload: ~1-10 Mbps upload spikes
- Idle: <0.1 Mbps

### Warning Signs
- Sustained high upload: Possible data exfiltration
- Steady high bandwidth with no user activity: Malware or updates
- Unusual protocol distribution: Possible compromise

---

## Interpreting Health Score

### Score Ranges

| Score | Status | Color | Meaning |
|-------|--------|-------|---------|
| 80-100 | Good | Green | Network is healthy |
| 50-79 | Warning | Yellow | Some concerns |
| 0-49 | Critical | Red | Immediate attention needed |

### Health Factors
The health score considers:
- **Bandwidth** (30%) — Is traffic within normal range?
- **Packet Loss** (25%) — Are packets being dropped?
- **Latency** (25%) — Are response times normal?
- **Anomalies** (20%) — Any unusual patterns detected?

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `D` | Navigate to Dashboard |
| `V` | Navigate to Devices |
| `A` | Navigate to Alerts |
| `R` | Refresh data |

---

## Command Line Options

```
python main.py [options]

Options:
  --port PORT       Use custom port (default: 5000)
  --host HOST       Bind to specific host (default: 127.0.0.1)
  --reset-db        Clear all data and start fresh
  --no-capture      Start without packet capture (dashboard only)
  --log-level LEVEL Set log level (DEBUG, INFO, WARNING, ERROR)
  --log-file PATH   Log to file
```

---

## Tips & Best Practices

1. **Run as Administrator** — Always. Packet capture requires it.
2. **Use --reset-db** after changing network modes for a clean start.
3. **Check the mode** — Verify the detected mode matches your setup.
4. **Don't panic at alerts** — The ML model needs time to learn your baseline.
5. **Name your devices** — Makes the dashboard much more useful.
6. **Regular cleanup** — Old data is automatically cleaned (7-day retention).

---

## FAQ

**Q: Why do I see only 1 device in WiFi client mode?**
A: WiFi client mode can only capture your own traffic. This is normal. To see other devices, use Hotspot or Ethernet mode.

**Q: Why is the bandwidth shown different from my speed test?**
A: NetWatch measures actual traffic, not your connection speed. Speed tests saturate the connection; normal browsing uses much less.

**Q: Can I use NetWatch on multiple computers?**
A: Yes, install on each computer. Each instance monitors its own network perspective.

**Q: Does NetWatch work over VPN?**
A: Yes, but it will show VPN tunnel traffic as a single flow to the VPN server. Individual sites won't be visible.

**Q: How long is data retained?**
A: Traffic data: 24 hours. Alerts: 7 days. Both configurable in config.py.
