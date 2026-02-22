# NetWatch User Manual

This guide explains how to use the NetWatch dashboard to monitor your network.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Main Dashboard](#main-dashboard)
3. [Devices Page](#devices-page)
4. [Alerts Page](#alerts-page)
5. [Understanding the Data](#understanding-the-data)
6. [Tips and Best Practices](#tips-and-best-practices)

---

## Getting Started

### Accessing the Dashboard

1. Ensure NetWatch is running (see [SETUP_GUIDE.md](SETUP_GUIDE.md))
2. Open a web browser
3. Navigate to: `http://localhost:5000`
4. The dashboard will load automatically

### Supported Browsers

- Google Chrome (recommended)
- Mozilla Firefox
- Microsoft Edge
- Safari

### First-Time Use

When you first access NetWatch:
- Data will be empty for the first few seconds
- Charts will populate as packets are captured
- The health score will calculate after ~1 minute of data

---

## Main Dashboard

The main dashboard (`index.html`) provides a real-time overview of your network.

### Navigation Bar

Located at the top of every page:
- **NetWatch Logo:** Click to return to dashboard
- **Dashboard:** Main overview (current page)
- **Devices:** Full device list
- **Alerts:** Alert feed
- **Status Indicator:** Green dot = healthy, Yellow = warning, Red = critical

### Metric Cards

Four cards at the top showing key statistics:

| Card | Description | Good Value |
|------|-------------|------------|
| **Bandwidth** | Current network bandwidth in MB/s | Varies by network |
| **Active Devices** | Devices seen in last 5 minutes | Depends on network size |
| **Packets/Second** | Packet processing rate | Higher = more traffic |
| **Health Score** | Overall network health (0-100) | 80+ is good |

### Bandwidth Chart

A line chart showing bandwidth over time:
- **X-axis:** Time (HH:MM format)
- **Y-axis:** Bandwidth in MB/s
- **Hover:** Shows exact value at any point
- **Trend:** Watch for unusual spikes

### Protocol Distribution Chart

A pie/doughnut chart showing traffic by protocol:
- **HTTPS:** Secure web traffic (typically largest)
- **HTTP:** Unsecure web traffic
- **DNS:** Domain name lookups
- **SSH:** Secure shell connections
- **Other:** TCP/UDP traffic on non-standard ports

### Top Devices Table

Shows the 10 devices using the most bandwidth:

| Column | Description |
|--------|-------------|
| IP Address | Device's network address |
| Hostname | User-assigned name (click to edit) |
| Bandwidth | Total data transferred |
| Last Seen | When device was last active |

### Auto-Refresh

The dashboard updates automatically every 3 seconds. You'll see:
- "Last updated" timestamp in the footer
- Smooth value transitions in metric cards
- Chart data scrolling left as new data arrives

---

## Devices Page

The devices page (`devices.html`) shows all detected network devices.

### Device List

A complete table of all devices with:
- **IP Address:** Unique network identifier
- **Hostname:** Editable friendly name
- **Total Bandwidth:** All-time data usage
- **First Seen:** When device was first detected
- **Last Seen:** Most recent activity
- **Status:** Active (green) or Inactive (gray)

### Search

Use the search box to filter devices:
- Search by IP address: `192.168.1`
- Search by hostname: `laptop`
- Case-insensitive search

### Sorting

Click column headers to sort:
- Click once for ascending order
- Click again for descending order
- Arrow indicator shows current sort

### Editing Hostnames

Assign friendly names to devices:

1. Click the IP address or hostname
2. Enter a new name in the popup
3. Click "Save"
4. The name persists across restarts

Example names:
- `192.168.1.105` → "Johns-MacBook"
- `192.168.1.42` → "Smart-TV-Living-Room"

### Pagination

For large device lists:
- Use Previous/Next buttons to navigate
- Select items per page (10, 25, 50, 100)
- Current page shown between buttons

---

## Alerts Page

The alerts page (`alerts.html`) shows system notifications.

### Alert Feed

Alerts appear in reverse chronological order (newest first):

Each alert card shows:
- **Color bar:** Severity indicator (left side)
- **Type icon:** What triggered the alert
- **Message:** Description of the issue
- **Timestamp:** When it occurred
- **Resolve button:** Mark as handled

### Severity Levels

| Color | Severity | Meaning |
|-------|----------|---------|
| Green | Info | Informational, no action needed |
| Orange | Warning | Attention recommended |
| Red | Critical | Immediate action required |

### Alert Types

| Type | Description |
|------|-------------|
| Bandwidth | Traffic exceeded threshold |
| Anomaly | ML detected unusual pattern |
| Device Count | Many new devices appeared |
| Health | Health score dropped |

### Filtering Alerts

Use the filter buttons:
- **All:** Show all alerts
- **Info:** Only informational
- **Warning:** Only warnings
- **Critical:** Only critical

### Time Range

Select time window:
- Last hour
- Last 24 hours
- Last 7 days

### Resolving Alerts

To mark an alert as handled:
1. Click the "Resolve" button on the alert
2. Alert moves to resolved state
3. Use "Show resolved" toggle to view

---

## Understanding the Data

### Bandwidth Measurements

Bandwidth is measured in bytes per second and displayed as:
- **B/s:** Bytes per second (small values)
- **KB/s:** Kilobytes per second
- **MB/s:** Megabytes per second
- **GB/s:** Gigabytes per second (rare)

### Health Score

The health score (0-100) is calculated from:

| Factor | Weight | Good Range |
|--------|--------|------------|
| Bandwidth utilization | 30% | < 70% of capacity |
| Active alerts | 20% | 0 critical, < 5 warning |
| Device count | 25% | Within expected range |
| Packet consistency | 25% | No sudden drops |

**Score Interpretation:**
- 80-100: Good (green) - Network is healthy
- 50-79: Warning (yellow) - Some issues
- 0-49: Critical (red) - Immediate attention needed

### Protocol Detection

NetWatch identifies protocols by port number:

| Port | Protocol |
|------|----------|
| 80 | HTTP |
| 443 | HTTPS |
| 22 | SSH |
| 53 | DNS |
| 21 | FTP |
| 25, 587 | SMTP (Email) |

Traffic on unknown ports shows as "TCP" or "UDP".

### Anomaly Detection

The ML-based anomaly detector looks for:
- Sudden bandwidth spikes
- Unusual traffic patterns
- Deviations from normal behavior

It learns your network's normal patterns and alerts when something differs.

---

## Tips and Best Practices

### For Accurate Monitoring

1. **Let it run:** More data = better analysis
2. **Name devices:** Easier to identify traffic sources
3. **Check regularly:** Brief daily reviews catch issues early

### Responding to Alerts

**Bandwidth Warning:**
- Check top devices for heavy users
- Consider if the usage is expected (downloads, updates)
- Investigate if unexpected

**Anomaly Alert:**
- Review the time of the anomaly
- Check which devices were active
- Look for new devices that appeared
- Consider if any legitimate activity could cause it

**Critical Alerts:**
- Act immediately
- Check if network is still functional
- Look for security issues
- Document and escalate if needed

### Optimizing Performance

- Clear old data periodically if database grows large
- Close unused browser tabs (each tab polls the API)
- Consider filtering to specific time ranges for analysis

### Monitoring Modes & Network Visibility

**Understanding What You Can See:**

NetWatch's monitoring capabilities depend on **how your laptop is connected** to the network. The dashboard shows your current monitoring mode:

#### 🌐 WiFi Client Mode (Most Common)
**When:** Your laptop is connected TO a WiFi network

**You Can See:**
- ✅ Your laptop's own traffic only
- ✅ Devices on the network via passive ARP cache reads (no active probing)
- ❌ Other devices' traffic (only your own packets are captured)

**Dashboard Shows:** 
> ⚠️ WiFi Client Mode: Monitoring limited to this device’s traffic.

**Why:** WiFi Access Points isolate clients from each other for security. NetWatch does **not** send active ARP scans in this mode—it only reads the OS’s existing ARP cache to list nearby devices without transmitting any probe packets.

**To Monitor Other Devices’ Traffic:** Enable Mobile Hotspot on your laptop (see below).

---

#### 📡 WiFi Hotspot Mode (Full Monitoring)
**When:** Mobile Hotspot is enabled ON YOUR LAPTOP, other devices connect to it

**You Can See:**
- ✅ ALL devices connected to your hotspot
- ✅ Complete traffic visibility
- ✅ Real-time bandwidth per device

**How to Enable:**
- **Windows:** Settings → Network & Internet → Mobile Hotspot → Turn On
- **macOS:** System Preferences → Sharing → Internet Sharing
- **Linux:** NetworkManager → Create Hotspot

**Best For:** Monitoring family devices, classroom networks, full home monitoring

---

#### 🔌 Ethernet Mode
**When:** Laptop connected via ethernet cable

**You Can See:**
- ✅ Your laptop's traffic
- ✅ Broadcast traffic
- ⚠️ Other devices (depends on switch configuration)

**Note:** Modern switches may isolate traffic between ports. You might only see your own traffic.

---

#### 📱 Mobile Hotspot Scenario (Phone as Hotspot)
**Setup:** Laptop connected TO phone's hotspot

**You Can See:**
- ✅ Laptop's internet usage
- ❌ Phone's own traffic (YouTube, apps, etc.)

**Why:** Phone's traffic goes Phone → Cell Tower directly, not through laptop. This is network topology, not a bug.

**To Monitor Phone:** Enable hotspot ON LAPTOP instead, connect phone to it.

---

### Common Monitoring Questions

**Q: "Why does dashboard show only 1 device (myself)?"**  
A: You're in WiFi Client Mode. Enable Mobile Hotspot on your laptop to monitor other devices.

**Q: "I watched YouTube on my phone but bandwidth didn't increase"**  
A: Your laptop is connected TO the phone's hotspot. Phone's traffic doesn't pass through laptop. Reverse the setup: enable hotspot on laptop, connect phone to it.

**Q: "Can I see what websites other people visit?"**  
A: Only if they're connected to YOUR laptop's hotspot AND the sites use HTTP. HTTPS is encrypted, so you only see destination, not content.

**Q: "Why can't I see smart TV/IoT devices?"**  
A: They're on the same WiFi network but isolated by the Access Point. Enable laptop as hotspot and connect them to it.

---

### Known Limitations

- **WiFi Client Mode:** Only captures own device traffic; discovers neighbors via passive ARP cache only (no active scanning)
- **Public Network Mode:** Own traffic only; passive ARP cache reads allowed but no active probing of any kind
- **Encrypted Traffic:** Cannot decrypt HTTPS content (only metadata visible)
- **Health Score:** Estimate based on heuristics, not absolute
- **Anomaly Detection:** Needs ~24 hours of data for accuracy
- **Switch Isolation:** Ethernet may not see other devices on managed switches
- **VPN Traffic:** Appears encrypted, cannot analyze payload

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `R` | Refresh data immediately |
| `1` | Go to Dashboard |
| `2` | Go to Devices |
| `3` | Go to Alerts |
| `Esc` | Close modal/popup |

---

## Getting Help

If you encounter issues:

1. Check the [SETUP_GUIDE.md](SETUP_GUIDE.md) troubleshooting section
2. Verify NetWatch is running (`http://localhost:5000/api/status`)
3. Contact your system administrator
4. Report bugs through your project's issue tracker
