# NetWatch Setup Guide

This guide provides step-by-step instructions for setting up NetWatch on Windows, macOS, and Linux.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Windows Setup](#windows-setup)
3. [macOS Setup](#macos-setup)
4. [Linux Setup](#linux-setup)
5. [Virtual Environment Setup](#virtual-environment-setup)
6. [Database Initialization](#database-initialization)
7. [Running NetWatch](#running-netwatch)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before installing NetWatch, ensure you have:

| Requirement | Minimum Version | Check Command |
|-------------|-----------------|---------------|
| Python | **3.11** (required) | `python --version` |
| pip | 21.0+ | `pip --version` |
| Git | 2.0+ | `git --version` |
| Admin Rights | Required | For packet capture |

**Disk Space:** ~200 MB for dependencies + database storage

---

## Windows Setup

### Step 1: Install Python 3.11

1. Download Python 3.11 from [python.org](https://www.python.org/downloads/release/python-3110/)
2. Run the installer
3. **IMPORTANT:** Check "Add Python to PATH"
4. Click "Install Now"

Verify installation:
```powershell
python --version
# Should show: Python 3.11.x
# If you have multiple versions:
py -3.11 --version
```

### Step 2: Install Npcap (Required for Scapy)

Scapy requires Npcap on Windows for packet capture:

1. Download Npcap from [npcap.com](https://npcap.com/#download)
2. Run the installer
3. Check "Install Npcap in WinPcap API-compatible Mode"
4. Complete installation

### Step 3: Clone the Repository

```powershell
cd C:\Users\YourName\Projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
```

### Step 4: Create Virtual Environment

```powershell
# Use Python 3.11 specifically
py -3.11 -m venv venv       # If multiple Python versions installed
python -m venv venv          # If 'python' already points to 3.11
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt.

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Initialize Database

```powershell
python database/init_db.py
```

### Step 7: Run NetWatch (As Administrator)

**IMPORTANT:** You must run as Administrator for packet capture.

1. Right-click on PowerShell or Command Prompt
2. Select "Run as Administrator"
3. Navigate to project folder
4. Activate virtual environment
5. Run:

```powershell
cd C:\Users\YourName\Projects\netwatch
venv\Scripts\activate
python main.py
```

---

## macOS Setup

### Step 1: Install Homebrew (if not installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2: Install Python

```bash
brew install python@3.11
```

Verify installation:
```bash
python3 --version
```

### Step 3: Clone the Repository

```bash
cd ~/Projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
```

### Step 4: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Initialize Database

```bash
python database/init_db.py
```

### Step 7: Run NetWatch (With sudo)

```bash
sudo python main.py
```

**Note:** You'll be prompted for your password. Scapy requires root privileges for packet capture.

---

## Linux Setup

### Ubuntu/Debian

#### Step 1: Update System and Install Python 3.11

```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip git
```

#### Step 2: Install libpcap (Required for Scapy)

```bash
sudo apt install libpcap-dev
```

#### Step 3: Clone the Repository

```bash
cd ~/projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
```

#### Step 4: Create Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate
```

#### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

#### Step 6: Initialize Database

```bash
python database/init_db.py
```

#### Step 7: Run NetWatch (With sudo)

```bash
sudo $(which python) main.py
```

**Note:** Using `$(which python)` ensures sudo uses your virtual environment's Python.

---

### CentOS/RHEL/Fedora

#### Step 1: Install Python and Dependencies

```bash
# Fedora
sudo dnf install python3.11 python3-pip git libpcap-devel

# CentOS/RHEL
sudo yum install python3 python3-pip git libpcap-devel
```

Follow Steps 3-7 from Ubuntu section above.

---

## Virtual Environment Setup

### Why Use a Virtual Environment?

- Isolates project dependencies
- Prevents conflicts with system Python
- Makes the project reproducible

### Creating the Environment

> **Important:** Always use Python 3.11 when creating the virtual environment.

```bash
# Create (use the appropriate command for your setup)
python -m venv venv              # If 'python' is 3.11
py -3.11 -m venv venv           # Windows with multiple Python versions
python3.11 -m venv venv         # Linux / macOS with multiple versions

# Activate (Windows CMD)
venv\Scripts\activate

# Activate (Windows PowerShell)
venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source venv/bin/activate

# Verify correct Python version
python --version
# Should show: Python 3.11.x

# Deactivate (when done)
deactivate
```

### Verifying Activation

When activated, your prompt should show `(venv)`:
```
(venv) user@machine:~/netwatch$
```

---

## Database Initialization

The database must be initialized before first run:

```bash
# From project root
python database/init_db.py
```

This creates `netwatch.db` with all required tables.

### Resetting the Database

To start fresh (deletes all data):

```bash
python database/init_db.py --reset
```

---

## Running NetWatch

### Starting the Application

```bash
# Windows (Run as Administrator)
python main.py

# Linux/macOS
sudo python main.py
```

### Accessing the Dashboard

Once running, open your browser:
```
http://localhost:5000
```

### Stopping the Application

Press `Ctrl+C` in the terminal.

---

## Network Connection Types & Monitoring Capabilities

### Understanding What NetWatch Can Monitor

NetWatch's monitoring capabilities depend on **how your laptop is connected** to the network. This section explains each scenario.

#### Scenario 1: Ethernet (Wired) Connection

**Setup:** Laptop connected via ethernet cable to router/switch

**What NetWatch Can Monitor:**
- ✅ Your laptop's own traffic (all protocols)
- ✅ Broadcast traffic (ARP, DHCP, network discovery)
- ⚠️ Other devices (depends on switch configuration)

**Limitations:**
- Modern managed switches isolate traffic between ports for security
- You may only see your own traffic + broadcasts
- To monitor other devices, ask network admin to configure port mirroring (SPAN)

**Best For:** Personal device monitoring, office networks

**Production Ready:** ✅ YES

---

#### Scenario 2: WiFi Client Mode (Connected TO WiFi) - ENHANCED

**Setup:** Laptop connected as a client to WiFi network (home/office WiFi)

**What NetWatch Can Monitor:**
- ✅ Your laptop's own traffic (full visibility)
- ✅ Broadcast traffic on the WiFi network
- ✅ **NEW:** ALL devices on network via ARP scanning
- ⚠️ Traffic capture limited to your device's packets

**Enhanced Capabilities (v2.0):**
- ✅ **ARP Scanning:** Discovers all devices on the local network
- ✅ **Ping Sweep:** Finds devices that block ARP
- ✅ **mDNS Discovery:** Finds smart devices and Apple devices
- ✅ **Passive Analysis:** Extracts device info from traffic
- ✅ **Promiscuous Mode:** Captures more traffic when available

**Note on Traffic Visibility:**
- WiFi AP isolation is a security feature that limits traffic capture
- However, **device discovery** works regardless of this limitation
- You'll see all devices, but detailed traffic only for your device's connections

**Example:** If you connect to WiFi and use the network:
- ✅ NetWatch discovers all 15 devices on network via ARP scan
- ✅ NetWatch captures your laptop's traffic in detail
- ⚠️ Other devices' traffic not captured (WiFi security feature)

**Best For:** Network discovery, personal bandwidth monitoring

**Production Ready:** ✅ YES (Full device discovery + own traffic monitoring)

**API Endpoints:**
- `GET /api/discovery/devices` - List all discovered devices
- `POST /api/discovery/scan` - Trigger immediate ARP scan
- `GET /api/discovery/capabilities` - Check available features

---

#### Scenario 3: WiFi Hotspot Mode (Laptop as Access Point)

**Setup:** Mobile Hotspot enabled ON THE LAPTOP, other devices connect to it

**What NetWatch Can Monitor:**
- ✅ ALL devices connected to your laptop's hotspot
- ✅ Complete traffic visibility for every connected device
- ✅ Real-time bandwidth per device
- ✅ Full network monitoring

**How to Enable:**

**Windows:**
1. Settings → Network & Internet → Mobile Hotspot
2. Turn on "Share my Internet connection"
3. Choose: Share WiFi or Ethernet connection
4. Set hotspot name and password
5. Other devices connect to your laptop's hotspot
6. Run NetWatch - will see ALL traffic

**macOS:**
1. System Preferences → Sharing
2. Enable "Internet Sharing"
3. Share from: Ethernet or WiFi
4. To computers using: WiFi
5. WiFi Options: Set network name and password
6. Check "Internet Sharing" to start
7. Other devices connect to your Mac's hotspot
8. Run NetWatch with sudo

**Linux (Ubuntu/Debian):**
```bash
# Install required packages
sudo apt install hostapd dnsmasq

# Use NetworkManager for easy setup
nm-connection-editor
# → Add → Wi-Fi → Mode: Hotspot
```

**Best For:** Full network monitoring, classroom environments, home network analysis

**Production Ready:** ✅ YES (Best scenario for multi-device monitoring)

---

#### Scenario 4: Switch/Router Network

**Setup:** Multiple devices on same network switch

**What NetWatch Can Monitor:**
- ✅ Your own device traffic
- ✅ Broadcast/multicast traffic
- ⚠️ Other devices (requires network configuration)

**Advanced: Port Mirroring for Full Visibility**

For enterprise monitoring, configure switch port mirroring:

1. Access switch management interface
2. Configure SPAN (Switched Port Analyzer) or port mirroring
3. Mirror target ports → monitoring port
4. Connect laptop to monitoring port
5. NetWatch will see all mirrored traffic

**Example (Cisco Switch):**
```
monitor session 1 source interface Gi1/0/1 - 10
monitor session 1 destination interface Gi1/0/24
```

**Port Mirror Detection (NEW):**
NetWatch automatically detects when connected to a port mirror/SPAN port:
- Analyzes traffic patterns for foreign MAC addresses
- Reports full network visibility when detected
- API: `GET /api/discovery/port-mirror-status`

**Best For:** Network admin use, enterprise monitoring

**Production Ready:** ✅ YES (with port mirroring configured)

---

#### Scenario 5: Mobile Hotspot (Phone as Access Point)

**Setup:** Laptop connected TO mobile phone's hotspot

**What NetWatch Can Monitor:**
- ✅ Laptop's own internet traffic
- ❌ Phone's own cellular data usage
- ❌ Other devices connected to phone's hotspot

**Why Limited:**
- This is WiFi Client Mode (see Scenario 2)
- Phone's own traffic: Phone → Cell Tower (doesn't pass through laptop)
- Laptop's traffic: Laptop → Phone → Cell Tower (visible to NetWatch)

**Best For:** Monitoring laptop's mobile data consumption

**Production Ready:** ✅ YES (for laptop monitoring only)

---

### Monitoring Mode Detection

NetWatch automatically detects your connection type:

```python
# Run this to see your current mode:
python -c "from packet_capture.monitor import get_interface_detector; d=get_interface_detector(); print(f'Mode: {d.detected_mode}\nInterface: {d.detected_interface}')"
```

**Modes:**
- `ETHERNET` - Wired connection
- `WIFI_CLIENT` - Connected to WiFi (limited monitoring)
- `WIFI_HOTSPOT` - Laptop is Access Point (full monitoring)
- `VIRTUAL` - VPN/Docker/VM interface
- `LOOPBACK` - Local only (127.0.0.1)

---

## Troubleshooting

### Common Issues

#### "Permission denied" or "Operation not permitted"

**Cause:** Packet capture requires admin/root privileges.

**Solution:**
- Windows: Run terminal as Administrator
- Linux/macOS: Use `sudo`

---

#### "No module named 'scapy'"

**Cause:** Dependencies not installed or wrong Python.

**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Reinstall dependencies
pip install -r requirements.txt
```

---

#### "Npcap not installed" (Windows)

**Cause:** Scapy needs Npcap on Windows.

**Solution:** Download and install Npcap from [npcap.com](https://npcap.com)

---

#### "No interface available" or "Cannot find interface"

**Cause:** Wrong network interface configured.

**Solution:**
1. List available interfaces:
   ```python
   from scapy.all import get_if_list
   print(get_if_list())
   ```
2. Update `NETWORK_INTERFACE` in `config.py`

---

#### "Dashboard shows only my device" or "Other devices not appearing"

**Cause:** You are in WiFi Client Mode (connected TO another WiFi network).

**Why This Happens:**
- WiFi Access Points isolate clients from each other for security
- Your laptop can ONLY see its own traffic
- This is NOT a bug - it's how WiFi security works

**Solution Options:**

**Option 1: Enable Laptop as Hotspot (Recommended for multi-device monitoring)**
1. Windows: Settings → Mobile Hotspot → Turn On
2. macOS: System Preferences → Sharing → Internet Sharing
3. Linux: Use NetworkManager to create hotspot
4. Connect other devices TO your laptop's hotspot
5. Restart NetWatch - will now see all devices

**Option 2: Accept Limited Monitoring**
- If you just want to monitor your laptop's bandwidth, this is fine
- Dashboard will show a warning explaining the limitation
- You can still track your own device's internet usage

**Option 3: Use Ethernet Instead**
- Connect via ethernet cable
- May provide better visibility depending on switch configuration

---

#### "Mobile device not detected" (phone watching YouTube)

**Cause:** You are connected TO the phone's hotspot.

**Technical Explanation:**
- When you connect laptop → phone's hotspot:
  - Laptop's traffic: Laptop → Phone → Cell Tower (✅ visible to NetWatch)
  - Phone's traffic: Phone → Cell Tower (❌ never passes through laptop)
- The phone's own internet usage (YouTube, apps) uses the cellular connection directly
- This traffic path doesn't include your laptop, so NetWatch cannot see it

**This is Network Topology, Not a Bug:**
```
Scenario A (Current - Phone as Hotspot):
┌──────────┐  WiFi   ┌───────┐  Cellular  ┌──────────┐
│  Laptop  │────────→│ Phone │───────────→│ Internet │  ✅ Laptop traffic visible
└──────────┘         └───┬───┘            └──────────┘
                         │
                         │ Cellular (Direct)
                         ↓
                    ┌──────────┐
                    │ Internet │  ❌ Phone's YouTube NOT visible
                    └──────────┘

Scenario B (Solution - Laptop as Hotspot):
┌───────────┐  WiFi   ┌────────┐  Ethernet/WiFi  ┌──────────┐
│   Phone   │────────→│ Laptop │────────────────→│ Internet │  ✅ ALL traffic visible!
└───────────┘         └────────┘                 └──────────┘
```

**Solution:**
- Enable Mobile Hotspot ON THE LAPTOP
- Connect phone TO laptop's hotspot
- Now phone's traffic goes through laptop and can be monitored

---

#### "Address already in use" (Port 5000)

**Cause:** Another application is using port 5000.

**Solution:**
1. Find and stop the other application, OR
2. Change `FLASK_PORT` in `config.py`

---

#### "Database is locked"

**Cause:** Multiple processes accessing SQLite.

**Solution:**
1. Stop all NetWatch processes
2. Delete `netwatch.db`
3. Re-initialize: `python database/init_db.py`

---

### Getting Help

1. Check this troubleshooting section
2. Read the [ARCHITECTURE.md](ARCHITECTURE.md) for system understanding
3. Ask your Project Lead (Member 1)
4. Use AI assistance with specific error messages

---

## Next Steps

After successful setup:

1. Read [USER_MANUAL.md](USER_MANUAL.md) to learn the dashboard
2. Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand the system
3. Read your role-specific guide in `docs/guides/`
