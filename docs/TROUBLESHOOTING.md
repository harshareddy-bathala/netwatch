# NetWatch Troubleshooting Guide

## Quick Diagnostic

Run these commands to quickly diagnose common issues:

```bash
# Check if NetWatch is running
curl http://localhost:5000/health

# Check Python version
python --version  # Must be 3.11+

# Check admin privileges (Linux/macOS)
whoami  # Should show 'root' or use sudo

# Check database
sqlite3 netwatch.db "PRAGMA journal_mode; SELECT COUNT(*) FROM devices;"
```

---

## Common Issues

### 1. "No interface detected" / "Permission denied for packet capture"

**Cause:** NetWatch requires administrator/root privileges to capture packets.

**Solution:**

| Platform | Fix |
|----------|-----|
| Windows | Right-click → "Run as administrator" |
| Linux | `sudo python3 main.py` |
| macOS | `sudo python3 main.py` |

**Also check:**
- **Windows:** Npcap is installed (download from https://npcap.com)
- **Linux:** `libpcap-dev` is installed: `sudo apt install libpcap-dev`
- **macOS:** Xcode command line tools: `xcode-select --install`

### 2. "Database locked" / "sqlite3.OperationalError: database is locked"

**Cause:** Another instance is running, or the database is corrupt.

**Solution:**
```bash
# Check for other instances
# Linux/macOS:
ps aux | grep netwatch
# Windows:
tasklist | findstr python

# Kill duplicate instances
# Linux/macOS:
pkill -f "python.*main.py"
# Windows:
taskkill /F /IM python.exe

# If database is corrupt:
python main.py --reset-db
```

**Prevention:**
- Always stop NetWatch cleanly (Ctrl+C)
- Don't run multiple instances

### 3. "Bandwidth shows 0" / No traffic data

**Possible Causes:**

1. **BPF filter too restrictive:**
   ```bash
   # Check current filter
   curl http://localhost:5000/api/interface/status
   ```

2. **Wrong interface selected:**
   ```bash
   # List available interfaces
   curl http://localhost:5000/api/interface/list
   ```

3. **No admin privileges:** See issue #1

4. **No network activity:** Open a browser and browse to generate traffic

5. **Npcap not in promiscuous mode (Windows):**
   - Reinstall Npcap with "Support raw 802.11 traffic" checked

### 4. "Alert count never decreases"

**Cause:** Alerts need to be explicitly acknowledged or resolved.

**Solution:**
```bash
# Acknowledge an alert
curl -X POST http://localhost:5000/api/alerts/1/acknowledge

# Resolve an alert
curl -X POST http://localhost:5000/api/alerts/1/resolve

# From the dashboard: click the alert → Acknowledge/Resolve button
```

### 5. "Frontend not loading" / Blank page

**Possible Causes:**

1. **Flask not running:**
   ```bash
   curl http://localhost:5000/health
   # If connection refused, restart NetWatch
   ```

2. **Port already in use:**
   ```bash
   # Check what's using port 5000
   # Linux/macOS:
   lsof -i :5000
   # Windows:
   netstat -ano | findstr :5000

   # Use different port:
   python main.py --port 8080
   ```

3. **Browser cache:** Try Ctrl+Shift+R (hard refresh)

4. **CORS issue:** Check browser console (F12) for CORS errors

### 6. "Mode detected incorrectly"

**Symptoms:**
- WiFi client detected as hotspot (captures hundreds of devices)
- Hotspot detected as WiFi client (misses connected devices)

**Solution:**
```bash
# Force refresh mode detection
curl -X POST http://localhost:5000/api/interface/refresh

# Check current mode
curl http://localhost:5000/api/interface/status
```

**If still wrong:**
- Verify your network setup matches the expected mode
- Check if mobile hotspot is actually enabled
- Windows: Check "Mobile hotspot" in Settings → Network

### 7. "High memory usage"

**Cause:** Large packet buffer or many tracked devices.

**Solution:**
```bash
# Reduce buffer size in config.py
PACKET_BUFFER_MAX_SIZE = 10000  # Default: 50000

# Clean old data
python -c "
from database.init_db import cleanup_old_data
cleanup_old_data(hours=12)
"

# Reset database
python main.py --reset-db
```

### 8. "Device count is too high / shows phantom devices"

**Cause:** Capturing traffic from outside your local subnet.

**Solution:**
1. Check the detected mode matches your real setup
2. Reset the database: `python main.py --reset-db`
3. Verify the BPF filter is filtering to your subnet

### 9. "Cannot connect to http://localhost:5000"

**Checklist:**
1. Is NetWatch running? Check terminal for errors
2. Is port 5000 open? `curl http://localhost:5000/health`
3. Is firewall blocking? Temporarily disable and test
4. Using WSL? Access via `http://localhost:5000` from Windows browser

### 10. "ModuleNotFoundError" on startup

**Solution:**
```bash
# Ensure virtual environment is active
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

---

## Performance Issues

### Dashboard is slow to load

1. Check number of devices: `curl http://localhost:5000/api/devices | python -m json.tool | wc -l`
2. If >100 devices, the system may be capturing too broadly
3. Check database size: `ls -lh netwatch.db`
4. Run cleanup: `python -c "from database.init_db import cleanup_old_data; cleanup_old_data(hours=6)"`

### API responses are slow (>100ms)

1. Enable WAL mode (should be default):
   ```bash
   sqlite3 netwatch.db "PRAGMA journal_mode=WAL;"
   ```
2. Vacuum the database:
   ```bash
   sqlite3 netwatch.db "VACUUM;"
   ```
3. Check for slow queries in logs (DEBUG mode)

### High CPU usage

1. Check if anomaly detector is training frequently
2. Reduce packet capture intensity in congested networks
3. Increase `ANOMALY_CHECK_INTERVAL` in config.py

---

## Platform-Specific Issues

### Windows

| Issue | Fix |
|-------|-----|
| "WinPcap not found" | Install Npcap from https://npcap.com |
| "Access denied" | Run as Administrator |
| Antivirus blocks capture | Add exception for NetWatch |
| Windows Defender firewall | Allow Python through firewall |

### Linux

| Issue | Fix |
|-------|-----|
| "Operation not permitted" | Use `sudo` or set capabilities: `sudo setcap cap_net_raw+ep $(which python3)` |
| "No such device" | Check interface name: `ip link show` |
| AppArmor blocking | Add profiles or disable for testing |

### macOS

| Issue | Fix |
|-------|-----|
| "Permission denied" | Use `sudo` |
| "en0 not found" | Check: `ifconfig` and use correct interface |
| SIP blocking | Packet capture should work with `sudo` |

---

## v3.0.0 — Resolved Issues

### WiFi Client Shows Too Many Devices

**Symptom:** Dashboard reports 6+ devices in WiFi Client mode when only 2 are expected (self + gateway).

**Cause:** Multicast MAC addresses (`01:00:5e:*` for IPv4 multicast, `33:33:*` for IPv6 multicast, `01:80:c2:*` for STP/LLDP) were being tracked as real devices. Public IPs from CDN/DNS servers were also being assigned to device objects.

**Fix (v3.0.0):** `_is_trackable_mac()` now rejects all multicast prefixes. IP assignments are guarded by `is_private_ip()` so only RFC1918 addresses appear as device IPs.

### Bandwidth Chart Oscillates

**Symptom:** The bandwidth chart line fluctuates or shows periodic dips to zero every few seconds.

**Cause:** The 60-second cutoff between DB history and live data used `datetime.now()`, which shifted every SSE frame. Data points near the boundary alternated between the two sources. Additionally, a synthetic zero-point "bridge" was inserted at the boundary, creating false dips.

**Fix (v3.0.0):** The cutoff is now rounded down to the nearest 10-second boundary, creating a stable split. The zero-point bridge insertion has been removed entirely — DB and live data are concatenated directly.

### Ctrl+C Doesn't Stop the App

**Symptom:** Pressing Ctrl+C in the terminal does nothing, or the app hangs after Ctrl+C.

**Cause:** The signal handler only set a threading event but did not interrupt the blocking `waitress_serve()` / Flask server call.

**Fix (v3.0.0):** The signal handler now raises `KeyboardInterrupt` after setting the shutdown event. This interrupts the blocking server call and allows the `finally` block and `except KeyboardInterrupt` handler to run `shutdown()` for clean teardown.

---

## Getting Help

1. **Check logs:** Look at terminal output or `/var/log/netwatch/`
2. **Enable debug mode:** Set `NETWATCH_ENV=development`
3. **Check API health:** `curl http://localhost:5000/health`
4. **Check database:** `sqlite3 netwatch.db ".tables"`
5. **File an issue:** Include OS, Python version, error logs, and mode detected
