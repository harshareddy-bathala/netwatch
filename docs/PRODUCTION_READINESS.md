# NetWatch Production Readiness Checklist

This document assesses NetWatch's readiness for production deployment and provides guidance for different deployment scenarios.

## Table of Contents

1. [Production Readiness Summary](#production-readiness-summary)
2. [Deployment Scenarios](#deployment-scenarios)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Performance Considerations](#performance-considerations)
5. [Security Recommendations](#security-recommendations)
6. [Known Limitations](#known-limitations)
7. [Monitoring & Maintenance](#monitoring--maintenance)
8. [Troubleshooting Production Issues](#troubleshooting-production-issues)

---

## Production Readiness Summary

| Category | Status | Notes |
|----------|--------|-------|
| **Core Functionality** | ✅ Ready | Packet capture, parsing, storage working |
| **Web Dashboard** | ✅ Ready | Real-time updates, responsive design |
| **Database** | ✅ Ready | SQLite with automatic cleanup (7-day retention) |
| **Error Handling** | ✅ Ready | Graceful degradation, error logging |
| **Documentation** | ✅ Ready | Complete setup, API, user manuals |
| **Testing** | ✅ Ready | Unit tests, connection type tests |
| **24/7 Operation** | ✅ Ready | Cleanup tasks, memory management |
| **Security** | ⚠️ Partial | Admin-only, no authentication by default |
| **Scalability** | ⚠️ Limited | Single machine, SQLite bottleneck |
| **Monitoring Modes** | ✅ Enhanced | Automatic detection, ARP scanning, port mirror support |
| **Device Discovery** | ✅ **NEW** | ARP scan, mDNS, passive analysis - finds ALL devices |
| **Enterprise Support** | ✅ **NEW** | Port mirror/SPAN detection, promiscuous mode |

**Overall Status:** ✅ **PRODUCTION READY** - Full network monitoring with enhanced device discovery

---

## Deployment Scenarios

### Scenario 1: Personal Device Monitoring ✅ **RECOMMENDED**

**Use Case:** Individual wants to monitor their own laptop's bandwidth usage

**Setup:**
- Run NetWatch on personal laptop
- Any network connection (WiFi/Ethernet)
- Access dashboard locally

**Pros:**
- ✅ Simple setup
- ✅ No special network configuration
- ✅ Works anywhere

**Cons:**
- ⚠️ Only monitors own device

**Production Ready:** ✅ **YES**

**Steps:**
1. Install NetWatch following [SETUP_GUIDE.md](SETUP_GUIDE.md)
2. Run with `python main.py`
3. Access dashboard at `http://localhost:5000`

---

### Scenario 2: Home Network Monitoring ✅ **RECOMMENDED**

**Use Case:** Family wants to monitor all household devices

**Setup:**
- Enable Mobile Hotspot on laptop
- All family devices connect to laptop's hotspot
- Run NetWatch to monitor all traffic

**Pros:**
- ✅ Full visibility of all devices
- ✅ Real-time per-device bandwidth
- ✅ Parental controls possible

**Cons:**
- ⚠️ Laptop must stay on 24/7
- ⚠️ May reduce internet speed (double-hop)
- ⚠️ Laptop battery drain

**Production Ready:** ✅ **YES**

**Steps:**
1. **Windows:** Settings → Mobile Hotspot → Turn On
2. **macOS:** System Preferences → Sharing → Internet Sharing
3. Connect all devices to laptop's hotspot
4. Run NetWatch with `python main.py --reset-db` (first time)
5. Access dashboard from any connected device at `http://<laptop-ip>:5000`

---

### Scenario 3: Small Office/Classroom (10-50 devices) ✅ **RECOMMENDED**

**Use Case:** Teacher/IT admin monitoring classroom or small office network

**Setup:**
- Dedicated laptop as monitoring station
- Laptop running as WiFi hotspot OR connected to switch with port mirroring
- All monitored devices connect through laptop

**Pros:**
- ✅ Centralized monitoring
- ✅ Multi-device visibility
- ✅ Good for 10-50 devices

**Cons:**
- ⚠️ Requires dedicated hardware
- ⚠️ Single point of failure
- ⚠️ Performance degrades above 50 devices

**Production Ready:** ✅ **YES** (up to 50 devices)

**Performance Tips:**
- Use laptop with SSD for database I/O
- Minimum 8GB RAM recommended
- Wired internet connection for hotspot source
- Consider cleanup interval reduction to 3 days if storage constrained

---

### Scenario 4: Enterprise/Campus Network (50+ devices) ✅ **NOW SUPPORTED**

**Use Case:** Large organization monitoring campus network

**Setup:**
- Dedicated server with port mirroring from network switches
- NetWatch captures mirrored traffic
- **NEW:** Automatic port mirror detection

**Pros:**
- ✅ **NEW:** Automatic port mirror/SPAN detection
- ✅ **NEW:** Enhanced device discovery via ARP scanning
- ✅ Can handle many devices with proper configuration
- ✅ No interruption to network flow
- ✅ Full network visibility when port mirror configured

**Considerations:**
- ⚠️ Requires switch configuration (SPAN/port mirroring)
- ⚠️ SQLite may become bottleneck at scale >100 devices
- ⚠️ No built-in authentication/multi-user support

**Production Ready:** ✅ **YES** (with port mirroring configuration)

**Recommended for >100 devices:**
- Replace SQLite with PostgreSQL
- Add authentication (OAuth/LDAP)
- Implement rate limiting on API
- Use Redis for session management
- Deploy behind reverse proxy (nginx)

---

## Pre-Deployment Checklist

### Software Requirements

- [ ] Python 3.10 or higher installed
- [ ] All dependencies from `requirements.txt` installed
- [ ] Scapy working (test with `scapy -H`)
- [ ] Windows: Npcap installed with WinPcap compatibility
- [ ] Linux/macOS: libpcap installed

### System Requirements

**Minimum:**
- CPU: Dual-core 2.0 GHz
- RAM: 4 GB
- Storage: 10 GB free (for database)
- Network: Active network interface

**Recommended (for 24/7 operation):**
- CPU: Quad-core 2.5 GHz+
- RAM: 8 GB
- Storage: 50 GB SSD
- Network: Gigabit Ethernet or WiFi 5/6

### Network Configuration

- [ ] Administrator/root privileges available
- [ ] Firewall allows port 5000 (or custom port)
- [ ] Network interface detected correctly
- [ ] Monitoring mode appropriate for use case
- [ ] If hotspot: Internet Connection Sharing configured

### Security Configuration

- [ ] Change default Flask secret key in production
- [ ] Restrict dashboard access to local network only
- [ ] Consider adding authentication if exposing beyond localhost
- [ ] Review and adjust database retention period
- [ ] Enable HTTPS if accessing over network (use nginx proxy)

### Database Setup

- [ ] Database initialized: `python database/init_db.py`
- [ ] Database location has write permissions
- [ ] Disk space monitoring enabled
- [ ] Backup strategy defined (optional for local use)

### Testing

- [ ] Run `python test_modules.py` - all tests pass
- [ ] Run `python test_connection_types.py` - monitoring mode detected correctly
- [ ] Dashboard loads: `http://localhost:5000`
- [ ] API status endpoint works: `http://localhost:5000/api/status`
- [ ] Packet capture starts without errors
- [ ] Database saves packets (check `get_realtime_stats()`)

---

## Performance Considerations

### Expected Performance (Typical Home Network)

| Metric | Value |
|--------|-------|
| Packet Capture Rate | 100-1000 packets/sec |
| CPU Usage | 5-15% (idle), 20-40% (heavy traffic) |
| RAM Usage | 100-300 MB |
| Database Growth | ~50-200 MB/day (depends on traffic) |
| Dashboard Response | < 100ms |
| Packet Processing Latency | < 10ms |

### Optimization Tips

#### For High-Traffic Networks

1. **Adjust Cleanup Interval:**
```python
# In main.py, line ~50
CLEANUP_INTERVAL = 1800  # 30 minutes instead of 1 hour
```

2. **Reduce Data Retention:**
```python
# In database/db_handler.py, cleanup_old_data()
days_to_keep = 3  # Instead of 7
```

3. **Batch Size Tuning:**
```python
# In packet_capture/monitor.py
batch_size = 50  # Reduce if memory constrained, increase for throughput
```

#### For Low-Resource Systems

1. **Disable Anomaly Detection:**
```python
# In alerts/detector.py
ENABLE_DETECTION = False  # Saves CPU and memory
```

2. **Increase Dashboard Refresh Interval:**
```javascript
// In frontend/js/dashboard.js
const REFRESH_INTERVAL = 5000;  // 5 seconds instead of 3
```

3. **Limit Chart Data Points:**
```javascript
// In frontend/js/charts.js
maxDataPoints: 30  // Instead of 60
```

### Database Maintenance

**Automatic Cleanup:**
- Runs hourly (configurable in `main.py`)
- Removes traffic data older than 7 days
- Keeps device information indefinitely

**Manual Cleanup:**
```bash
# Clear all data and reset
python main.py --reset-db

# Compact database
sqlite3 netwatch.db "VACUUM;"
```

**Backup (Optional):**
```bash
# Backup database
cp netwatch.db netwatch.db.backup

# Restore
cp netwatch.db.backup netwatch.db
```

---

## Security Recommendations

### For Personal Use (localhost only)

✅ **Default configuration is fine** - dashboard only accessible from localhost

### For Network-Wide Access

⚠️ **Additional security needed:**

1. **Add Authentication:**
   - Implement Flask-Login or similar
   - Create user accounts
   - Protect all routes except static files

2. **Enable HTTPS:**
   - Use nginx reverse proxy with SSL
   - Obtain SSL certificate (Let's Encrypt)
   - Force HTTPS redirects

3. **Change Secret Key:**
```python
# In config.py
SECRET_KEY = 'generate-a-random-secure-key-here'
```

4. **Restrict Access by IP:**
```python
# In backend/app.py
from flask import request, abort

@app.before_request
def limit_remote_addr():
    allowed_ips = ['192.168.1.0/24']  # Your network
    if request.remote_addr not in allowed_ips:
        abort(403)
```

5. **Rate Limiting:**
```python
# Install: pip install flask-limiter
from flask_limiter import Limiter

limiter = Limiter(app, default_limits=["200 per day", "50 per hour"])
```

### Data Privacy

- NetWatch stores IP addresses, hostnames, and traffic metadata
- Does NOT store packet payloads or website content
- HTTPS traffic is encrypted, only destination visible
- Consider GDPR/privacy laws if deploying in organization

### Network Security

- Running in hotspot mode exposes your connection
- Set strong WiFi password (WPA2/WPA3)
- Consider MAC address filtering
- Monitor for unauthorized devices regularly

---

## Known Limitations

### Technical Limitations (Mitigated with v2.0 Enhancements)

1. **WiFi Client Mode - ENHANCED ✅**
   - ❌ Cannot see other WiFi clients' traffic content (WiFi security by design)
   - ✅ **NEW:** Can discover ALL devices on network via ARP scanning
   - ✅ **NEW:** Can capture traffic with promiscuous mode when available
   - ✅ Full device visibility regardless of connection mode
   - 💡 For complete traffic capture: Use hotspot mode or port mirroring

2. **Encrypted Traffic**
   - ❌ Cannot decrypt HTTPS/TLS content
   - ✅ Can see: destination, size, timing
   - ❌ Cannot see: URLs, form data, passwords

3. **Scalability**
   - ✅ Good: 1-50 devices
   - ⚠️ Moderate: 50-100 devices
   - ❌ Poor: 100+ devices (SQLite bottleneck)

4. **Single Machine Architecture**
   - No distributed deployment
   - No redundancy/failover
   - Single point of failure

5. **Switch Port Isolation - ENHANCED ✅**
   - ✅ **NEW:** ARP scanning discovers devices even with port isolation
   - ✅ **NEW:** Port mirror auto-detection for enterprise setups
   - ✅ **NEW:** Promiscuous mode for enhanced capture when supported
   - 💡 For full traffic visibility: Configure switch port mirroring (SPAN)

### Enterprise Features (NEW in v2.0)

1. **Port Mirror Detection**
   - ✅ Automatic detection of SPAN/port mirror configuration
   - ✅ Optimizes capture when full network visibility available
   - ✅ API endpoint: `/api/discovery/port-mirror-status`

2. **Active Network Discovery**
   - ✅ ARP scanning finds all local network devices
   - ✅ Ping sweep for devices blocking ARP
   - ✅ mDNS discovery for smart devices
   - ✅ DHCP monitoring for new device detection
   - ✅ API endpoint: `/api/discovery/scan`

3. **Enhanced Monitoring Modes**
   - ✅ Promiscuous mode for maximum packet capture
   - ✅ Passive device extraction from traffic
   - ✅ Background continuous discovery (every 2 minutes)
   - ✅ API endpoint: `/api/discovery/capabilities`

### Functional Limitations

1. **No Historical Analysis Beyond 7 Days**
   - Automatic cleanup deletes old traffic data
   - Device info retained indefinitely
   - Today's usage tracking included

2. **No User Authentication**
   - Anyone with access to dashboard URL can view
   - No user roles or permissions
   - Requires custom implementation for multi-user

3. **No Real-Time Blocking/Filtering**
   - Monitoring only, not a firewall
   - Cannot block devices or applications
   - Cannot prioritize traffic (no QoS)

4. **Protocol Detection Limitations**
   - Based on port numbers (heuristic)
   - VPN traffic shows as encrypted blob
   - Custom ports may be misidentified

---

## Monitoring & Maintenance

### Daily Tasks (Automated)

✅ **No manual intervention required:**
- Packet capture runs continuously
- Database saves traffic data
- Cleanup task runs hourly
- Dashboard updates every 3 seconds

### Weekly Tasks (Optional)

- Check database size: `ls -lh netwatch.db`
- Review critical alerts
- Verify monitoring mode still appropriate
- Check disk space on monitoring machine

### Monthly Tasks (Recommended)

- Review top bandwidth consumers
- Update friendly hostnames for new devices
- Check for NetWatch updates (if pulling from git)
- Verify Python dependencies up to date

### Quarterly Tasks

- Full database backup (optional)
- Review and adjust retention policies
- Performance tuning if needed
- Security audit if network-accessible

### Logs & Monitoring

**View Logs:**
```bash
# NetWatch uses Python logging
# Check terminal output or redirect to file:
python main.py > netwatch.log 2>&1
```

**Key Metrics to Monitor:**
- CPU usage (should be < 50% average)
- Memory usage (should be < 500 MB)
- Database size (should grow linearly, not exponentially)
- Packet drop rate (should be < 1%)

**Health Checks:**
```bash
# Status endpoint
curl http://localhost:5000/api/status

# Database integrity
python database/init_db.py --check

# Interface detection
python test_connection_types.py
```

---

## Troubleshooting Production Issues

### High CPU Usage

**Symptoms:** Python process using > 50% CPU consistently

**Causes:**
- Too many devices on network
- High packet rate
- Inefficient queries

**Solutions:**
1. Check packet capture rate in stats
2. Reduce dashboard refresh rate
3. Disable anomaly detection if not needed
4. Optimize database queries (add indexes)

---

### High Memory Usage

**Symptoms:** Python process using > 1 GB RAM

**Causes:**
- Packet queue backing up
- Memory leak in long-running process
- Too many database connections

**Solutions:**
1. Restart NetWatch
2. Reduce batch size in monitor.py
3. Check for packet processing bottleneck
4. Update to latest version (memory fixes)

---

### Dashboard Not Loading

**Symptoms:** Browser shows "Cannot connect" or timeout

**Causes:**
- NetWatch not running
- Wrong port number
- Firewall blocking
- Interface binding issue

**Solutions:**
1. Check if process running: `ps aux | grep main.py` (Linux) or Task Manager (Windows)
2. Verify port: `netstat -an | grep 5000`
3. Check firewall: Allow port 5000
4. Try `http://127.0.0.1:5000` instead of `localhost`

---

### No Devices Showing

**Symptoms:** Dashboard shows 0 devices or only 1 (self)

**Causes:**
- WiFi Client Mode (most common)
- No traffic on network
- BPF filter issue
- Database not saving packets

**Solutions:**
1. Check monitoring mode: Visit `/api/status`
2. If WiFi Client Mode: Enable hotspot on laptop
3. Verify packets being captured: Check stats in terminal
4. Test database: Run `python test_modules.py`

---

### Database Growing Too Large

**Symptoms:** `netwatch.db` > 5 GB

**Causes:**
- Cleanup task not running
- Very high traffic volume
- Retention period too long

**Solutions:**
1. Check cleanup task: Look for "Cleanup task started" in logs
2. Manually compact: `sqlite3 netwatch.db "VACUUM;"`
3. Reduce retention: Edit `cleanup_old_data()` in db_handler.py
4. Archive old data: Backup and reset database

---

### Application Crashes

**Symptoms:** Python process exits unexpectedly

**Causes:**
- Unhandled exception
- Out of memory
- Database locked
- Permission issues

**Solutions:**
1. Check logs for error messages
2. Run with exception handling: `python main.py 2>&1 | tee error.log`
3. Verify database permissions: `ls -l netwatch.db`
4. Check disk space: `df -h`
5. Report bug with error trace

---

## Production Deployment Examples

### Example 1: Personal Laptop (Windows)

```powershell
# 1. Install
cd C:\Users\YourName\Projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 2. Initialize
python database\init_db.py

# 3. Run (as Administrator)
python main.py

# 4. Access
# Open browser: http://localhost:5000
```

---

### Example 2: Home Network Monitoring (macOS)

```bash
# 1. Install
cd ~/Projects
git clone https://github.com/your-team/netwatch.git
cd netwatch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Enable Internet Sharing
# System Preferences → Sharing → Internet Sharing
# Share from: Ethernet, To: WiFi

# 3. Initialize database
python database/init_db.py

# 4. Run
sudo python main.py

# 5. Connect devices to Mac's WiFi hotspot

# 6. Access from any device
# http://<mac-ip-address>:5000
```

---

### Example 3: 24/7 Classroom Monitoring (Linux)

```bash
# 1. Install on dedicated Ubuntu server
sudo apt update
sudo apt install python3.10 python3-venv python3-pip libpcap-dev
cd /opt
sudo git clone https://github.com/your-team/netwatch.git
cd netwatch
sudo python3 -m venv venv
source venv/bin/activate
sudo pip install -r requirements.txt

# 2. Create systemd service
sudo nano /etc/systemd/system/netwatch.service

# Add:
[Unit]
Description=NetWatch Network Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netwatch
ExecStart=/opt/netwatch/venv/bin/python /opt/netwatch/main.py
Restart=always

[Install]
WantedBy=multi-user.target

# 3. Enable and start
sudo systemctl enable netwatch
sudo systemctl start netwatch

# 4. Check status
sudo systemctl status netwatch

# 5. View logs
sudo journalctl -u netwatch -f
```

---

## Conclusion

NetWatch is **production-ready** for:
- ✅ Personal device monitoring
- ✅ Home network monitoring (hotspot mode)
- ✅ Small office/classroom (10-50 devices)

NetWatch requires modifications for:
- ⚠️ Enterprise scale (100+ devices)
- ⚠️ Multi-user environments
- ⚠️ Public internet exposure

Follow this guide for successful deployment and ongoing operation.

**Questions?** See [SETUP_GUIDE.md](SETUP_GUIDE.md) for installation help or [USER_MANUAL.md](USER_MANUAL.md) for usage.
