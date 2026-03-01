# Port Mirror / SPAN Setup Guide

This guide explains how to configure switch port mirroring (SPAN) so that
NetWatch can monitor all traffic on your network with full visibility.

---

## What Is Port Mirroring?

Port mirroring (also called **SPAN** — Switched Port Analyzer) is a feature on
managed network switches that copies traffic from one or more source ports to a
designated **mirror port**. A monitoring tool like NetWatch, connected to the
mirror port, can then observe all traffic without interfering with normal network
operation.

**When to use port mirror mode:**

- You want to see **all** devices and traffic on a VLAN, not just your own
- You have a **managed switch** that supports port mirroring / SPAN
- You need full protocol visibility for network auditing or troubleshooting

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Managed switch** | Must support port mirroring / SPAN (unmanaged switches do not) |
| **Dedicated mirror port** | One port on the switch configured to receive mirrored traffic |
| **Npcap** (Windows) | Install from [npcap.com](https://npcap.com/) with "WinPcap API-compatible Mode" |
| **Admin/root privileges** | Packet capture requires elevated permissions |
| **NetWatch** | Running on the PC connected to the mirror port |

---

## Switch Configuration

### Cisco IOS (SPAN)

```
! Mirror all traffic from ports Fa0/1-Fa0/24 to port Gi0/1
configure terminal
monitor session 1 source interface FastEthernet0/1 - 24
monitor session 1 destination interface GigabitEthernet0/1
end

! Verify
show monitor session 1
```

**Key points:**
- The destination port stops forwarding normal traffic and only sends mirrored frames.
- Use `both` (default) to capture traffic in both directions; or specify `rx` / `tx`.

### Cisco Small Business (SG series)

1. Log into the switch web UI
2. Navigate to **Status and Statistics > Port Mirroring**
3. Set **Destination Port** to the port connected to your NetWatch PC
4. Add source ports (the ports you want to monitor)
5. Click **Apply**

### Netgear Managed Switches

1. Log into the switch web interface
2. Go to **Monitoring > Mirroring**
3. Set the **Destination Port** to the port your NetWatch PC is connected to
4. Select one or more **Source Ports**
5. Choose direction: **Both** (ingress + egress)
6. Click **Apply**

### TP-Link Managed Switches

1. Log into the switch management page
2. Navigate to **Monitoring > Port Mirror**
3. Select the **Mirroring Port** (destination — your NetWatch PC)
4. Select the **Mirrored Port(s)** (source — ports to monitor)
5. Set mirroring mode to **Both** (Ingress & Egress)
6. Click **Save**

### HP / Aruba ProCurve

```
configure terminal
mirror-port 24              # your NetWatch PC port
interface 1-23 monitor      # mirror all other ports
write memory
```

### Dell / PowerConnect

```
configure
monitor session 1 source interface ethernet 1/0/1-1/0/23 both
monitor session 1 destination interface ethernet 1/0/24
exit
```

### Ubiquiti UniFi

1. Open the UniFi Controller
2. Go to **Devices** > select your switch
3. Open **Port Management**
4. Find the port connected to your NetWatch PC
5. Enable **Mirror Port** and select source ports
6. Click **Apply Changes**

---

## NetWatch Setup

### 1. Connect to the Mirror Port

Connect your NetWatch PC to the switch port you configured as the
**destination / mirror port**.

### 2. Start NetWatch

```bash
# Windows (Run as Administrator)
python main.py

# Linux (root required for raw capture)
sudo python3 main.py
```

### 3. Verify Mode Detection

NetWatch automatically detects port mirror mode by analyzing source MAC addresses
in captured traffic. When more than 50% of source MACs are foreign (not your own
NIC's MAC), it identifies the connection as a port mirror.

**Detection timeline:**
- **First boot:** Promiscuous probe runs immediately (~3 seconds), detects mirror traffic
- **Ongoing:** The capture engine feeds source MACs to the detector every 15-30 seconds
- **Total detection time:** Usually under 10 seconds after connecting

**What you should see in the dashboard:**
- Sidebar badge shows **"Port Mirror"** with a magnifying glass icon
- Mode hint: *"Full traffic visibility -- promiscuous capture"*
- All devices on the mirrored VLAN(s) appear in the device list

### 4. If Mode Is Not Auto-Detected

If NetWatch detects a different mode (e.g., Ethernet), you can force a refresh:

**Via the Dashboard:**
Click the refresh button next to the mode badge in the sidebar.

**Via the API:**
```bash
# Force mode re-detection
curl -X POST http://127.0.0.1:5000/api/interface/refresh
```

**Check your switch configuration** if the mode still isn't detected:
- Verify the mirror port is receiving traffic (check switch port counters)
- Ensure the source ports have active traffic
- Try increasing `PORT_MIRROR_FOREIGN_MAC_THRESHOLD` in `config.py` if you're
  on a quiet network (lower value = more sensitive detection)

---

## What to Expect in Port Mirror Mode

### Device Discovery
- **All devices** on the mirrored VLAN(s) will appear in the device list
- Devices are discovered via passive traffic observation, ARP scanning, and ARP cache
- Discovery runs every 60 seconds with ping sweep every 5th cycle

### Traffic Monitoring
- **No BPF filter** is applied — all traffic is captured
- **Promiscuous mode** is enabled at the OS level
- Full protocol visibility: HTTP, HTTPS, DNS, SSH, FTP, SMTP, and all others
- Bandwidth is measured for all observed traffic (not just your own)

### Device Details
- IP address, MAC address, hostname (via reverse DNS, mDNS, NetBIOS)
- Per-device bandwidth (upload / download)
- Protocol breakdown
- First seen / last seen timestamps

---

## Performance Considerations

Port mirror mode captures significantly more traffic than other modes. On busy
networks, consider these tuning options in `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `PACKET_SAMPLE_RATE` | `1` | Process 1 out of every N packets. Set to `5` on busy networks. |
| `MAX_PACKETS_PER_SECOND` | `0` | Rate limit (0 = unlimited). Set to `500` if CPU is high. |
| `BATCH_SIZE` | `500` | Packets per DB write batch. Increase for throughput. |
| `BANDWIDTH_WINDOW_SECONDS` | `10` | Sliding window for bandwidth calculation. |
| `PORT_MIRROR_MAX_PPS` | `5000` | Auto-sample above this packet rate. |
| `PORT_MIRROR_MAX_UNIQUE_MACS_PER_MINUTE` | `500` | Alert and sample if exceeded. |
| `PORT_MIRROR_CONNECTION_TIMEOUT` | `300` | Expire stale connections after 5 min. |

### 24/7 Operation Settings

For long-running port mirror deployments, these settings prevent disk exhaustion:

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_DATABASE_SIZE_GB` | `20` | Adaptive retention kicks in above this size. |
| `EMERGENCY_RETENTION_HOURS` | `6` | Minimum retention when disk is critically low. |
| `DISK_SPACE_WARNING_PERCENT` | `10` | Alert when disk free space drops below 10%. |
| `DISK_SPACE_CRITICAL_PERCENT` | `5` | Emergency cleanup triggered below 5%. |
| `STALE_DEVICE_PRUNE_INTERVAL` | `300` | Prune inactive devices from memory every 5 min. |
| `STALE_DEVICE_TIMEOUT_HOURS` | `2` | Remove devices not seen in 2 hours from memory. |
| `MAX_IN_MEMORY_DEVICES` | `10000` | LRU eviction limit for in-memory device tracking. |
| `WAL_CHECKPOINT_INTERVAL_MINUTES` | `30` | Periodic WAL merge to prevent unbounded WAL growth. |

**Tips for high-traffic networks:**
- Monitor CPU usage; if consistently above 80%, increase `PACKET_SAMPLE_RATE`
- Use a dedicated NIC for the mirror port (avoid the NIC used for management)
- SSD storage recommended for the database at high packet rates
- Plan for ~2-5 GB/day of database growth at 1000 pkt/s (adaptive cleanup manages this)
- Monitor disk space via `/api/system/health` endpoint

---

## Troubleshooting

### Mode Not Detected as Port Mirror

1. **Check switch config:** Verify the mirror port is correctly configured
2. **Check traffic:** Run `tcpdump -i <interface> -c 20` and verify you see
   packets with foreign source MAC addresses
3. **Check Npcap (Windows):** Ensure Npcap is installed and the interface is visible
4. **Lower threshold:** In `config.py`, set `PORT_MIRROR_FOREIGN_MAC_THRESHOLD = 0.30`
5. **Force refresh:** POST to `/api/interface/refresh`

### No Devices Showing

1. **Verify mirror is active:** Check switch port counters for the mirror port
2. **Check source ports:** Ensure the source ports have active devices
3. **Wait for discovery:** Initial ARP scan + ping sweep may take up to 60 seconds
4. **Check permissions:** NetWatch must run as Administrator (Windows) or root (Linux)

### High CPU / Memory Usage

1. Increase `PACKET_SAMPLE_RATE` to `5` or `10`
2. Set `MAX_PACKETS_PER_SECOND` to `500`
3. Reduce the number of mirrored source ports if possible
4. Monitor with the `/api/system/health` endpoint

### Bandwidth Readings Seem Wrong

1. Verify the mirror port is set to **Both** (ingress + egress)
2. Check if the switch is mirroring VLAN-tagged frames (may need trunk mode)
3. Ensure `PACKET_SAMPLE_RATE` is `1` for accurate readings

---

## Security Notes

- **Port mirror provides read-only access** — NetWatch cannot modify traffic
- The mirror port only receives copies of frames; it does not inject into the network
- ARP scanning from the mirror port is normal and helps discover devices
- Access to the switch management console should be restricted to authorized personnel
