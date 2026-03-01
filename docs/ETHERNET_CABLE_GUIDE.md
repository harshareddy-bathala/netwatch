# Ethernet Cable Setup Guide

How to use NetWatch with a wired ethernet connection to share internet
and monitor connected devices.

---

## Scenario Overview

| Scenario | You are... | NetWatch monitors... | Detected mode |
|----------|-----------|---------------------|---------------|
| **ICS Host** | Sharing WiFi internet via cable | Connected client devices | Hotspot |
| **ICS Client** | Receiving internet via cable | Your own device + gateway | Ethernet |
| **Router/Switch** | Plugged into a router or switch | All LAN devices (including self) | Ethernet |
| **Port Mirror** | Connected to a SPAN/mirror port | ALL mirrored traffic | Port Mirror |

---

## Windows 11 — Internet Connection Sharing (ICS)

ICS lets you share your laptop's WiFi internet with another device
connected via ethernet cable.

### Prerequisites

- Windows 11 laptop with an active WiFi connection
- An ethernet cable (any standard Cat5e/Cat6)
- Another device with an ethernet port (laptop, desktop, etc.)

### Setup Steps

1. **Connect the cable** between your laptop's ethernet port and the
   other device's ethernet port. A crossover cable is not needed on
   modern hardware (Auto-MDIX handles it).

2. **Open Network Connections**
   - Press `Win + R`, type `ncpa.cpl`, press Enter

3. **Enable ICS on your WiFi adapter**
   - Right-click your **WiFi** adapter -> Properties
   - Go to the **Sharing** tab
   - Check **"Allow other network users to connect through this
     computer's Internet connection"**
   - In the dropdown, select your **Ethernet** adapter
   - Click OK

4. **Verify**
   - Your ethernet adapter will automatically get IP `192.168.137.1`
   - The connected device will get a DHCP address in `192.168.137.x`
   - The connected device should have internet access

5. **Start NetWatch**
   - Run NetWatch as Administrator
   - It will detect **Hotspot mode** on the `192.168.137.0/24` subnet
   - Connected devices will appear in the dashboard

### Disabling ICS

1. Open `ncpa.cpl`
2. Right-click WiFi adapter -> Properties -> Sharing tab
3. Uncheck the sharing option
4. Click OK

---

## macOS — Internet Sharing

macOS can share its WiFi (or any connection) over Ethernet, Thunderbolt,
or USB.

### Setup Steps

1. **Connect the cable** between your Mac and the other device.

2. **Open System Settings**
   - Go to **General** -> **Sharing**
   - (On older macOS: System Preferences -> Sharing)

3. **Configure Internet Sharing**
   - Click the (i) icon next to **Internet Sharing**
   - **Share your connection from:** WiFi (or whichever has internet)
   - **To computers using:** Ethernet / Thunderbolt Bridge / USB
   - Toggle Internet Sharing ON

4. **Verify**
   - macOS creates a `bridge100` interface on `192.168.2.0/24`
   - The connected device gets a DHCP address in `192.168.2.x`

5. **Start NetWatch**
   - Run with `sudo` for packet capture privileges
   - Detects as Hotspot mode on the bridge interface

---

## Linux — Connection Sharing

### Option A: NetworkManager (Easiest)

1. **Connect the cable**

2. **Open Network Settings**
   - Click the ethernet connection
   - Go to **IPv4 Settings**
   - Change Method to **"Shared to other computers"**
   - Apply

3. NetworkManager automatically:
   - Assigns `10.42.0.1` to the ethernet interface
   - Runs a DHCP server for connected devices
   - Enables NAT/masquerading

### Option B: Manual (iptables + dnsmasq)

```bash
# 1. Assign a static IP to the ethernet interface
sudo ip addr add 192.168.137.1/24 dev eth0

# 2. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 3. Set up NAT (replace wlan0 with your internet-facing interface)
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 4. Start dnsmasq for DHCP
sudo dnsmasq --interface=eth0 --dhcp-range=192.168.137.100,192.168.137.200,12h --no-daemon
```

---

## Ethernet vs Port Mirroring

| Feature | Ethernet Mode | Port Mirror Mode |
|---------|--------------|-----------------|
| **Connection** | Standard LAN port on router/switch | Dedicated SPAN/mirror port on managed switch |
| **Traffic visible** | Own traffic + broadcasts + some unicast (hubs) | ALL traffic from mirrored ports |
| **Scope** | LOCAL_NETWORK | ALL_TRAFFIC |
| **BPF filter** | `net <subnet> or ip6` | None (captures everything) |
| **Promiscuous mode** | ON | ON |
| **ARP scanning** | Yes | Yes |
| **Detection** | Non-WiFi adapter with valid IP + gateway | >50% foreign MAC addresses in traffic |
| **Use case** | Home/office LAN monitoring | Enterprise network monitoring |

### How NetWatch Tells Them Apart

- **Ethernet mode**: Detected when the adapter is a physical non-WiFi
  interface with a valid IP address and a default gateway. Most traffic
  has the host's own MAC as source or destination.

- **Port mirror mode**: Detected when captured traffic contains a high
  proportion (>50%) of MAC addresses that don't belong to the host.
  This indicates the switch is forwarding other devices' frames to
  this port.

---

## Expected Behavior

### ICS Host (Sharing Internet)

- **Mode**: Hotspot
- **Devices shown**: Connected client devices only
- **Host device**: Hidden (host is the gateway)
- **Gateway (router)**: Hidden
- **Traffic**: Upload = clients' downloads, Download = clients' uploads

### ICS Client (Receiving Internet)

- **Mode**: Ethernet
- **Devices shown**: Self + gateway (the sharing computer)
- **Host device**: Visible with hostname
- **Traffic**: Own upload/download traffic

### Standard Ethernet (Router/Switch)

- **Mode**: Ethernet
- **Devices shown**: Self + gateway/router + other LAN devices
  (visibility depends on switch behavior)
- **Host device**: Visible
- **ARP scan**: Discovers devices on the subnet

---

## Troubleshooting

### ICS not working on Windows

- Make sure you're sharing FROM WiFi TO Ethernet (not the reverse)
- The ethernet adapter must not have a static IP configured
- Try disabling and re-enabling ICS
- Check Windows Firewall isn't blocking ICS

### Connected device not getting an IP

- Verify the cable is connected (check link lights)
- On the connected device, release/renew DHCP:
  - Windows: `ipconfig /release && ipconfig /renew`
  - Linux: `sudo dhclient -r eth0 && sudo dhclient eth0`
  - macOS: Toggle the ethernet connection off and on

### NetWatch not detecting the mode

- Ensure NetWatch is running as Administrator (Windows) or root (Linux/macOS)
- Check that the ethernet adapter has an IP address assigned
- For ICS: verify the adapter shows `192.168.137.1`
