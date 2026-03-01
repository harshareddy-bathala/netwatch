"""
network_discovery.py - Advanced Network Device Discovery
==========================================================

This module provides robust network device discovery using multiple methods:
1. ARP Scanning - Discover all devices on local network
2. mDNS/Bonjour Discovery - Find devices advertising services
3. NetBIOS Scanning - Discover Windows devices
4. Passive Discovery - Extract devices from captured traffic
5. DHCP Snooping - Monitor DHCP to find new devices

Works regardless of monitoring mode (WiFi client, hotspot, ethernet).
Requires administrator/root privileges.
"""

import os
import sys
import socket
import struct
import threading
import time
import logging
import subprocess
import re
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# Scapy imports
try:
    from scapy.all import (
        ARP, Ether, IP, ICMP, UDP, TCP, srp, sr1, send, sniff,
        conf, get_if_addr, get_if_hwaddr, DNSRR, DNSQR, DNS,
        Raw, NBNSQueryRequest, NBNSQueryResponse
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not available. Network discovery limited.")

# Setup logging
logger = logging.getLogger(__name__)


class NetworkDiscovery:
    """
    Advanced network device discovery engine.
    
    Discovers devices using multiple techniques to provide
    comprehensive network visibility regardless of connection mode.
    """
    
    def __init__(self, interface: str = None, subnet: str = None):
        """
        Initialize NetworkDiscovery.
        
        Args:
            interface: Network interface to use (None for auto-detect)
            subnet: Target subnet in CIDR format (e.g., '192.168.1.0/24')
                   If None, auto-detects from interface
        """
        self.interface = interface
        self.subnet = subnet
        self.discovered_devices: Dict[str, Dict] = {}  # MAC -> device info
        self._max_discovered_devices: int = 10_000  # prevent unbounded growth
        self.discovery_lock = threading.Lock()
        self.running = False
        self.discovery_thread = None

        # Self-exclusion sets — IPs and MACs belonging to this host.
        # Populated by the caller (e.g. main.py) via set_exclusions().
        self.exclude_ips: Set[str] = set()
        self.exclude_macs: Set[str] = set()  # upper-case MACs

        # Discovery settings
        self.arp_timeout = 2  # seconds
        self.ping_timeout = 1  # seconds
        self.scan_interval = 60  # seconds between full scans
        
        # Auto-detect subnet if not provided
        if not self.subnet and self.interface:
            self.subnet = self._detect_subnet()
        
        logger.info("NetworkDiscovery initialized (interface: %s, subnet: %s)", interface, self.subnet)

    # Compiled once — matches exactly 6 groups of 2 hex digits separated
    # by ':' or '-'.  Used to reject malformed MACs like ':::'.
    _MAC_RE = re.compile(
        r'^[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}$'
    )

    @classmethod
    def is_valid_mac(cls, mac: str) -> bool:
        """Return *True* if *mac* looks like a well-formed Ethernet address."""
        return bool(cls._MAC_RE.match(mac))

    def set_exclusions(
        self,
        ips: Optional[Set[str]] = None,
        macs: Optional[Set[str]] = None,
    ) -> None:
        """Set (or clear) the host's own IPs / MACs so scans can skip them."""
        self.exclude_ips = ips or set()
        self.exclude_macs = {m.upper() for m in (macs or set())}

    def _is_self(self, ip: Optional[str], mac: Optional[str]) -> bool:
        """Return *True* if the IP or MAC belongs to this host."""
        if ip and ip in self.exclude_ips:
            return True
        if mac and mac.upper() in self.exclude_macs:
            return True
        return False

    def _detect_subnet(self) -> Optional[str]:
        """Detect the local subnet using the real interface netmask (not /24 assumption)."""
        try:
            # Try netifaces first for accurate netmask
            try:
                import netifaces
                addrs = netifaces.ifaddresses(self.interface)
                ipv4_list = addrs.get(netifaces.AF_INET, [])
                for entry in ipv4_list:
                    ip = entry.get('addr')
                    netmask = entry.get('netmask')
                    if ip and ip != '0.0.0.0' and netmask:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        return str(network)
            except ImportError:
                pass
            except Exception:
                pass

            # Fallback: use Scapy with /24 assumption if netifaces unavailable
            if not SCAPY_AVAILABLE:
                return None
            
            ip = get_if_addr(self.interface)
            if ip and ip != '0.0.0.0':
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                return str(network)
        except Exception as e:
            logger.error("Error detecting subnet: %s", e)
        return None
    
    def _get_local_network_info(self) -> Tuple[str, str, str]:
        """
        Get local network information.
        
        Returns:
            Tuple of (local_ip, local_mac, gateway_ip)
        """
        local_ip = None
        local_mac = None
        gateway_ip = None
        
        try:
            if SCAPY_AVAILABLE and self.interface:
                local_ip = get_if_addr(self.interface)
                local_mac = get_if_hwaddr(self.interface)
            
            # Try to get gateway
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['ipconfig'],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            gw = parts[1].strip()
                            if gw and gw[0].isdigit():
                                gateway_ip = gw
                                break
            else:
                result = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True, text=True, timeout=5
                )
                match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    gateway_ip = match.group(1)
                    
        except Exception as e:
            logger.debug("Error getting network info: %s", e)
        
        return local_ip, local_mac, gateway_ip
    
    # =========================================================================
    # ARP SCANNING
    # =========================================================================
    
    def arp_scan(self, subnet: str = None, timeout: float = None) -> List[Dict]:
        """
        Perform ARP scan to discover all devices on the network.
        
        ARP scanning works at Layer 2 and can discover ALL devices
        on the local network segment, regardless of firewall settings.
        
        Args:
            subnet: Target subnet (default: auto-detected)
            timeout: Scan timeout in seconds
            
        Returns:
            List of discovered devices with IP, MAC, hostname
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, using fallback ARP method")
            return self._arp_scan_fallback()
        
        target_subnet = subnet or self.subnet
        if not target_subnet:
            logger.error("No subnet specified for ARP scan")
            return []
        
        timeout = timeout or self.arp_timeout
        discovered = []
        
        try:
            logger.info("Starting ARP scan on %s", target_subnet)
            
            # Create ARP request packet
            # Ether: broadcast to all devices
            # ARP: who-has query for each IP in subnet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet)
            
            # Send and receive responses
            answered, unanswered = srp(
                arp_request,
                iface=self.interface,
                timeout=timeout,
                verbose=False,
                retry=1
            )
            
            for sent, received in answered:
                dev_ip = received.psrc
                dev_mac = received.hwsrc.upper()

                # Skip our own host's IPs and MACs
                if self._is_self(dev_ip, dev_mac):
                    continue

                device = {
                    'ip': dev_ip,
                    'mac': dev_mac,
                    'hostname': self._resolve_hostname(dev_ip),
                    'discovery_method': 'arp',
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'vendor': self._get_mac_vendor(received.hwsrc)
                }
                discovered.append(device)
                self._add_device(device)
            
            # Only log at INFO level when device count changes
            prev_count = getattr(self, '_last_arp_device_count', -1)
            if len(discovered) != prev_count:
                logger.info("ARP scan found %d devices", len(discovered))
                self._last_arp_device_count = len(discovered)
            else:
                logger.debug("ARP scan: %d devices (unchanged)", len(discovered))
            
        except PermissionError:
            logger.error("ARP scan requires administrator privileges")
        except Exception as e:
            logger.error("ARP scan error: %s", e)
        
        return discovered
    
    def _arp_scan_fallback(self) -> List[Dict]:
        """Fallback ARP scan using system arp command."""
        return self.arp_cache_scan()

    def arp_cache_scan(self) -> List[Dict]:
        """
        Scan the OS ARP cache for devices on our subnet.

        Unlike ``_arp_scan_fallback`` (which was only called when Scapy
        was unavailable), this is cheap and always useful — the cache may
        contain entries for devices that don't respond to our ARP
        broadcast (e.g. WiFi client isolation on mobile hotspots).
        """
        discovered = []
        subnet_prefix = None
        if self.subnet:
            try:
                net = ipaddress.IPv4Network(self.subnet, strict=False)
                subnet_prefix = net
            except (ValueError, TypeError):
                pass

        try:
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True, text=True, timeout=10
                )
                # Parse Windows arp output
                for line in result.stdout.split('\n'):
                    match = re.search(
                        r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+\w+',
                        line
                    )
                    if match:
                        ip, mac = match.groups()
                        mac = mac.replace('-', ':').upper()
                        # Filter to our subnet
                        if subnet_prefix:
                            try:
                                if ipaddress.IPv4Address(ip) not in subnet_prefix:
                                    continue
                            except (ValueError, TypeError):
                                continue
                        # Skip broadcast / incomplete entries
                        if mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                            continue
                        # Reject malformed MACs (e.g. ':::')
                        if not self.is_valid_mac(mac):
                            continue
                        # Skip our own host's IPs and MACs
                        if self._is_self(ip, mac):
                            continue
                        device = {
                            'ip': ip,
                            'mac': mac,
                            'hostname': self._resolve_hostname(ip),
                            'discovery_method': 'arp_cache',
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now()
                        }
                        discovered.append(device)
                        self._add_device(device)
            else:
                result = subprocess.run(
                    ['arp', '-n'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    match = re.search(
                        r'(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([0-9a-fA-F:]+)',
                        line
                    )
                    if match:
                        ip, mac = match.groups()
                        mac = mac.upper()
                        if subnet_prefix:
                            try:
                                if ipaddress.IPv4Address(ip) not in subnet_prefix:
                                    continue
                            except (ValueError, TypeError):
                                continue
                        if mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                            continue
                        # Reject malformed MACs (e.g. ':::')
                        if not self.is_valid_mac(mac):
                            continue
                        # Skip our own host's IPs and MACs
                        if self._is_self(ip, mac):
                            continue
                        device = {
                            'ip': ip,
                            'mac': mac,
                            'hostname': self._resolve_hostname(ip),
                            'discovery_method': 'arp_cache',
                            'first_seen': datetime.now(),
                            'last_seen': datetime.now()
                        }
                        discovered.append(device)
                        self._add_device(device)

        except Exception as e:
            logger.error("ARP cache scan error: %s", e)

        if discovered:
            logger.info("ARP cache scan found %d devices on subnet", len(discovered))
        return discovered
    
    # =========================================================================
    # PING SWEEP
    # =========================================================================
    
    def ping_sweep(self, subnet: str = None, max_workers: int = 50) -> List[Dict]:
        """
        Perform ICMP ping sweep to discover responsive devices.
        
        Args:
            subnet: Target subnet
            max_workers: Maximum concurrent ping threads
            
        Returns:
            List of responding devices
        """
        target_subnet = subnet or self.subnet
        if not target_subnet:
            return []
        
        discovered = []
        
        try:
            network = ipaddress.IPv4Network(target_subnet, strict=False)
            hosts = list(network.hosts())
            
            logger.info("Starting ping sweep of %d hosts", len(hosts))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._ping_host, str(ip)): str(ip)
                    for ip in hosts
                }
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            discovered.append(result)
                            self._add_device(result)
                    except Exception as e:
                        logger.debug("Ping error for %s: %s", ip, e)
            
            logger.info("Ping sweep found %d responding hosts", len(discovered))
            
        except Exception as e:
            logger.error("Ping sweep error: %s", e)
        
        return discovered
    
    def _ping_host(self, ip: str) -> Optional[Dict]:
        """Ping a single host."""
        try:
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(int(self.ping_timeout * 1000)), ip],
                    capture_output=True, timeout=self.ping_timeout + 1
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(self.ping_timeout), ip],
                    capture_output=True, timeout=self.ping_timeout + 1
                )
            
            if result.returncode == 0:
                return {
                    'ip': ip,
                    'hostname': self._resolve_hostname(ip),
                    'discovery_method': 'ping',
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                }
        except Exception:
            pass
        return None
    
    # =========================================================================
    # mDNS / BONJOUR DISCOVERY
    # =========================================================================
    
    def mdns_discover(self, duration: int = 5) -> List[Dict]:
        """
        Discover devices using mDNS/Bonjour.
        
        Many devices advertise services via mDNS (Apple devices,
        Chromecast, smart TVs, printers, etc.)
        
        Args:
            duration: Listen duration in seconds
            
        Returns:
            List of discovered devices
        """
        if not SCAPY_AVAILABLE:
            return []
        
        discovered = []
        seen_ips = set()
        
        def mdns_callback(pkt):
            try:
                if pkt.haslayer(DNSRR):
                    # Extract device info from DNS response
                    for i in range(pkt[DNS].ancount):
                        rr = pkt[DNS].an[i]
                        if hasattr(rr, 'rdata'):
                            rdata = rr.rdata
                            # Check if it's an IP address response
                            if isinstance(rdata, str) and re.match(r'\d+\.\d+\.\d+\.\d+', rdata):
                                if rdata not in seen_ips:
                                    seen_ips.add(rdata)
                                    device = {
                                        'ip': rdata,
                                        'hostname': str(rr.rrname).rstrip('.'),
                                        'discovery_method': 'mdns',
                                        'first_seen': datetime.now(),
                                        'last_seen': datetime.now(),
                                        'service': 'mDNS advertised'
                                    }
                                    discovered.append(device)
                                    self._add_device(device)
            except Exception as e:
                logger.debug("mDNS parse error: %s", e)
        
        try:
            logger.info("Starting mDNS discovery for %s seconds", duration)
            
            # Listen for mDNS traffic (port 5353)
            sniff(
                iface=self.interface,
                filter="udp port 5353",
                prn=mdns_callback,
                timeout=duration,
                store=False
            )
            
            logger.info("mDNS discovery found %d devices", len(discovered))
            
        except Exception as e:
            logger.error("mDNS discovery error: %s", e)
        
        return discovered
    
    # =========================================================================
    # DHCP MONITORING
    # =========================================================================
    
    def start_dhcp_monitoring(self):
        """
        Start monitoring DHCP traffic to detect new devices joining the network.
        """
        if not SCAPY_AVAILABLE:
            return
        
        def dhcp_callback(pkt):
            try:
                if pkt.haslayer(UDP) and (pkt[UDP].sport == 67 or pkt[UDP].dport == 67):
                    if pkt.haslayer(IP):
                        # DHCP traffic detected
                        if pkt.haslayer(Ether):
                            device = {
                                'mac': pkt[Ether].src.upper(),
                                'discovery_method': 'dhcp',
                                'first_seen': datetime.now(),
                                'last_seen': datetime.now()
                            }
                            if pkt[IP].src != '0.0.0.0':
                                device['ip'] = pkt[IP].src
                            self._add_device(device)
            except Exception as e:
                logger.debug("DHCP monitoring error: %s", e)
        
        try:
            sniff(
                iface=self.interface,
                filter="udp port 67 or udp port 68",
                prn=dhcp_callback,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error("DHCP monitoring error: %s", e)
    
    # =========================================================================
    # PASSIVE TRAFFIC ANALYSIS
    # =========================================================================
    
    def extract_devices_from_traffic(self, packet) -> Optional[Dict]:
        """
        Extract device information from captured network traffic.
        
        This is called for every captured packet to passively
        discover devices from actual network activity.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Device info dict if new device found, None otherwise
        """
        try:
            device = None
            
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src.upper()
                dst_mac = packet[Ether].dst.upper()
                
                # Extract source device
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Add source device if not broadcast
                    if src_mac != "FF:FF:FF:FF:FF:FF":
                        device = {
                            'ip': src_ip,
                            'mac': src_mac,
                            'discovery_method': 'traffic',
                            'last_seen': datetime.now()
                        }
                        self._add_device(device)
                    
                    # Add destination device if local and not broadcast
                    if self._is_local_ip(dst_ip) and dst_mac != "FF:FF:FF:FF:FF:FF":
                        dst_device = {
                            'ip': dst_ip,
                            'mac': dst_mac,
                            'discovery_method': 'traffic',
                            'last_seen': datetime.now()
                        }
                        self._add_device(dst_device)
            
            return device
            
        except Exception as e:
            logger.debug("Traffic extraction error: %s", e)
            return None
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is in the local network range."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private and not ip_obj.is_loopback
        except:
            return False
    
    # =========================================================================
    # DEVICE MANAGEMENT
    # =========================================================================
    
    def _add_device(self, device: Dict):
        """Add or update a device in the discovered devices list."""
        mac = device.get('mac', device.get('ip', 'unknown'))
        ip = device.get('ip')

        # Reject malformed MACs (e.g. ':::') before touching the dict
        if mac and mac != 'unknown' and not self.is_valid_mac(mac):
            logger.debug("Rejecting device with invalid MAC: %s", mac)
            return

        # Skip our own host's IPs and MACs
        if self._is_self(ip, mac):
            return

        with self.discovery_lock:
            if mac in self.discovered_devices:
                # Update existing device
                existing = self.discovered_devices[mac]
                existing['last_seen'] = datetime.now()
                
                # Update IP if provided and device didn't have one
                if 'ip' in device and not existing.get('ip'):
                    existing['ip'] = device['ip']
                
                # Add hostname if we didn't have it
                if 'hostname' in device and not existing.get('hostname'):
                    existing['hostname'] = device['hostname']
            else:
                # Evict oldest entries when at capacity (#42 — bound dict)
                if len(self.discovered_devices) >= self._max_discovered_devices:
                    oldest_mac = min(
                        self.discovered_devices,
                        key=lambda m: self.discovered_devices[m].get('last_seen', datetime.min),
                    )
                    del self.discovered_devices[oldest_mac]

                # New device
                if 'first_seen' not in device:
                    device['first_seen'] = datetime.now()
                device['last_seen'] = datetime.now()
                self.discovered_devices[mac] = device
                logger.info("New device discovered: %s - %s", device.get('ip', 'unknown'), mac)
    
    def get_all_devices(self) -> List[Dict]:
        """Get list of all discovered devices."""
        with self.discovery_lock:
            return list(self.discovered_devices.values())
    
    def get_device_count(self) -> int:
        """Get count of discovered devices."""
        return len(self.discovered_devices)
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Return a passively-learned hostname for *ip*, or ``None``.

        Only checks the passive hostname cache (DHCP Option 12, mDNS,
        NetBIOS-NS, SSDP).  Does **not** trigger active resolution
        (rDNS, NetBIOS query) because those are unreliable during
        discovery scans — especially on Windows hotspot where the ICS
        DNS server returns wrong/host-leaked names for client IPs.

        Active resolution is handled asynchronously by the background
        hostname resolver after the device is enqueued via
        ``enqueue_for_resolution()``.
        """
        try:
            from packet_capture.hostname_resolver import get_passive_hostname
            return get_passive_hostname(ip)
        except ImportError:
            return None
    
    def _get_mac_vendor(self, mac: str) -> Optional[str]:
        """
        Get vendor name from MAC address OUI.
        Uses first 3 octets of MAC address.
        """
        # Basic OUI lookup table (expandable)
        OUI_TABLE = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '08:00:27': 'VirtualBox',
            '00:15:5D': 'Hyper-V',
            '00:1A:11': 'Google',
            'AC:67:5D': 'Apple',
            '3C:22:FB': 'Apple',
            'F4:5C:89': 'Apple',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:E0:4C': 'Realtek',
            '54:E1:AD': 'Intel',
            '8C:85:90': 'Intel',
            '00:23:24': 'Samsung',
            'A8:1E:84': 'Samsung',
            '00:26:AB': 'Xiaomi',
            '64:CE:31': 'Xiaomi',
        }
        
        try:
            oui = mac[:8].upper()
            return OUI_TABLE.get(oui)
        except:
            return None
    
    # =========================================================================
    # CONTINUOUS DISCOVERY
    # =========================================================================
    
    def start_continuous_discovery(self, interval: int = None):
        """
        Start continuous background device discovery.
        
        Args:
            interval: Seconds between full scans (default: 60)
        """
        self.running = True
        self.scan_interval = interval or self.scan_interval
        
        def discovery_loop():
            logger.info("Starting continuous network discovery")
            
            while self.running:
                try:
                    # Perform ARP scan
                    self.arp_scan()
                    
                    # Wait for next scan
                    for _ in range(self.scan_interval):
                        if not self.running:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    logger.error("Discovery loop error: %s", e)
                    time.sleep(10)
            
            logger.info("Continuous discovery stopped")
        
        self.discovery_thread = threading.Thread(
            target=discovery_loop,
            daemon=True,
            name="NetworkDiscovery"
        )
        self.discovery_thread.start()
    
    def stop_continuous_discovery(self):
        """Stop continuous discovery."""
        self.running = False
        if self.discovery_thread:
            self.discovery_thread.join(timeout=5)


class PortMirrorDetector:
    """
    Detect if we're connected to a port mirror/SPAN port on a switch.
    
    Port mirroring allows full network visibility. This class detects
    if such a configuration is active.
    """
    
    @staticmethod
    def detect_port_mirror(interface: str = None, duration: int = 10) -> Tuple[bool, str]:
        """
        Detect if interface is receiving mirrored/SPAN traffic.
        
        Signs of port mirroring:
        1. Receiving traffic with foreign source MACs
        2. Traffic between IPs that don't involve our interface
        3. High volume of diverse traffic
        
        Args:
            interface: Network interface to check
            duration: Monitoring duration in seconds
            
        Returns:
            Tuple of (is_mirror_detected, description)
        """
        if not SCAPY_AVAILABLE:
            return False, "Scapy not available"
        
        try:
            local_mac = get_if_hwaddr(interface).upper() if interface else None
            local_ip = get_if_addr(interface) if interface else None
            
            foreign_src_macs = set()
            foreign_traffic = 0
            local_traffic = 0
            
            def analyze_packet(pkt):
                nonlocal foreign_traffic, local_traffic
                
                try:
                    if pkt.haslayer(Ether):
                        src_mac = pkt[Ether].src.upper()
                        dst_mac = pkt[Ether].dst.upper()
                        
                        # Check if traffic involves us
                        if local_mac and src_mac != local_mac and dst_mac != local_mac:
                            if dst_mac != "FF:FF:FF:FF:FF:FF":  # Not broadcast
                                foreign_traffic += 1
                                foreign_src_macs.add(src_mac)
                        else:
                            local_traffic += 1
                except:
                    pass
            
            # Capture traffic for analysis
            sniff(
                iface=interface,
                prn=analyze_packet,
                timeout=duration,
                store=False
            )
            
            # Analyze results
            total_traffic = foreign_traffic + local_traffic
            if total_traffic == 0:
                return False, "No traffic captured"
            
            foreign_ratio = foreign_traffic / total_traffic
            unique_foreign_macs = len(foreign_src_macs)
            
            # Heuristics for port mirror detection
            if foreign_ratio > 0.5 and unique_foreign_macs > 3:
                return True, f"Port mirror detected: {foreign_ratio*100:.1f}% foreign traffic from {unique_foreign_macs} unique MACs"
            elif foreign_ratio > 0.2:
                return True, f"Possible port mirror: {foreign_ratio*100:.1f}% foreign traffic"
            else:
                return False, f"Normal traffic pattern ({foreign_ratio*100:.1f}% foreign)"
                
        except PermissionError:
            return False, "Administrator privileges required"
        except Exception as e:
            return False, f"Detection error: {e}"


# =============================================================================
# PROMISCUOUS MODE HANDLER
# =============================================================================

class PromiscuousModeHandler:
    """
    Handle promiscuous mode operations on network interfaces.
    
    Promiscuous mode allows capturing ALL traffic on the network segment,
    not just traffic destined for this interface.
    """
    
    @staticmethod
    def enable_promiscuous(interface: str) -> bool:
        """
        Enable promiscuous mode on interface.
        
        Args:
            interface: Network interface name
            
        Returns:
            True if successful
        """
        try:
            if sys.platform == 'win32':
                # Windows: Handled by Npcap/WinPcap automatically
                # When sniffing, set promisc=True
                return True
            else:
                # Linux: Use ip command
                subprocess.run(
                    ['ip', 'link', 'set', interface, 'promisc', 'on'],
                    check=True, capture_output=True
                )
                logger.info("Promiscuous mode enabled on %s", interface)
                return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to enable promiscuous mode: %s", e)
            return False
        except Exception as e:
            logger.error("Error enabling promiscuous mode: %s", e)
            return False
    
    @staticmethod
    def disable_promiscuous(interface: str) -> bool:
        """Disable promiscuous mode on interface."""
        try:
            if sys.platform != 'win32':
                subprocess.run(
                    ['ip', 'link', 'set', interface, 'promisc', 'off'],
                    check=True, capture_output=True
                )
                logger.info("Promiscuous mode disabled on %s", interface)
            return True
        except Exception as e:
            logger.error("Error disabling promiscuous mode: %s", e)
            return False
    
    @staticmethod
    def check_promiscuous(interface: str) -> bool:
        """Check if promiscuous mode is active on interface."""
        try:
            if sys.platform == 'win32':
                return True  # Assume available on Windows with Npcap
            else:
                result = subprocess.run(
                    ['ip', 'link', 'show', interface],
                    capture_output=True, text=True
                )
                return 'PROMISC' in result.stdout
        except:
            return False


# =============================================================================
# FULL NETWORK SCANNER
# =============================================================================

class FullNetworkScanner:
    """
    Comprehensive network scanner combining all discovery methods.
    
    Provides the most complete network visibility possible.
    """
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.discovery = NetworkDiscovery(interface=interface)
        self.port_mirror_detected = False
        self.promiscuous_enabled = False
    
    def initialize(self) -> Dict:
        """
        Initialize scanner with optimal settings.
        
        Returns:
            Status dictionary with capabilities
        """
        status = {
            'interface': self.interface,
            'promiscuous_mode': False,
            'port_mirror_detected': False,
            'discovery_enabled': True,
            'capabilities': []
        }
        
        # Enable promiscuous mode
        if PromiscuousModeHandler.enable_promiscuous(self.interface):
            self.promiscuous_enabled = True
            status['promiscuous_mode'] = True
            status['capabilities'].append('promiscuous_capture')
        
        # Check for port mirroring
        is_mirror, desc = PortMirrorDetector.detect_port_mirror(self.interface, duration=5)
        if is_mirror:
            self.port_mirror_detected = True
            status['port_mirror_detected'] = True
            status['capabilities'].append('port_mirror')
        
        # Always have these capabilities
        status['capabilities'].extend([
            'arp_scanning',
            'ping_sweep',
            'passive_discovery',
            'dhcp_monitoring'
        ])
        
        return status
    
    def full_scan(self) -> Dict:
        """
        Perform a comprehensive network scan using all methods.
        
        Returns:
            Scan results with all discovered devices
        """
        results = {
            'scan_time': datetime.now().isoformat(),
            'methods_used': [],
            'devices': [],
            'summary': {}
        }
        
        # 1. ARP Scan (most reliable)
        arp_devices = self.discovery.arp_scan()
        results['methods_used'].append('arp')
        
        # 2. Ping Sweep (finds devices that block ARP)
        ping_devices = self.discovery.ping_sweep()
        results['methods_used'].append('ping')
        
        # 3. mDNS Discovery (finds smart devices)
        mdns_devices = self.discovery.mdns_discover(duration=3)
        results['methods_used'].append('mdns')
        
        # Get all discovered devices
        all_devices = self.discovery.get_all_devices()
        results['devices'] = all_devices
        
        # Summary
        results['summary'] = {
            'total_devices': len(all_devices),
            'arp_found': len(arp_devices),
            'ping_found': len(ping_devices),
            'mdns_found': len(mdns_devices),
            'port_mirror_mode': self.port_mirror_detected,
            'promiscuous_mode': self.promiscuous_enabled
        }
        
        return results
    
    def get_monitoring_capabilities(self) -> str:
        """Get human-readable description of monitoring capabilities."""
        caps = []
        
        if self.port_mirror_detected:
            caps.append("Full network visibility via port mirroring")
        if self.promiscuous_enabled:
            caps.append("Promiscuous mode enabled for enhanced capture")
        
        caps.append("Active device discovery via ARP/Ping/mDNS")
        caps.append("Passive traffic analysis")
        caps.append("DHCP monitoring for new devices")
        
        return " | ".join(caps)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'NetworkDiscovery',
    'PortMirrorDetector', 
    'PromiscuousModeHandler',
    'FullNetworkScanner',
    'SCAPY_AVAILABLE'
]
