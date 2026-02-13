"""
mode_detector.py - Intelligent Network Mode Detector
======================================================

Central orchestrator that inspects the current network state and returns
the correct ``BaseMode`` subclass instance.

Detection priority (highest → lowest):
    1. Port Mirror   – lots of foreign-MAC traffic
    2. Hotspot       – ONLY if **we** are hosting (verified per-platform)
    3. Ethernet      – wired interface with a gateway
    4. WiFi Client   – connected to a WiFi network as a regular client
    5. Public Network – safe fallback for anything else

**Critical rule — _is_hosting_hotspot() MUST NOT return True just because
WiFi is connected.**  On Windows it must check
``netsh wlan show hostednetwork`` for ``Status: Started`` **AND** verify
that our IP is on the expected hotspot subnet (192.168.137.x for ICS).
On Linux it checks for ``hostapd`` / ``dnsmasq`` processes.  On macOS it
checks the Internet Sharing preference.

**How do you detect when the network mode changes?**
The ``InterfaceManager`` (see ``interface_manager.py``) runs a background
thread that calls ``ModeDetector.detect()`` every 30 seconds.  If the
returned mode differs from the previous one it fires registered callbacks
so that the capture engine can reconfigure on the fly.
"""

import ipaddress
import logging
import re
import sys
import time
import threading
from typing import Dict, List, Optional, Tuple

from .modes.base_mode import (
    BaseMode,
    InterfaceInfo,
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    ModeName,
    run_command,
)
from .modes.ethernet_mode import EthernetMode
from .modes.hotspot_mode import HotspotMode
from .modes.port_mirror_mode import PortMirrorMode
from .modes.public_network_mode import PublicNetworkMode
from .modes.wifi_client_mode import WiFiClientMode

logger = logging.getLogger(__name__)

# Threshold: fraction of foreign source MACs that indicates a mirror port
PORT_MIRROR_FOREIGN_MAC_THRESHOLD = 0.50


class ModeDetector:
    """
    Stateless detector — each call to ``detect()`` inspects the live OS
    state and returns a fresh ``BaseMode`` instance.

    Usage::

        detector = ModeDetector()
        mode = detector.detect()          # Returns BaseMode subclass
        print(mode.get_bpf_filter())      # e.g. "host 192.168.1.42"
        print(mode.should_use_promiscuous())  # e.g. False
    """

    # Class-level cache to avoid re-running subprocesses on every detect()
    _ipconfig_cache: Optional[str] = None
    _ipconfig_cache_time: float = 0
    _ssid_cache: Optional[str] = None
    _ssid_cache_time: float = 0
    _hostednet_cache: Optional[str] = None
    _hostednet_cache_time: float = 0
    _CACHE_TTL = 10  # seconds — all subprocess caches share this TTL

    # Track last detected mode to avoid log spam
    _last_logged_mode: Optional[str] = None

    def __init__(self):
        self._all_interfaces: List[InterfaceInfo] = []

    # ================================================================== #
    #  PUBLIC API
    # ================================================================== #

    def detect(self, sample_source_macs: Optional[List[str]] = None) -> BaseMode:
        """
        Run the full detection pipeline and return the appropriate mode.

        Args:
            sample_source_macs: Optional list of source MAC addresses from
                a short sample capture.  Used for port-mirror heuristic.

        Returns:
            A concrete ``BaseMode`` subclass instance.
        """
        # Pre-fetch all OS data in parallel on Windows to avoid
        # sequential subprocess calls (ipconfig + netsh x2 = 3-6s sequential).
        if IS_WINDOWS:
            self._prefetch_windows_data()

        # Step 0 — gather all interface info from the OS
        self._all_interfaces = self._enumerate_interfaces()

        if not self._all_interfaces:
            logger.warning("No active network interfaces found — network disconnected")
            return self._disconnected_fallback()

        # Step 1 — Port Mirror (needs sample traffic; skip if no sample)
        if sample_source_macs:
            mirror_mode = self._check_port_mirror(sample_source_macs)
            if mirror_mode:
                self._log_mode_change("PORT_MIRROR")
                return mirror_mode

        # Step 2 — Hotspot (ONLY if we are actually hosting)
        hotspot_mode = self._check_hotspot()
        if hotspot_mode:
            self._log_mode_change("HOTSPOT")
            return hotspot_mode

        # Step 3 — Ethernet
        ethernet_mode = self._check_ethernet()
        if ethernet_mode:
            self._log_mode_change("ETHERNET")
            return ethernet_mode

        # Step 4 — WiFi Client
        wifi_mode = self._check_wifi_client()
        if wifi_mode:
            self._log_mode_change("WIFI_CLIENT")
            return wifi_mode

        # Step 5 — Fallback: Public / Safe mode
        self._log_mode_change("PUBLIC_NETWORK")
        return self._safe_fallback()

    def _log_mode_change(self, mode_name: str) -> None:
        """Only log at INFO level when the detected mode actually changes."""
        if mode_name != ModeDetector._last_logged_mode:
            logger.info("Detected mode: %s", mode_name)
            ModeDetector._last_logged_mode = mode_name
        else:
            logger.debug("Mode stable: %s", mode_name)

    def get_all_interfaces(self) -> List[InterfaceInfo]:
        """Return interfaces from the last ``detect()`` call."""
        return list(self._all_interfaces)

    # ================================================================== #
    #  INTERFACE ENUMERATION
    # ================================================================== #

    def _prefetch_windows_data(self) -> None:
        """
        Run ipconfig, netsh wlan show interfaces, and netsh wlan show
        hostednetwork in PARALLEL threads.  Results are cached for
        ``_CACHE_TTL`` seconds so repeated detect() calls are near-instant.

        This reduces first-detect time from ~4-6s (sequential) to ~1.5-2s.
        """
        now = time.time()
        needs_ipconfig = (
            ModeDetector._ipconfig_cache is None
            or (now - ModeDetector._ipconfig_cache_time) > ModeDetector._CACHE_TTL
        )
        needs_ssid = (
            ModeDetector._ssid_cache is None
            or (now - ModeDetector._ssid_cache_time) > ModeDetector._CACHE_TTL
        )
        needs_hosted = (
            ModeDetector._hostednet_cache is None
            or (now - ModeDetector._hostednet_cache_time) > ModeDetector._CACHE_TTL
        )

        if not (needs_ipconfig or needs_ssid or needs_hosted):
            return  # all caches still fresh

        results: Dict[str, Optional[str]] = {}

        def _run(key: str, args: List[str]) -> None:
            results[key] = run_command(args)

        threads: List[threading.Thread] = []
        if needs_ipconfig:
            t = threading.Thread(target=_run, args=("ipconfig", ["ipconfig", "/all"]))
            threads.append(t)
        if needs_ssid:
            t = threading.Thread(
                target=_run,
                args=("ssid", ["netsh", "wlan", "show", "interfaces"]),
            )
            threads.append(t)
        if needs_hosted:
            t = threading.Thread(
                target=_run,
                args=("hosted", ["netsh", "wlan", "show", "hostednetwork"]),
            )
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=4)

        now = time.time()
        if "ipconfig" in results:
            ModeDetector._ipconfig_cache = results["ipconfig"]
            ModeDetector._ipconfig_cache_time = now
        if "ssid" in results:
            ModeDetector._ssid_cache = results["ssid"]
            ModeDetector._ssid_cache_time = now
        if "hosted" in results:
            ModeDetector._hostednet_cache = results["hosted"]
            ModeDetector._hostednet_cache_time = now

    def _enumerate_interfaces(self) -> List[InterfaceInfo]:
        """
        Query the OS for all active network interfaces and build
        ``InterfaceInfo`` objects.
        """
        interfaces: List[InterfaceInfo] = []

        if IS_WINDOWS:
            interfaces = self._enumerate_windows_interfaces()
        elif IS_LINUX:
            interfaces = self._enumerate_linux_interfaces()
        elif IS_MACOS:
            interfaces = self._enumerate_macos_interfaces()

        # Filter to only active, non-loopback interfaces with an IP
        active = [
            iface for iface in interfaces
            if iface.is_active
            and iface.ip_address
            and iface.ip_address not in ("0.0.0.0", "127.0.0.1")
            and iface.interface_type != "loopback"
        ]

        # Prefer real (non-virtual) interfaces when available.
        # Virtual adapters (VMware, VirtualBox, Hyper-V) should not
        # cause a false "Public Network" detection when no real
        # network is connected.  If *only* virtual interfaces exist
        # we return an EMPTY list so the caller falls through to the
        # disconnected / no-network state instead of capturing on a
        # VirtualBox or VMware adapter that has nothing to do with
        # real network traffic.
        real = [
            i for i in active
            if i.interface_type not in ("virtual", "bluetooth", "hotspot_virtual")
        ]
        if real:
            return real
        # No real interfaces — return empty to signal disconnected.
        # Only keep virtual adapters if we're inside a VM (heuristic:
        # ALL active interfaces are virtual AND at least one has a gateway).
        has_gateway = any(i.gateway for i in active)
        if has_gateway:
            return active  # likely inside a VM — keep virtual adapters
        return []  # truly disconnected — no real network

    # ---- Windows -------------------------------------------------------- #

    def _enumerate_windows_interfaces(self) -> List[InterfaceInfo]:
        """Parse ``ipconfig /all`` and ``netsh`` to build interface list."""
        interfaces: List[InterfaceInfo] = []

        # Use cached output if available (populated by _prefetch_windows_data)
        out = ModeDetector._ipconfig_cache
        if out is None:
            out = run_command(["ipconfig", "/all"])
        if not out:
            return interfaces

        current: Optional[InterfaceInfo] = None
        for line in out.splitlines():
            # New adapter section
            adapter_match = re.match(r"^(\S.*adapter\s+(.+)):$", line, re.IGNORECASE)
            if adapter_match:
                if current and current.ip_address:
                    current.is_active = True
                    interfaces.append(current)
                full_header = adapter_match.group(1)
                name = adapter_match.group(2).strip()
                current = InterfaceInfo(
                    name=name,
                    friendly_name=name,
                    interface_type=self._guess_type_windows(full_header, name),
                )
                continue

            if current is None:
                continue

            stripped = line.strip()

            # IPv4 Address
            if "IPv4 Address" in stripped or "IP Address" in stripped:
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if ip_match:
                    current.ip_address = ip_match.group(1)

            # Subnet Mask
            elif "Subnet Mask" in stripped:
                mask_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if mask_match:
                    current.netmask = mask_match.group(1)

            # Default Gateway
            elif "Default Gateway" in stripped:
                gw_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if gw_match:
                    current.gateway = gw_match.group(1)

            # Physical Address (MAC)
            elif "Physical Address" in stripped:
                mac_match = re.search(
                    r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", stripped
                )
                if mac_match:
                    current.mac_address = mac_match.group(1).replace("-", ":").lower()

        # Don't forget last adapter
        if current and current.ip_address:
            current.is_active = True
            interfaces.append(current)

        # Enrich WiFi interfaces with SSID
        ssid = self._get_windows_ssid()
        if ssid:
            for iface in interfaces:
                if iface.interface_type == "wifi":
                    iface.ssid = ssid

        return interfaces

    @staticmethod
    def _guess_type_windows(header: str, name: str) -> str:
        h = (header + " " + name).lower()
        if "loopback" in h:
            return "loopback"
        # Check virtual adapters BEFORE ethernet/wifi — virtual adapter
        # names often contain "ethernet" or "wi-fi" (e.g. "VirtualBox
        # Host-Only Ethernet Adapter") and would otherwise match first.
        if any(w in h for w in ("vmware", "virtualbox", "vbox", "hyper-v", "vethernet")):
            return "virtual"
        # VPN TAP/TUN adapters — treat as virtual so they don't override
        # the real physical interface.
        if any(w in h for w in ("tap-windows", "tap adapter", "tun ", "wireguard",
                                 "openvpn", "wintun", "tailscale", "zerotier")):
            return "virtual"
        if "bluetooth" in h:
            return "bluetooth"
        if any(w in h for w in ("local area connection*", "wi-fi direct", "hosted")):
            return "hotspot_virtual"
        if any(w in h for w in ("wi-fi", "wifi", "wlan", "wireless")):
            return "wifi"
        # USB tethering (RNDIS / NCM) — treat as ethernet
        if any(w in h for w in ("rndis", "remote ndis", "usb ethernet", "ncm")):
            return "ethernet"
        if any(w in h for w in ("ethernet", "eth", "realtek", "intel(r) ethernet")):
            return "ethernet"
        return "unknown"

    @staticmethod
    def _get_windows_ssid() -> Optional[str]:
        # Use cached output if available (populated by _prefetch_windows_data)
        out = ModeDetector._ssid_cache
        if out is None:
            out = run_command(["netsh", "wlan", "show", "interfaces"])
        if not out:
            return None
        for line in out.splitlines():
            # Match SSID but not BSSID
            if "SSID" in line and "BSSID" not in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ssid = parts[1].strip()
                    if ssid:
                        return ssid
        return None

    # ---- Linux ---------------------------------------------------------- #

    def _enumerate_linux_interfaces(self) -> List[InterfaceInfo]:
        """Parse ``ip -4 addr show`` and enrich with wifi/gateway info."""
        interfaces: List[InterfaceInfo] = []
        out = run_command(["ip", "-4", "addr", "show"])
        if not out:
            return interfaces

        current_name: Optional[str] = None
        current_iface: Optional[InterfaceInfo] = None

        for line in out.splitlines():
            # Interface header: "2: enp0s3: <BROADCAST,...> ..."
            hdr = re.match(r"^\d+:\s+(\S+):", line)
            if hdr:
                if current_iface and current_iface.ip_address:
                    current_iface.is_active = True
                    interfaces.append(current_iface)
                current_name = hdr.group(1)
                current_iface = InterfaceInfo(
                    name=current_name,
                    friendly_name=current_name,
                    interface_type=self._guess_type_linux(current_name),
                )
                continue

            if current_iface is None:
                continue

            ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if ip_match:
                current_iface.ip_address = ip_match.group(1)
                # Convert prefix length to dotted netmask
                prefix = int(ip_match.group(2))
                current_iface.netmask = str(
                    ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
                )

        if current_iface and current_iface.ip_address:
            current_iface.is_active = True
            interfaces.append(current_iface)

        # Gateway
        gw_out = run_command(["ip", "route", "show", "default"])
        if gw_out:
            gw_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)", gw_out)
            if gw_match:
                gw_ip = gw_match.group(1)
                gw_dev = gw_match.group(2)
                for iface in interfaces:
                    if iface.name == gw_dev:
                        iface.gateway = gw_ip

        # SSID for wifi interfaces
        for iface in interfaces:
            if iface.interface_type == "wifi":
                ssid_out = run_command(["iwgetid", "-r", iface.name])
                if ssid_out and ssid_out.strip():
                    iface.ssid = ssid_out.strip()
                # Alternate: iw dev <iface> link
                if not iface.ssid:
                    iw_out = run_command(["iw", "dev", iface.name, "link"])
                    if iw_out:
                        m = re.search(r"SSID:\s*(.+)", iw_out)
                        if m:
                            iface.ssid = m.group(1).strip()

        # MAC addresses
        for iface in interfaces:
            mac_out = run_command(["cat", f"/sys/class/net/{iface.name}/address"])
            if mac_out and mac_out.strip():
                iface.mac_address = mac_out.strip().lower()

        return interfaces

    @staticmethod
    def _guess_type_linux(name: str) -> str:
        n = name.lower()
        if n in ("lo",):
            return "loopback"
        if n.startswith(("wl", "wlan", "ath", "ra")):
            return "wifi"
        if n.startswith(("eth", "en", "em", "eno", "enp", "ens")):
            return "ethernet"
        # USB tethering (RNDIS/NCM) — often shows as usb0 or enx...
        if n.startswith(("usb", "enx")):
            return "ethernet"
        # VPN / tunnel interfaces — treat as virtual
        if n.startswith(("tun", "tap", "wg", "tailscale", "zt")):
            return "virtual"
        if n.startswith(("docker", "br-", "veth", "virbr")):
            return "virtual"
        return "unknown"

    # ---- macOS ---------------------------------------------------------- #

    def _enumerate_macos_interfaces(self) -> List[InterfaceInfo]:
        """Parse ``ifconfig`` output on macOS."""
        interfaces: List[InterfaceInfo] = []
        out = run_command(["ifconfig"])
        if not out:
            return interfaces

        current: Optional[InterfaceInfo] = None
        for line in out.splitlines():
            hdr = re.match(r"^(\w+):\s+flags=", line)
            if hdr:
                if current and current.ip_address:
                    current.is_active = True
                    interfaces.append(current)
                name = hdr.group(1)
                current = InterfaceInfo(
                    name=name,
                    friendly_name=name,
                    interface_type=self._guess_type_macos(name),
                )
                continue

            if current is None:
                continue

            stripped = line.strip()
            inet_match = re.match(
                r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", stripped
            )
            if inet_match:
                current.ip_address = inet_match.group(1)
                # Convert hex netmask to dotted decimal
                hex_mask = int(inet_match.group(2), 16)
                current.netmask = str(ipaddress.IPv4Address(hex_mask))

            ether_match = re.match(r"ether\s+([0-9a-f:]+)", stripped)
            if ether_match:
                current.mac_address = ether_match.group(1)

        if current and current.ip_address:
            current.is_active = True
            interfaces.append(current)

        # Gateway
        gw_out = run_command(["netstat", "-rn"])
        if gw_out:
            for gw_line in gw_out.splitlines():
                if gw_line.startswith("default"):
                    parts = gw_line.split()
                    if len(parts) >= 4:
                        gw_ip = parts[1]
                        gw_iface = parts[3] if len(parts) > 3 else ""
                        for iface in interfaces:
                            if iface.name == gw_iface:
                                iface.gateway = gw_ip
                        break

        # WiFi SSID via airport
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        ssid_out = run_command([airport_path, "-I"])
        if ssid_out:
            m = re.search(r"\sSSID:\s*(.+)", ssid_out)
            if m:
                ssid = m.group(1).strip()
                for iface in interfaces:
                    if iface.interface_type == "wifi":
                        iface.ssid = ssid

        return interfaces

    @staticmethod
    def _guess_type_macos(name: str) -> str:
        n = name.lower()
        if n in ("lo0",):
            return "loopback"
        if n.startswith("en0"):
            return "wifi"  # en0 is usually WiFi on Macs
        if n.startswith(("en", "eth")):
            return "ethernet"
        # VPN / tunnel interfaces
        if n.startswith(("utun", "tun", "tap", "ipsec", "ppp")):
            return "virtual"
        if n.startswith(("bridge", "awdl", "llw")):
            return "virtual"
        return "unknown"

    # ================================================================== #
    #  MODE CHECKS — in priority order
    # ================================================================== #

    def _check_port_mirror(self, source_macs: List[str]) -> Optional[PortMirrorMode]:
        """Return PortMirrorMode if traffic analysis suggests a SPAN port."""
        # We need an active interface with a MAC to compare against
        for iface in self._all_interfaces:
            if iface.mac_address and iface.interface_type in ("ethernet", "unknown"):
                is_mirror = PortMirrorMode.detect_mirror_traffic(
                    source_macs,
                    iface.mac_address,
                    threshold=PORT_MIRROR_FOREIGN_MAC_THRESHOLD,
                )
                if is_mirror:
                    return PortMirrorMode(iface)
        return None

    def _check_hotspot(self) -> Optional[HotspotMode]:
        """
        Return HotspotMode **only** if this machine is hosting a hotspot.

        CRITICAL: This must NOT return a mode just because WiFi is connected.
        """
        if IS_WINDOWS:
            return self._check_hotspot_windows()
        elif IS_LINUX:
            return self._check_hotspot_linux()
        elif IS_MACOS:
            return self._check_hotspot_macos()
        return None

    def _check_hotspot_windows(self) -> Optional[HotspotMode]:
        """
        Windows hotspot detection — TWO conditions must BOTH be true:

        1. ``netsh wlan show hostednetwork`` reports ``Status: Started``
        2. We have an interface on the expected ICS subnet (192.168.137.x)
           **OR** a "Local Area Connection*" / "Wi-Fi Direct" virtual adapter
           with a private IP.

        Merely being connected to a WiFi network does NOT satisfy either
        condition — this is the fix for the original bug.
        """
        # ---- Condition 1: hosted network is running ----
        # Use cached output if available (populated by _prefetch_windows_data)
        out = ModeDetector._hostednet_cache
        if out is None:
            out = run_command(["netsh", "wlan", "show", "hostednetwork"])
        hosted_started = False
        if out and "Started" in out:
            # Verify it says "Status" near "Started" (not some other field)
            for line in out.splitlines():
                if "status" in line.lower() and "started" in line.lower():
                    hosted_started = True
                    break

        # Even if the legacy hosted-network is not started, Windows 10/11
        # Mobile Hotspot uses a different mechanism.  Check for a virtual
        # adapter with the well-known ICS IP range.
        ics_interface: Optional[InterfaceInfo] = None
        virtual_hotspot_interface: Optional[InterfaceInfo] = None

        for iface in self._all_interfaces:
            # ICS always uses 192.168.137.x
            if iface.ip_address and iface.ip_address.startswith("192.168.137."):
                ics_interface = iface
                break
            # Mobile Hotspot creates a "Local Area Connection*" or
            # "Microsoft Wi-Fi Direct Virtual Adapter" interface
            if iface.interface_type == "hotspot_virtual" and iface.ip_address:
                virtual_hotspot_interface = iface

        if hosted_started:
            # Prefer ICS interface, fall back to virtual adapter
            target = ics_interface or virtual_hotspot_interface
            if target:
                return HotspotMode(target)
            # hosted network is "started" but no matching interface — edge case
            # Still return hotspot if we found any virtual adapter
            for iface in self._all_interfaces:
                if iface.interface_type == "hotspot_virtual" and iface.ip_address:
                    return HotspotMode(iface)

        # Not hosted_started — check ICS adapter alone (standalone ICS without
        # the legacy hosted-network API, common on Win10/11 Mobile Hotspot)
        if ics_interface:
            # Verify that ICS is truly active by checking if the adapter has
            # both an IP AND there are ARP entries on its subnet (clients exist)
            return HotspotMode(ics_interface, hotspot_subnet="192.168.137.0/24")

        # Mobile Hotspot virtual adapter without ICS range — might be on
        # a different subnet.  Only accept if IP is in a private range
        # and it's clearly a virtual hotspot adapter.
        if virtual_hotspot_interface:
            ip = virtual_hotspot_interface.ip_address
            if ip:
                try:
                    addr = ipaddress.IPv4Address(ip)
                    if addr.is_private and not ip.startswith("169.254."):
                        return HotspotMode(virtual_hotspot_interface)
                except ValueError:
                    pass

        return None

    def _check_hotspot_linux(self) -> Optional[HotspotMode]:
        """
        Linux: hosting if ``hostapd`` or ``dnsmasq`` is running on a wifi iface.
        """
        # Check hostapd
        hostapd_running = False
        out = run_command(["pgrep", "-x", "hostapd"])
        if out and out.strip():
            hostapd_running = True

        # Check dnsmasq (often paired with hostapd for DHCP)
        dnsmasq_running = False
        out = run_command(["pgrep", "-x", "dnsmasq"])
        if out and out.strip():
            dnsmasq_running = True

        if not (hostapd_running or dnsmasq_running):
            return None

        # Find the wifi interface that hostapd is using
        # Try parsing hostapd config
        hostapd_iface: Optional[str] = None
        out = run_command(["cat", "/etc/hostapd/hostapd.conf"])
        if out:
            for line in out.splitlines():
                m = re.match(r"^interface\s*=\s*(\S+)", line)
                if m:
                    hostapd_iface = m.group(1)
                    break

        for iface in self._all_interfaces:
            if hostapd_iface and iface.name == hostapd_iface:
                return HotspotMode(iface)
            if iface.interface_type == "wifi" and hostapd_running:
                return HotspotMode(iface)

        return None

    def _check_hotspot_macos(self) -> Optional[HotspotMode]:
        """
        macOS: Check Internet Sharing pref and bridge100 interface.
        """
        # Internet Sharing creates a bridge100 interface on 192.168.2.x
        for iface in self._all_interfaces:
            if iface.name.startswith("bridge") and iface.ip_address:
                if iface.ip_address.startswith("192.168.2."):
                    return HotspotMode(iface, hotspot_subnet="192.168.2.0/24")

        # Also check the preference plist
        out = run_command([
            "defaults", "read",
            "/Library/Preferences/SystemConfiguration/com.apple.nat",
            "NAT",
        ])
        if out and "Enabled = 1" in out:
            # NAT is enabled — look for the bridge interface
            for iface in self._all_interfaces:
                if iface.name.startswith("bridge") and iface.ip_address:
                    return HotspotMode(iface)

        return None

    def _check_ethernet(self) -> Optional[EthernetMode]:
        """Return EthernetMode if we have an active wired interface with a gateway."""
        for iface in self._all_interfaces:
            if iface.interface_type == "ethernet" and iface.gateway:
                return EthernetMode(iface)
        return None

    def _check_wifi_client(self) -> Optional[WiFiClientMode]:
        """
        Return WiFiClientMode if we are connected to WiFi as a regular client.

        **This is NOT a hotspot.**  We only reach this point because
        ``_check_hotspot()`` already returned None — meaning the machine is
        NOT hosting.  Being *connected to* someone else's WiFi (or phone
        hotspot) is a client relationship, so WiFiClientMode is correct.
        """
        for iface in self._all_interfaces:
            if iface.interface_type == "wifi" and iface.ssid:
                return WiFiClientMode(iface)
        # WiFi adapter active but no SSID (odd but possible)
        for iface in self._all_interfaces:
            if iface.interface_type == "wifi" and iface.ip_address:
                return WiFiClientMode(iface)
        return None

    def _safe_fallback(self) -> PublicNetworkMode:
        """
        Return PublicNetworkMode as the ultimate safe default.

        **What happens if we can't detect the mode?**
        We return PublicNetworkMode, which:
          - Uses ``host <our_ip>`` BPF filter (own traffic only)
          - Disables promiscuous mode
          - Disables ARP scanning
          - Is safe for any network

        This is the correct default because capturing other hosts' traffic
        on an unknown network could violate privacy laws and policies.
        """
        # Pick best available interface for the fallback
        for iface in self._all_interfaces:
            if iface.ip_address:
                return PublicNetworkMode(iface)

        # Truly nothing available — create a minimal InterfaceInfo
        return self._disconnected_fallback()

    def _disconnected_fallback(self) -> PublicNetworkMode:
        """
        Return a PublicNetworkMode with a dummy interface that signals
        "no network connection" to the InterfaceManager and dashboard.

        This is used when no real network interfaces are found (e.g.
        hotspot turned off, cable unplugged, WiFi disconnected).
        """
        return PublicNetworkMode(InterfaceInfo(
            name="none",
            friendly_name="Disconnected",
            ip_address="0.0.0.0",
            is_active=False,
            interface_type="disconnected",
        ))
