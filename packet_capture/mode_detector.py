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
    _cidr_from_ip_and_mask,
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

    def detect_for_interface(self, iface: InterfaceInfo) -> BaseMode:
        """
        Determine the best mode for a *specific* interface.

        Unlike :meth:`detect` (which picks the best interface automatically),
        this method classifies a single pre-selected interface and returns
        the appropriate mode.

        Args:
            iface: The :class:`InterfaceInfo` to classify.

        Returns:
            A concrete :class:`BaseMode` subclass instance.
        """
        # Temporarily set _all_interfaces so the _check_* helpers work
        saved = self._all_interfaces
        self._all_interfaces = [iface]

        try:
            # Re-use the same priority chain as detect()
            if IS_WINDOWS:
                self._prefetch_windows_data()

            hotspot = self._check_hotspot()
            if hotspot:
                return hotspot

            ethernet = self._check_ethernet()
            if ethernet:
                return ethernet

            wifi = self._check_wifi_client()
            if wifi:
                return wifi

            return self._safe_fallback()
        finally:
            self._all_interfaces = saved

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
        #
        # NOTE: hotspot_virtual is intentionally NOT excluded here —
        # it must remain in _all_interfaces so _check_hotspot() can
        # find the Windows Mobile Hotspot adapter.  Mode-specific
        # checks (ethernet, wifi_client, port_mirror) already exclude
        # it via their own interface_type filters.
        real = [
            i for i in active
            if i.interface_type not in ("virtual", "bluetooth")
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
        """Build interface list using PowerShell/WMI (locale-independent).

        Falls back to ``ipconfig /all`` parsing only when PowerShell fails.
        """
        interfaces = self._enumerate_windows_interfaces_wmi()
        if interfaces:
            # Enrich WiFi interfaces with SSID
            ssid = self._get_windows_ssid()
            if ssid:
                for iface in interfaces:
                    if iface.interface_type == "wifi":
                        iface.ssid = ssid
            return interfaces

        # Fallback: parse ipconfig (English-only labels)
        return self._enumerate_windows_interfaces_ipconfig()

    def _enumerate_windows_interfaces_wmi(self) -> List[InterfaceInfo]:
        """Use PowerShell Get-NetIPConfiguration for locale-independent parsing."""
        ps_cmd = (
            "Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "$alias = $_.InterfaceAlias; "
            "$desc  = $_.InterfaceDescription; "
            "$ipv4  = ($_.IPv4Address | Select-Object -First 1).IPAddress; "
            "$mask  = ($_.IPv4Address | Select-Object -First 1).PrefixLength; "
            "$gw    = ($_.IPv4DefaultGateway | Select-Object -First 1).NextHop; "
            "$mac   = $_.NetAdapter.MacAddress; "
            "$status = $_.NetAdapter.Status; "
            "$type  = $_.NetAdapter.InterfaceDescription; "
            "\"$alias|$desc|$ipv4|$mask|$gw|$mac|$status|$type\" "
            "}"
        )
        out = run_command(["powershell", "-NoProfile", "-Command", ps_cmd])
        if not out:
            return []

        interfaces: List[InterfaceInfo] = []
        for line in out.strip().splitlines():
            parts = line.strip().split("|")
            if len(parts) < 8:
                continue
            alias, desc, ipv4, prefix, gw, mac, status, itype = (
                p.strip() for p in parts
            )
            if not ipv4 or ipv4 == "" or status.lower() not in ("up", ""):
                continue
            # Convert prefix length to netmask
            netmask = None
            if prefix and prefix.isdigit():
                try:
                    netmask = str(
                        ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
                    )
                except Exception:
                    pass
            # Normalise MAC
            if mac:
                mac = mac.replace("-", ":").lower()
            else:
                mac = None
            iface = InterfaceInfo(
                name=alias,
                friendly_name=alias,
                ip_address=ipv4 if ipv4 else None,
                netmask=netmask,
                gateway=gw if gw else None,
                mac_address=mac,
                interface_type=self._guess_type_windows(desc or "", alias),
                is_active=True,
            )
            interfaces.append(iface)
        return interfaces

    def _enumerate_windows_interfaces_ipconfig(self) -> List[InterfaceInfo]:
        """Legacy fallback: parse ``ipconfig /all`` (English-only labels)."""
        interfaces: List[InterfaceInfo] = []

        out = ModeDetector._ipconfig_cache
        if out is None:
            out = run_command(["ipconfig", "/all"])
        if not out:
            return interfaces

        current: Optional[InterfaceInfo] = None
        for line in out.splitlines():
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

            if "IPv4 Address" in stripped or "IP Address" in stripped:
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if ip_match:
                    current.ip_address = ip_match.group(1)

            elif "Subnet Mask" in stripped:
                mask_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if mask_match:
                    current.netmask = mask_match.group(1)

            elif "Default Gateway" in stripped:
                gw_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
                if gw_match:
                    current.gateway = gw_match.group(1)

            elif "Physical Address" in stripped:
                mac_match = re.search(
                    r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", stripped
                )
                if mac_match:
                    current.mac_address = mac_match.group(1).replace("-", ":").lower()

        if current and current.ip_address:
            current.is_active = True
            interfaces.append(current)

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

    # Class-level cache for macOS hardware port → interface mapping
    _macos_hw_ports: Optional[Dict[str, str]] = None
    _macos_hw_ports_time: float = 0

    @staticmethod
    def _guess_type_macos(name: str) -> str:
        n = name.lower()
        if n in ("lo0",):
            return "loopback"
        # VPN / tunnel interfaces
        if n.startswith(("utun", "tun", "tap", "ipsec", "ppp")):
            return "virtual"
        if n.startswith(("bridge", "awdl", "llw")):
            return "virtual"

        # Use networksetup -listallhardwareports to detect real type
        now = time.time()
        if (
            ModeDetector._macos_hw_ports is None
            or now - ModeDetector._macos_hw_ports_time > 30
        ):
            hw_map: Dict[str, str] = {}
            try:
                out = run_command(["networksetup", "-listallhardwareports"])
                if out:
                    current_type = None
                    for line in out.splitlines():
                        line = line.strip()
                        if line.startswith("Hardware Port:"):
                            port_name = line.split(":", 1)[1].strip().lower()
                            if "wi-fi" in port_name or "airport" in port_name:
                                current_type = "wifi"
                            elif "ethernet" in port_name or "thunderbolt" in port_name:
                                current_type = "ethernet"
                            elif "bluetooth" in port_name:
                                current_type = "bluetooth"
                            else:
                                current_type = "unknown"
                        elif line.startswith("Device:") and current_type:
                            dev = line.split(":", 1)[1].strip()
                            if dev:
                                hw_map[dev.lower()] = current_type
                            current_type = None
            except Exception:
                pass
            ModeDetector._macos_hw_ports = hw_map
            ModeDetector._macos_hw_ports_time = now

        hw = ModeDetector._macos_hw_ports or {}
        if n in hw:
            return hw[n]

        # Fallback heuristics if networksetup was unavailable
        if n.startswith(("en", "eth")):
            return "ethernet"
        return "unknown"

    # ================================================================== #
    #  MODE CHECKS — in priority order
    # ================================================================== #

    def _check_port_mirror(self, source_macs: List[str]) -> Optional[PortMirrorMode]:
        """Return PortMirrorMode if traffic analysis suggests a SPAN port."""
        # MAC-based heuristic: check ALL non-loopback, non-virtual interfaces
        # (including WiFi — a WiFi adapter can receive mirrored traffic on
        # some enterprise setups via monitor mode).
        for iface in self._all_interfaces:
            if iface.mac_address and iface.interface_type not in (
                "loopback", "virtual", "bluetooth", "hotspot_virtual"
            ):
                is_mirror = PortMirrorMode.detect_mirror_traffic(
                    source_macs,
                    iface.mac_address,
                    threshold=PORT_MIRROR_FOREIGN_MAC_THRESHOLD,
                )
                if is_mirror:
                    return PortMirrorMode(iface)

        # Promiscuous-mode probe: if no source MACs were provided but we
        # have an interface, try a short Scapy sniff to see if we receive
        # frames with foreign source MACs (indicates mirror / monitor mode).
        if not source_macs:
            mirror_iface = self._probe_promiscuous_mode()
            if mirror_iface:
                return PortMirrorMode(mirror_iface)

        return None

    def _probe_promiscuous_mode(self) -> Optional[InterfaceInfo]:
        """
        Short Scapy sniff in promiscuous mode to detect mirrored traffic.

        Captures ~20 packets and checks whether a majority have foreign
        source MACs — the hallmark of a SPAN/mirror port.
        """
        try:
            from scapy.all import sniff, Ether  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("Scapy not available for promiscuous probe")
            return None

        for iface in self._all_interfaces:
            if not iface.mac_address or iface.interface_type in (
                "loopback", "virtual", "bluetooth", "hotspot_virtual"
            ):
                continue
            try:
                pkts = sniff(
                    iface=iface.name,
                    count=20,
                    timeout=3,
                    store=True,
                )
                src_macs = [
                    pkt[Ether].src for pkt in pkts if pkt.haslayer(Ether)
                ]
                if src_macs and PortMirrorMode.detect_mirror_traffic(
                    src_macs,
                    iface.mac_address,
                    threshold=PORT_MIRROR_FOREIGN_MAC_THRESHOLD,
                ):
                    logger.info(
                        "Promiscuous probe detected mirror traffic on %s",
                        iface.name,
                    )
                    return iface
            except Exception as exc:
                logger.debug(
                    "Promiscuous probe failed on %s: %s", iface.name, exc
                )
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
        Windows 10/11 Mobile Hotspot detection.

        Detection strategy (ordered by reliability):

        1. **Active hotspot virtual adapter** — Windows Mobile Hotspot
           creates a "Microsoft Wi-Fi Direct Virtual Adapter" named
           "Local Area Connection* N".  When the hotspot is active the
           adapter receives a valid private IP (typically 192.168.137.1
           for ICS).  Checking for an active ``hotspot_virtual`` adapter
           with a routable IP is the most reliable method for Win10/11.

        2. **Legacy ``netsh wlan show hostednetwork``** — For the older
           ``netsh wlan start hostednetwork`` API.  Checks for
           ``Status: Started``.

        3. **Fallback: any adapter on 192.168.137.x** — ICS default.

        NOTE: The Win10/11 Mobile Hotspot uses Wi-Fi Direct and does
        **not** register with ``WlanHostedNetworkSvc``, so we must NOT
        gate on that service.
        """
        # ── Strategy 1: Active hotspot virtual adapter (Win10/11 Mobile Hotspot)
        # This covers Mobile Hotspot which uses Wi-Fi Direct and does NOT
        # register with WlanHostedNetworkSvc.
        for iface in self._all_interfaces:
            if (
                iface.interface_type == "hotspot_virtual"
                and iface.ip_address
                and iface.ip_address not in ("0.0.0.0", "127.0.0.1")
                and not iface.ip_address.startswith("169.254.")
            ):
                # Sanity check: hotspot adapter must be on a DIFFERENT
                # subnet than the Wi-Fi client adapter.  If they share a
                # subnet the adapter is not acting as a real hotspot.
                wifi_subnets: set = set()
                for other in self._all_interfaces:
                    if other.interface_type == "wifi" and other.ip_address and other.netmask:
                        ws = _cidr_from_ip_and_mask(other.ip_address, other.netmask)
                        if ws:
                            wifi_subnets.add(ws)

                hotspot_subnet = _cidr_from_ip_and_mask(
                    iface.ip_address,
                    iface.netmask or "255.255.255.0",
                )

                if hotspot_subnet and hotspot_subnet in wifi_subnets:
                    logger.debug(
                        "Hotspot adapter %s shares subnet with Wi-Fi (%s) — skipping",
                        iface.name, hotspot_subnet,
                    )
                    continue

                # Enrich interface with hotspot SSID if available
                iface.ssid = self._get_hotspot_ssid()

                logger.info(
                    "Hotspot detected via virtual adapter: %s (%s), subnet=%s",
                    iface.name, iface.ip_address, hotspot_subnet,
                )
                return HotspotMode(iface, hotspot_subnet=hotspot_subnet)

        # ── Strategy 2: Legacy hosted network (netsh wlan show hostednetwork)
        hosted_out = ModeDetector._hostednet_cache
        if hosted_out is None:
            hosted_out = run_command(["netsh", "wlan", "show", "hostednetwork"])
        if hosted_out and "Started" in hosted_out:
            # Hosted network is active — find its adapter
            for iface in self._all_interfaces:
                if iface.interface_type == "hotspot_virtual" and iface.ip_address:
                    subnet = _cidr_from_ip_and_mask(
                        iface.ip_address,
                        iface.netmask or "255.255.255.0",
                    )
                    iface.ssid = self._get_hotspot_ssid()
                    logger.info(
                        "Hotspot detected via legacy hosted network: %s (%s), subnet=%s",
                        iface.name, iface.ip_address, subnet,
                    )
                    return HotspotMode(iface, hotspot_subnet=subnet)

            # Fallback: any adapter on 192.168.137.x (ICS default subnet)
            for iface in self._all_interfaces:
                if iface.ip_address and iface.ip_address.startswith("192.168.137."):
                    subnet = _cidr_from_ip_and_mask(
                        iface.ip_address,
                        iface.netmask or "255.255.255.0",
                    )
                    return HotspotMode(iface, hotspot_subnet=subnet)

        logger.debug("No active hotspot detected on Windows")
        return None

    @staticmethod
    def _get_hotspot_ssid() -> Optional[str]:
        """Extract the hotspot SSID from ``netsh wlan show hostednetwork``."""
        hosted_out = ModeDetector._hostednet_cache
        if hosted_out is None:
            hosted_out = run_command(["netsh", "wlan", "show", "hostednetwork"])
        if hosted_out:
            for line in hosted_out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        if ssid:
                            return ssid
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
        """Return EthernetMode if we have an active non-WiFi physical adapter with a valid IP and gateway."""
        for iface in self._all_interfaces:
            if (
                iface.interface_type not in (
                    "wifi", "virtual", "loopback", "bluetooth", "hotspot_virtual"
                )
                and iface.ip_address
                and iface.ip_address not in ("0.0.0.0", "127.0.0.1")
                and not iface.ip_address.startswith("169.254.")
                and iface.gateway
            ):
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

    # ================================================================== #
    #  PUBLIC / PRIVATE NETWORK DETECTION (Windows NLM API)
    # ================================================================== #

    @staticmethod
    def detect_network_category() -> Optional[str]:
        """
        Use the Windows Network List Manager (NLM) COM API to determine
        whether the active network connection is ``public``, ``private``,
        or ``domain_authenticated``.

        Returns
        -------
        str or None
            ``"public"``, ``"private"``, ``"domain_authenticated"``,
            or ``None`` if detection is unavailable (non-Windows or COM error).

        The NLM ``NLM_NETWORK_CATEGORY`` enum values are:
            0 = NLM_NETWORK_CATEGORY_PUBLIC
            1 = NLM_NETWORK_CATEGORY_PRIVATE
            2 = NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED
        """
        if not IS_WINDOWS:
            return None

        try:
            import comtypes  # type: ignore[import-untyped]
            from comtypes import GUID, HRESULT, CoClass  # noqa: F401

            # Network List Manager CLSID & IID
            CLSID_NetworkListManager = GUID("{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")
            IID_INetworkListManager = GUID("{DCB00000-570F-4A9B-8D69-199FDBA5723B}")

            nlm = comtypes.CoCreateInstance(
                CLSID_NetworkListManager, interface=None
            )
            # INetworkListManager::GetConnectedNetworks
            networks = nlm.GetNetworks(1)  # NLM_ENUM_NETWORK_CONNECTED = 1
            categories = []
            for net in networks:
                cat = net.GetCategory()
                categories.append(cat)

            if not categories:
                return None

            # If ANY connected network is domain, treat as domain
            if 2 in categories:
                return "domain_authenticated"
            # If ANY is private, treat as private
            if 1 in categories:
                return "private"
            return "public"

        except ImportError:
            # comtypes not installed — fall back to PowerShell
            pass
        except Exception as exc:
            logger.debug("NLM COM API failed: %s — trying PowerShell fallback", exc)

        # PowerShell fallback (works without comtypes)
        try:
            out = run_command([
                "powershell", "-Command",
                "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"
            ])
            if out:
                raw = out.strip().lower()
                if "domain" in raw:
                    return "domain_authenticated"
                if "private" in raw:
                    return "private"
                if "public" in raw:
                    return "public"
        except Exception as exc:
            logger.debug("PowerShell network category detection failed: %s", exc)

        return None

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
