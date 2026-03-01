"""
platform_helpers.py - Platform-specific subprocess helpers
==========================================================

Extracted from ``mode_detector.py`` to isolate OS-specific subprocess
invocations (PowerShell, ipconfig, netsh, ip addr, ifconfig, airport,
pgrep, etc.) and their output parsers.

This module only imports stdlib modules and ``config`` -- no circular
import risk with other packet_capture modules.
"""

import ipaddress
import logging
import re
import subprocess
import sys
import time
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform constants (defined locally so this module is self-contained)
# ---------------------------------------------------------------------------
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"


# ---------------------------------------------------------------------------
# Subprocess runner (self-contained copy -- avoids importing base_mode)
# ---------------------------------------------------------------------------

def run_command(args: List[str], timeout: int = 3) -> Optional[str]:
    """Run a subprocess safely and return its stdout, or ``None`` on any error."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        return result.stdout if result.returncode == 0 else result.stdout
    except FileNotFoundError:
        logger.debug("Command not found: %s", args[0])
        return None
    except subprocess.TimeoutExpired:
        logger.debug("Command timed out: %s", ' '.join(args))
        return None
    except Exception as exc:
        logger.debug("Command failed (%s): %s", ' '.join(args), exc)
        return None


def _cidr_from_ip_and_mask(ip: str, netmask: str) -> Optional[str]:
    """Return a CIDR string like ``192.168.1.0/24`` from an IP and netmask."""
    try:
        iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
        return str(iface.network)
    except (ValueError, TypeError):
        return None


# ================================================================== #
#  WINDOWS HELPERS
# ================================================================== #

def prefetch_windows_commands(
    needs_ipconfig: bool,
    needs_ssid: bool,
    needs_hosted: bool,
) -> Dict[str, Optional[str]]:
    """
    Run ipconfig, netsh wlan show interfaces, and netsh wlan show
    hostednetwork in PARALLEL threads.  Returns a dict mapping
    ``"ipconfig"``, ``"ssid"``, ``"hosted"`` to their command output.

    This reduces first-detect time from ~4-6s (sequential) to ~1.5-2s.
    """
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

    return results


def guess_type_windows(header: str, name: str, mac: str = "") -> str:
    """Classify a Windows network adapter by its description / alias name.

    An optional *mac* address enables OUI-based detection of virtual
    adapters whose description doesn't contain vendor keywords (e.g.
    when Windows renames the adapter to a generic "Ethernet" alias).
    """
    h = (header + " " + name).lower()
    if "loopback" in h:
        return "loopback"
    # Check virtual adapters BEFORE ethernet/wifi -- virtual adapter
    # names often contain "ethernet" or "wi-fi" (e.g. "VirtualBox
    # Host-Only Ethernet Adapter") and would otherwise match first.
    if any(w in h for w in ("vmware", "virtualbox", "vbox", "hyper-v", "vethernet")):
        return "virtual"
    # VPN TAP/TUN adapters -- treat as virtual so they don't override
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
    # MAC OUI check: catch virtual adapters whose description doesn't
    # contain vendor keywords (common when Windows renames adapters).
    #   VirtualBox  08:00:27:xx:xx:xx
    #   VMware      00:0C:29:xx:xx:xx  /  00:50:56:xx:xx:xx
    #   Hyper-V     00:15:5D:xx:xx:xx
    if mac:
        mac_norm = mac.lower().replace("-", ":")
        _VIRTUAL_MAC_PREFIXES = (
            "08:00:27:", "00:0c:29:", "00:50:56:", "00:15:5d:",
        )
        if any(mac_norm.startswith(p) for p in _VIRTUAL_MAC_PREFIXES):
            return "virtual"
    # USB tethering (RNDIS / NCM) -- treat as ethernet
    if any(w in h for w in ("rndis", "remote ndis", "usb ethernet", "ncm")):
        return "ethernet"
    if any(w in h for w in ("ethernet", "eth", "realtek", "intel(r) ethernet")):
        return "ethernet"
    return "unknown"


def get_windows_ssid(ssid_cache: Optional[str] = None) -> Optional[str]:
    """Return the current WiFi SSID on Windows, or ``None``."""
    out = ssid_cache
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


def get_hotspot_ssid(hostednet_cache: Optional[str] = None) -> Optional[str]:
    """Extract the hotspot SSID from ``netsh wlan show hostednetwork``."""
    hosted_out = hostednet_cache
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


def enumerate_windows_interfaces_wmi() -> List[dict]:
    """Use PowerShell Get-NetIPConfiguration for locale-independent parsing.

    Returns a list of dicts with InterfaceInfo-compatible keys:
    ``name``, ``friendly_name``, ``ip_address``, ``netmask``, ``gateway``,
    ``mac_address``, ``interface_type``, ``is_active``.
    """
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

    interfaces: List[dict] = []
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
        iface = dict(
            name=alias,
            friendly_name=alias,
            ip_address=ipv4 if ipv4 else None,
            netmask=netmask,
            gateway=gw if gw else None,
            mac_address=mac,
            interface_type=guess_type_windows(desc or "", alias, mac or ""),
            is_active=True,
        )
        interfaces.append(iface)
    return interfaces


def enumerate_windows_interfaces_ipconfig(
    ipconfig_cache: Optional[str] = None,
) -> List[dict]:
    """Legacy fallback: parse ``ipconfig /all`` (English-only labels).

    Returns a list of dicts with InterfaceInfo-compatible keys.
    """
    interfaces: List[dict] = []

    out = ipconfig_cache
    if out is None:
        out = run_command(["ipconfig", "/all"])
    if not out:
        return interfaces

    current: Optional[dict] = None
    for line in out.splitlines():
        adapter_match = re.match(r"^(\S.*adapter\s+(.+)):$", line, re.IGNORECASE)
        if adapter_match:
            if current and current.get("ip_address"):
                current["is_active"] = True
                interfaces.append(current)
            full_header = adapter_match.group(1)
            name = adapter_match.group(2).strip()
            current = dict(
                name=name,
                friendly_name=name,
                ip_address=None,
                netmask=None,
                gateway=None,
                mac_address=None,
                interface_type=guess_type_windows(full_header, name),
                is_active=False,
            )
            continue

        if current is None:
            continue

        stripped = line.strip()

        if "IPv4 Address" in stripped or "IP Address" in stripped:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if ip_match:
                current["ip_address"] = ip_match.group(1)

        elif "Subnet Mask" in stripped:
            mask_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if mask_match:
                current["netmask"] = mask_match.group(1)

        elif "Default Gateway" in stripped:
            gw_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if gw_match:
                current["gateway"] = gw_match.group(1)

        elif "Physical Address" in stripped:
            mac_match = re.search(
                r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", stripped
            )
            if mac_match:
                current["mac_address"] = mac_match.group(1).replace("-", ":").lower()

    if current and current.get("ip_address"):
        current["is_active"] = True
        interfaces.append(current)

    # Post-process: re-classify adapters that have a MAC now.
    # The initial classification at parse time didn't have the MAC yet,
    # so virtual adapters with generic names may have been misclassified.
    for iface in interfaces:
        mac = iface.get("mac_address") or ""
        if mac and iface.get("interface_type") not in ("loopback", "virtual", "bluetooth", "hotspot_virtual", "wifi"):
            reclassified = guess_type_windows(
                iface.get("friendly_name", ""), iface.get("name", ""), mac,
            )
            if reclassified == "virtual":
                iface["interface_type"] = "virtual"

    return interfaces


def check_hotspot_adapter_status(adapter_name: str) -> Tuple[str, str]:
    """Query a Windows adapter's Status and MediaConnectionState.

    Returns ``(status, media_state)`` strings, e.g. ``("Up", "1")``.
    Returns ``("", "")`` if the query fails.
    """
    out = run_command([
        "powershell", "-NoProfile", "-Command",
        f"Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue "
        "| Select-Object -Property Status, MediaConnectionState "
        "| ForEach-Object { \"$($_.Status)|$($_.MediaConnectionState)\" }",
    ])

    if out is None:
        return ("", "")

    raw = out.strip()
    parts = raw.split("|")
    status = parts[0].strip() if parts else ""
    media_state = parts[1].strip() if len(parts) > 1 else ""
    return (status, media_state)


def detect_network_category() -> Optional[str]:
    """
    Use the Windows Network List Manager (NLM) COM API to determine
    whether the active network connection is ``public``, ``private``,
    or ``domain_authenticated``.

    Returns ``None`` on non-Windows or if detection is unavailable.

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
        # comtypes not installed -- fall back to PowerShell
        pass
    except Exception as exc:
        logger.debug("NLM COM API failed: %s -- trying PowerShell fallback", exc)

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


# ================================================================== #
#  LINUX HELPERS
# ================================================================== #

def guess_type_linux(name: str) -> str:
    """Classify a Linux network interface by its name."""
    n = name.lower()
    if n in ("lo",):
        return "loopback"
    if n.startswith(("wl", "wlan", "ath", "ra")):
        return "wifi"
    if n.startswith(("eth", "en", "em", "eno", "enp", "ens")):
        return "ethernet"
    # USB tethering (RNDIS/NCM) -- often shows as usb0 or enx...
    if n.startswith(("usb", "enx")):
        return "ethernet"
    # VPN / tunnel interfaces -- treat as virtual
    if n.startswith(("tun", "tap", "wg", "tailscale", "zt")):
        return "virtual"
    if n.startswith(("docker", "br-", "veth", "virbr")):
        return "virtual"
    return "unknown"


def enumerate_linux_interfaces() -> List[dict]:
    """Parse ``ip -4 addr show`` and enrich with wifi/gateway info.

    Returns a list of dicts with InterfaceInfo-compatible keys.
    """
    interfaces: List[dict] = []
    out = run_command(["ip", "-4", "addr", "show"])
    if not out:
        return interfaces

    current_name: Optional[str] = None
    current_iface: Optional[dict] = None

    for line in out.splitlines():
        # Interface header: "2: enp0s3: <BROADCAST,...> ..."
        hdr = re.match(r"^\d+:\s+(\S+):", line)
        if hdr:
            if current_iface and current_iface.get("ip_address"):
                current_iface["is_active"] = True
                interfaces.append(current_iface)
            current_name = hdr.group(1)
            current_iface = dict(
                name=current_name,
                friendly_name=current_name,
                ip_address=None,
                netmask=None,
                gateway=None,
                mac_address=None,
                ssid=None,
                interface_type=guess_type_linux(current_name),
                is_active=False,
            )
            continue

        if current_iface is None:
            continue

        ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if ip_match:
            current_iface["ip_address"] = ip_match.group(1)
            # Convert prefix length to dotted netmask
            prefix = int(ip_match.group(2))
            current_iface["netmask"] = str(
                ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
            )

    if current_iface and current_iface.get("ip_address"):
        current_iface["is_active"] = True
        interfaces.append(current_iface)

    # Gateway
    gw_out = run_command(["ip", "route", "show", "default"])
    if gw_out:
        gw_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)", gw_out)
        if gw_match:
            gw_ip = gw_match.group(1)
            gw_dev = gw_match.group(2)
            for iface in interfaces:
                if iface["name"] == gw_dev:
                    iface["gateway"] = gw_ip

    # SSID for wifi interfaces
    for iface in interfaces:
        if iface["interface_type"] == "wifi":
            ssid_out = run_command(["iwgetid", "-r", iface["name"]])
            if ssid_out and ssid_out.strip():
                iface["ssid"] = ssid_out.strip()
            # Alternate: iw dev <iface> link
            if not iface.get("ssid"):
                iw_out = run_command(["iw", "dev", iface["name"], "link"])
                if iw_out:
                    m = re.search(r"SSID:\s*(.+)", iw_out)
                    if m:
                        iface["ssid"] = m.group(1).strip()

    # MAC addresses
    for iface in interfaces:
        mac_out = run_command(["cat", f"/sys/class/net/{iface['name']}/address"])
        if mac_out and mac_out.strip():
            iface["mac_address"] = mac_out.strip().lower()

    return interfaces


def check_linux_hotspot_processes() -> Tuple[bool, bool, Optional[str]]:
    """Check if hostapd or dnsmasq is running on Linux.

    Returns ``(hostapd_running, dnsmasq_running, hostapd_interface_name)``.
    """
    hostapd_running = False
    out = run_command(["pgrep", "-x", "hostapd"])
    if out and out.strip():
        hostapd_running = True

    dnsmasq_running = False
    out = run_command(["pgrep", "-x", "dnsmasq"])
    if out and out.strip():
        dnsmasq_running = True

    # Find the wifi interface that hostapd is using
    # Try parsing hostapd config
    hostapd_iface: Optional[str] = None
    if hostapd_running:
        out = run_command(["cat", "/etc/hostapd/hostapd.conf"])
        if out:
            for line in out.splitlines():
                m = re.match(r"^interface\s*=\s*(\S+)", line)
                if m:
                    hostapd_iface = m.group(1)
                    break

    return (hostapd_running, dnsmasq_running, hostapd_iface)


# ================================================================== #
#  macOS HELPERS
# ================================================================== #

def fetch_macos_hardware_ports() -> Dict[str, str]:
    """Run ``networksetup -listallhardwareports`` and return a
    ``{device_name: interface_type}`` mapping.
    """
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
    return hw_map


def guess_type_macos(name: str, hw_ports: Optional[Dict[str, str]] = None) -> str:
    """Classify a macOS network interface by its name and optional
    hardware-port mapping (from :func:`fetch_macos_hardware_ports`).
    """
    n = name.lower()
    if n in ("lo0",):
        return "loopback"
    # VPN / tunnel interfaces
    if n.startswith(("utun", "tun", "tap", "ipsec", "ppp")):
        return "virtual"
    if n.startswith(("bridge", "awdl", "llw")):
        return "virtual"

    hw = hw_ports or {}
    if n in hw:
        return hw[n]

    # Fallback heuristics if networksetup was unavailable
    if n.startswith(("en", "eth")):
        return "ethernet"
    return "unknown"


def enumerate_macos_interfaces(
    hw_ports: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """Parse ``ifconfig`` output on macOS.

    Returns a list of dicts with InterfaceInfo-compatible keys.
    """
    interfaces: List[dict] = []
    out = run_command(["ifconfig"])
    if not out:
        return interfaces

    current: Optional[dict] = None
    for line in out.splitlines():
        hdr = re.match(r"^(\w+):\s+flags=", line)
        if hdr:
            if current and current.get("ip_address"):
                current["is_active"] = True
                interfaces.append(current)
            name = hdr.group(1)
            current = dict(
                name=name,
                friendly_name=name,
                ip_address=None,
                netmask=None,
                gateway=None,
                mac_address=None,
                ssid=None,
                interface_type=guess_type_macos(name, hw_ports),
                is_active=False,
            )
            continue

        if current is None:
            continue

        stripped = line.strip()
        inet_match = re.match(
            r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)", stripped
        )
        if inet_match:
            current["ip_address"] = inet_match.group(1)
            # Convert hex netmask to dotted decimal
            hex_mask = int(inet_match.group(2), 16)
            current["netmask"] = str(ipaddress.IPv4Address(hex_mask))

        ether_match = re.match(r"ether\s+([0-9a-f:]+)", stripped)
        if ether_match:
            current["mac_address"] = ether_match.group(1)

    if current and current.get("ip_address"):
        current["is_active"] = True
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
                        if iface["name"] == gw_iface:
                            iface["gateway"] = gw_ip
                    break

    # WiFi SSID via airport
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    ssid_out = run_command([airport_path, "-I"])
    if ssid_out:
        m = re.search(r"\sSSID:\s*(.+)", ssid_out)
        if m:
            ssid = m.group(1).strip()
            for iface in interfaces:
                if iface["interface_type"] == "wifi":
                    iface["ssid"] = ssid

    return interfaces


def check_macos_internet_sharing() -> bool:
    """Return ``True`` if macOS Internet Sharing (NAT) is enabled."""
    out = run_command([
        "defaults", "read",
        "/Library/Preferences/SystemConfiguration/com.apple.nat",
        "NAT",
    ])
    return bool(out and "Enabled = 1" in out)


# ================================================================== #
#  CROSS-PLATFORM HELPERS
# ================================================================== #

def detect_gateway_netifaces() -> Optional[str]:
    """Try to detect the default gateway via the ``netifaces`` library.

    Returns the gateway IP string, or ``None`` if unavailable.
    """
    try:
        import netifaces
        gws = netifaces.gateways()
        default_gw = gws.get('default', {}).get(netifaces.AF_INET)
        if default_gw:
            gw_ip = default_gw[0]
            if gw_ip and gw_ip[0].isdigit():
                return gw_ip
    except Exception:
        pass
    return None


def detect_gateway_route_print(our_ip: str) -> Optional[str]:
    """Detect the default gateway via ``route print`` on Windows.

    Returns the gateway IP string, or ``None`` if unavailable.
    """
    try:
        out = run_command(["route", "print", "0.0.0.0"])
        if out:
            # Look for default route (0.0.0.0 mask 0.0.0.0)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    gw_ip = parts[2]
                    if gw_ip and gw_ip[0].isdigit() and gw_ip != '0.0.0.0':
                        return gw_ip
    except Exception:
        pass
    return None
