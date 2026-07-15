"""
hotspot_mode.py - Hotspot Monitoring Mode
==========================================

Active when THIS device is hosting a WiFi hotspot (Mobile Hotspot, ICS,
hostapd, or macOS Internet Sharing). Captures traffic for all connected
clients on the hotspot subnet.

Key behaviour:
    - Promiscuous mode: ON (need to see client-to-client traffic)
    - Scope: CONNECTED_CLIENTS
    - BPF filter: restricts capture to the hotspot subnet
    - ARP scan: allowed (our subnet, our rules)
    - Provides list of connected client MACs

Platform specifics:
    Windows  → ICS uses 192.168.137.0/24; Mobile Hotspot may vary.
    Linux    → Depends on hostapd/dnsmasq config; often 192.168.12.0/24.
    macOS    → Internet Sharing uses 192.168.2.0/24 by default.
"""

import logging
import re
from typing import Dict, List, Optional, Set

from .base_mode import (
    BaseMode,
    InterfaceInfo,
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    ModeCapabilities,
    ModeName,
    NetworkScope,
    _cidr_from_ip_and_mask,
    run_command,
)

logger = logging.getLogger(__name__)

# Default hotspot subnets per platform
_DEFAULT_HOTSPOT_SUBNETS: Dict[str, str] = {
    "windows_ics": "192.168.137.0/24",
    "windows_mobile": "192.168.137.0/24",
    "linux_hostapd": "192.168.12.0/24",
    "macos_sharing": "192.168.2.0/24",
}


class HotspotMode(BaseMode):
    """
    Monitoring mode for when this device is **hosting** a WiFi hotspot.

    Detection is strict: the mode detector must verify that the local machine
    is actually running a hotspot service, **not** merely connected to someone
    else's hotspot.  See ``mode_detector.py`` for the detection logic.
    """

    def __init__(self, interface_info: InterfaceInfo, hotspot_subnet: Optional[str] = None):
        super().__init__(interface_info)
        # If caller already knows the subnet, accept it; otherwise detect.
        self._hotspot_subnet = hotspot_subnet or self._detect_hotspot_subnet()

    # ------------------------------------------------------------------ #
    # Abstract method implementations
    # ------------------------------------------------------------------ #

    def get_mode_name(self) -> ModeName:
        return ModeName.HOTSPOT

    def get_bpf_filter(self) -> str:
        """
        BPF filter for hotspot mode — capture ALL traffic on this adapter.

        The hotspot creates a **dedicated** virtual adapter (e.g.
        ``Local Area Connection* 10`` on Windows ICS, ``bridge100`` on macOS).
        All traffic on this adapter belongs to the hotspot — there is no risk
        of capturing unrelated traffic from other networks.

        Uses an **empty filter** (capture everything) instead of ``ip or ip6``
        so we never miss traffic due to Ethernet-type mismatches on Windows
        ICS virtual adapters.  The PacketProcessor already ignores non-IP
        frames (returns None), so the only cost is a few extra ARP/LLC
        frames being dequeued and discarded — negligible on a hotspot adapter
        serving a handful of clients.

        This approach ensures we capture:

        * **All NATted data traffic** — on some Windows ICS adapters, the
          ``ip`` BPF token (= ``ether proto 0x0800``) can miss frames whose
          Ethernet type isn't set to the standard value by the virtual adapter
          driver.  An empty filter bypasses this entirely.
        * **DHCP DISCOVER/REQUEST** (broadcast) for passive hostname learning.
        * **IPv6 traffic** from connected clients.
        * **ARP** frames for device discovery.
        """
        return ""

    def get_valid_ip_range(self) -> Optional[str]:
        return self._hotspot_subnet

    def _get_capabilities(self) -> ModeCapabilities:
        return ModeCapabilities(
            can_see_other_devices=True,
            should_use_promiscuous=True,
            scope=NetworkScope.CONNECTED_CLIENTS,
            can_arp_scan=True,
            can_do_passive_discovery=True,
            safe_for_public=False,
            description=(
                "Hotspot mode — capturing traffic for devices connected to "
                "our hosted hotspot."
            ),
        )

    # ------------------------------------------------------------------ #
    # Hotspot-specific public API
    # ------------------------------------------------------------------ #

    def get_connected_clients(self) -> List[Dict[str, str]]:
        """
        Return a list of connected client dicts with keys:
            ``mac``, ``ip`` (if known), ``status``.

        **How do you get the list of connected clients on a Windows hotspot?**
        On Windows, ``netsh wlan show hostednetwork`` reports connected peers.
        For ICS, parsing the ARP table (``arp -a``) for the hotspot subnet
        is the most reliable cross-version approach.  On Linux, ``hostapd_cli
        all_sta`` or parsing ``/var/lib/misc/dnsmasq.leases`` works.  On macOS,
        the ARP table on ``bridge100`` is the simplest option.
        """
        if IS_WINDOWS:
            return self._get_windows_clients()
        elif IS_LINUX:
            return self._get_linux_clients()
        elif IS_MACOS:
            return self._get_macos_clients()
        return []

    def get_connected_client_macs(self) -> Set[str]:
        """Convenience: return just the MAC addresses of connected clients."""
        return {c["mac"] for c in self.get_connected_clients() if c.get("mac")}

    def _collect_local_macs(self) -> Set[str]:
        """Return normalized MAC addresses that belong to this host.

        Hotspot virtual adapters are not always exposed consistently across
        APIs on Windows, so combine the mode-interface MAC with psutil data.
        """
        local_macs: Set[str] = set()

        iface_mac = (getattr(self._interface, "mac_address", "") or "").strip()
        if iface_mac:
            local_macs.add(iface_mac.lower().replace("-", ":"))

        try:
            import psutil

            for _name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name in ("AF_LINK", "AF_PACKET"):
                        mac = (addr.address or "").strip()
                        if mac and mac not in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
                            local_macs.add(mac.lower().replace("-", ":"))
        except (ImportError, Exception):
            pass

        return local_macs

    # ------------------------------------------------------------------ #
    # Subnet detection (private)
    # ------------------------------------------------------------------ #

    def _detect_hotspot_subnet(self) -> Optional[str]:
        """Auto-detect the hotspot subnet from the interface state.

        Phase 5: Handles Wi-Fi Direct adapters that may use subnets other
        than the traditional 192.168.137.0/24 (e.g. 192.168.49.0/24 or
        172.x ranges).  The IP+mask from the interface snapshot is always
        preferred; platform defaults are only used as a last resort.
        """
        ip = self._interface.ip_address
        mask = self._interface.netmask

        # Best case: we have IP + mask from the interface snapshot
        if ip and mask:
            cidr = _cidr_from_ip_and_mask(ip, mask)
            if cidr:
                return cidr

        # Phase 5: if we have an IP but no mask, derive a /24 from
        # the IP address (better than falling back to hard-coded
        # 192.168.137.0/24 when the hotspot is Wi-Fi Direct).
        if ip:
            import ipaddress as _ipaddress
            try:
                net = _ipaddress.IPv4Network(f"{ip}/24", strict=False)
                return str(net)
            except ValueError:
                pass

        # Platform defaults (absolute last resort)
        if IS_WINDOWS:
            if ip and ip.startswith("192.168.137."):
                return _DEFAULT_HOTSPOT_SUBNETS["windows_ics"]
            return _DEFAULT_HOTSPOT_SUBNETS["windows_mobile"]
        elif IS_LINUX:
            return self._detect_linux_hotspot_subnet() or _DEFAULT_HOTSPOT_SUBNETS["linux_hostapd"]
        elif IS_MACOS:
            return _DEFAULT_HOTSPOT_SUBNETS["macos_sharing"]

        return None

    def _detect_linux_hotspot_subnet(self) -> Optional[str]:
        """Parse dnsmasq or hostapd config to discover the subnet."""
        # Try dnsmasq config
        out = run_command(["cat", "/etc/dnsmasq.conf"])
        if out:
            match = re.search(r"dhcp-range=(\d+\.\d+\.\d+\.\d+),(\d+\.\d+\.\d+\.\d+)", out)
            if match:
                start_ip = match.group(1)
                # Derive /24 from start IP (common case)
                parts = start_ip.rsplit(".", 1)
                return f"{parts[0]}.0/24"

        # Try reading ip addr on the interface
        iface = self._interface.name
        out = run_command(["ip", "-4", "addr", "show", iface])
        if out:
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
            if match:
                import ipaddress
                net = ipaddress.IPv4Interface(f"{match.group(1)}/{match.group(2)}")
                return str(net.network)
        return None

    # ------------------------------------------------------------------ #
    # Client enumeration (private, per-platform)
    # ------------------------------------------------------------------ #

    def _get_windows_clients(self) -> List[Dict[str, str]]:
        """
        Windows: Use ``netsh wlan show hostednetwork`` for hosted-network
        peers, plus parse ``arp -a`` on the hotspot interface for ICS clients.
        """
        clients: List[Dict[str, str]] = []
        seen_macs: Set[str] = set()
        local_macs = self._collect_local_macs()

        # Method 1: Hosted-network peer list
        out = run_command(["netsh", "wlan", "show", "hostednetwork"])
        if out:
            # Parse per-line to avoid cross-line regex matches that can
            # incorrectly capture adapter BSSID metadata as a "client".
            valid_status = {"connected", "authenticated", "associated"}
            for raw_line in out.splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                # Typical lines:
                #   1  aa:bb:cc:dd:ee:ff  Authenticated
                #   aa-bb-cc-dd-ee-ff     Connected
                match = re.match(
                    r"^(?:\d+\s+)?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+([A-Za-z]+)$",
                    line,
                )
                if not match:
                    continue

                mac = match.group(1).lower().replace("-", ":")
                status_raw = (match.group(2) or "").strip()
                status = status_raw.lower()

                if status not in valid_status:
                    continue

                # Never treat our own adapter MAC as a connected client.
                if mac in local_macs:
                    continue

                if mac not in seen_macs:
                    seen_macs.add(mac)
                    clients.append({
                        "mac": mac,
                        "ip": "",
                        "status": status_raw,
                        "source": "hostednetwork",
                    })

        # Method 2: ARP table for the hotspot subnet
        arp_clients = self._parse_arp_table()

        # When hostednetwork reports clients, treat it as authoritative for
        # membership and use ARP only to fill missing IPs. This avoids ARP
        # cache-only stale peers inflating connected-client counts.
        if clients:
            arp_by_mac = {
                (c.get("mac") or "").lower().replace("-", ":"): c
                for c in arp_clients
            }
            for c in clients:
                mac = (c.get("mac") or "").lower().replace("-", ":")
                arp_hit = arp_by_mac.get(mac)
                if arp_hit and arp_hit.get("ip") and not c.get("ip"):
                    c["ip"] = arp_hit["ip"]
            return clients

        # If hostednetwork yielded nothing (platform/driver variance), fall
        # back to ARP-derived clients.
        return arp_clients

    def _get_linux_clients(self) -> List[Dict[str, str]]:
        """
        Linux: Try ``hostapd_cli all_sta``, dnsmasq leases, then ARP table.
        """
        clients: List[Dict[str, str]] = []
        seen_macs: Set[str] = set()

        # hostapd_cli
        out = run_command(["hostapd_cli", "all_sta"])
        if out:
            for match in re.finditer(
                r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out
            ):
                mac = match.group(1).lower()
                if mac not in seen_macs:
                    seen_macs.add(mac)
                    clients.append({"mac": mac, "ip": "", "status": "connected"})

        # dnsmasq leases
        out = run_command(["cat", "/var/lib/misc/dnsmasq.leases"])
        if out:
            for line in out.strip().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    mac = parts[1].lower()
                    ip = parts[2]
                    if mac not in seen_macs:
                        seen_macs.add(mac)
                        clients.append({"mac": mac, "ip": ip, "status": "leased"})

        # Fallback: ARP table
        if not clients:
            clients = self._parse_arp_table()

        return clients

    def _get_macos_clients(self) -> List[Dict[str, str]]:
        """macOS: Parse ARP table on bridge100 (Internet Sharing interface)."""
        return self._parse_arp_table()

    def _parse_arp_table(self) -> List[Dict[str, str]]:
        """
        Parse the system ARP table and return entries whose IP falls
        within the hotspot subnet.

        Filters out the host's own IP (the hotspot gateway address) so
        this machine never appears as a "connected client".
        """
        clients: List[Dict[str, str]] = []
        subnet = self.get_valid_ip_range()
        if not subnet:
            return clients

        import ipaddress
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
        except ValueError:
            return clients

        # Collect all local IPs to exclude (our own hotspot IP + other adapters)
        own_ips: set = set()
        if self._interface.ip_address:
            own_ips.add(self._interface.ip_address)
        own_macs: Set[str] = self._collect_local_macs()
        try:
            import psutil
            for _name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name == 'AF_INET' and addr.address not in ('0.0.0.0', '127.0.0.1'):
                        own_ips.add(addr.address)
        except (ImportError, Exception):
            pass

        if IS_WINDOWS:
            out = run_command(["arp", "-a"])
        else:
            out = run_command(["arp", "-an"])

        if not out:
            return clients

        for line in out.splitlines():
            # Windows format: "  192.168.137.2    aa-bb-cc-dd-ee-ff   dynamic"
            # Unix format:    "? (192.168.137.2) at aa:bb:cc:dd:ee:ff [ether] on ..."
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_match = re.search(
                r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}"
                r"[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                line,
            )
            if ip_match and mac_match:
                ip_addr = ip_match.group(1)
                try:
                    if ipaddress.IPv4Address(ip_addr) in network:
                        # Skip our own IP — the hotspot host is not a client
                        if ip_addr in own_ips:
                            continue
                        mac = mac_match.group(1).lower().replace("-", ":")
                        # Some Windows adapters can appear in ARP under
                        # non-hotspot IPs; always exclude host MACs too.
                        if mac in own_macs:
                            continue
                        clients.append({
                            "mac": mac,
                            "ip": ip_addr,
                            "status": "arp",
                            "source": "arp",
                        })
                except ValueError:
                    continue

        return clients

    # ------------------------------------------------------------------ #
    # Overrides
    # ------------------------------------------------------------------ #

    def get_description(self) -> str:
        subnet = self.get_valid_ip_range() or "unknown subnet"
        num_clients = len(self.get_connected_clients())
        return (
            f"Hotspot Mode — subnet {subnet}, "
            f"{num_clients} client(s) connected"
        )
