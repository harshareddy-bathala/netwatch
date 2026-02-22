"""
ethernet_mode.py - Ethernet / Wired LAN Monitoring Mode
=========================================================

Active when this device is connected to a wired LAN (Ethernet).

Key behaviour:
    - Promiscuous mode: ON — on a shared switch/hub we can see broadcast and
      potentially unicast traffic for the local segment.
    - Scope: LOCAL_NETWORK
    - BPF filter: ``net <local_subnet>`` — restricts to the local LAN.
    - ARP scan: allowed (we're on the LAN).
    - Detects whether connected to a switch (many ARP entries) or a direct
      point-to-point cable (1-2 entries).
"""

import logging
import re
from typing import Optional

from .base_mode import (
    BaseMode,
    InterfaceInfo,
    IS_WINDOWS,
    ModeCapabilities,
    ModeName,
    NetworkScope,
    _cidr_from_ip_and_mask,
    run_command,
)

logger = logging.getLogger(__name__)


class EthernetMode(BaseMode):
    """
    Monitoring mode for a standard wired Ethernet connection.

    When connected via Ethernet:
    * On a hub or unmanaged switch we may see unicast frames for other hosts.
    * On a managed switch we see our own unicast + broadcast/multicast.
    * Either way, promiscuous mode lets the NIC deliver everything the switch
      sends, and the BPF filter keeps only local-subnet traffic.

    The subnet is **detected** from the interface, not hard-coded to /24.
    """

    # ------------------------------------------------------------------ #
    # Abstract method implementations
    # ------------------------------------------------------------------ #

    def get_mode_name(self) -> ModeName:
        return ModeName.ETHERNET

    def get_bpf_filter(self) -> str:
        """
        BPF filter: restrict to the local subnet CIDR + IPv6.

        We do NOT hardcode ``/24``.  The actual prefix length is read from
        the OS (e.g. ``255.255.255.0`` → ``/24``, ``255.255.0.0`` → ``/16``).

        ``or ip6`` is appended to also capture IPv6 traffic on the local
        segment.  Without it, all IPv6 streaming/web traffic is silently
        dropped, causing severe bandwidth under-reporting.
        """
        cidr = self.get_valid_ip_range()
        if cidr:
            return f"(net {cidr}) or ip6"
        # Fallback: own traffic only (IPv4 + IPv6)
        mac = self._interface.mac_address
        if mac:
            return f"ether host {mac}"
        if self._interface.ip_address:
            return f"host {self._interface.ip_address} or ip6"
        return ""

    def get_valid_ip_range(self) -> Optional[str]:
        ip = self._interface.ip_address
        mask = self._interface.netmask
        if ip and mask:
            return _cidr_from_ip_and_mask(ip, mask)
        return None

    def _get_capabilities(self) -> ModeCapabilities:
        return ModeCapabilities(
            can_see_other_devices=True,
            should_use_promiscuous=True,
            scope=NetworkScope.LOCAL_NETWORK,
            can_arp_scan=True,
            can_do_passive_discovery=True,
            safe_for_public=False,
            description=(
                "Ethernet LAN mode — monitoring local network traffic "
                "with promiscuous mode enabled."
            ),
        )

    # ------------------------------------------------------------------ #
    # Ethernet-specific helpers
    # ------------------------------------------------------------------ #

    def is_direct_connection(self) -> bool:
        """
        Heuristic: if the ARP table for this subnet has ≤ 2 entries we are
        probably connected directly to another device (point-to-point cable).
        """
        count = self._count_arp_entries()
        return count <= 2

    def is_switch_connection(self) -> bool:
        """Inverse of ``is_direct_connection``."""
        return not self.is_direct_connection()

    def _count_arp_entries(self) -> int:
        """Count ARP table entries that belong to our subnet."""
        import ipaddress

        cidr = self.get_valid_ip_range()
        if not cidr:
            return 0

        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            return 0

        if IS_WINDOWS:
            out = run_command(["arp", "-a"])
        else:
            out = run_command(["arp", "-an"])

        if not out:
            return 0

        count = 0
        for line in out.splitlines():
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                try:
                    if ipaddress.IPv4Address(ip_match.group(1)) in network:
                        count += 1
                except ValueError:
                    continue
        return count

    # ------------------------------------------------------------------ #
    # Overrides
    # ------------------------------------------------------------------ #

    def get_description(self) -> str:
        cidr = self.get_valid_ip_range() or "unknown subnet"
        gw = self._interface.gateway or "no gateway"
        conn = "switch" if self.is_switch_connection() else "direct"
        return f"Ethernet — {cidr} via {gw} ({conn} connection)"
