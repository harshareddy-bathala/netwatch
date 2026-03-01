"""
public_network_mode.py - Public / Untrusted Network Safe Mode
==============================================================

The **default safe fallback** when the mode detector cannot confidently
determine the network type, or when the user explicitly enables safe mode.

Key behaviour:
    - Promiscuous mode: OFF
    - Scope: OWN_TRAFFIC_ONLY
    - BPF filter: ``ether host <our_mac>``
    - ARP scan: NEVER (would probe other people's devices)
    - ARP cache scan: DISABLED (no device discovery at all)
    - Passive discovery: OFF
    - safe_for_public: True

**What happens if we can't detect the mode — what's the safe default?**

PublicNetworkMode.  It assumes the worst case (coffee-shop WiFi, hotel
network, airport lounge) and adopts the most restrictive posture:
    - No promiscuous mode
    - No ARP scanning
    - No ARP cache scanning
    - No passive discovery of neighbours
    - BPF filter limited to our own MAC only
    - Dashboard shows only our own device

This guarantees we never accidentally eavesdrop on, probe, or even
enumerate devices on a network that isn't ours.
"""

import logging
from typing import Optional

from .base_mode import (
    BaseMode,
    InterfaceInfo,
    ModeCapabilities,
    ModeName,
    NetworkScope,
    _cidr_from_ip_and_mask,
)

logger = logging.getLogger(__name__)


class PublicNetworkMode(BaseMode):
    """
    Safe-mode for untrusted / public networks.

    This mode is intentionally restrictive.  If the mode detector is unsure
    about the network topology, returning ``PublicNetworkMode`` is always the
    correct choice — it never does anything that could violate network policy
    or expose other users' traffic.
    """

    # ------------------------------------------------------------------ #
    # Abstract method implementations
    # ------------------------------------------------------------------ #

    def get_mode_name(self) -> ModeName:
        return ModeName.PUBLIC_NETWORK

    def get_bpf_filter(self) -> str:
        """Only capture our own traffic — no exceptions.

        Uses ``ether host <mac>`` to capture both IPv4 and IPv6 traffic.
        A pure ``host <ip>`` filter only matches IPv4, silently dropping
        all IPv6 video/web traffic and causing bandwidth under-reporting.
        """
        mac = self._interface.mac_address
        ip = self._interface.ip_address
        if mac:
            # BPF expects colon-separated lowercase MAC
            mac = mac.lower().replace("-", ":")
            return f"ether host {mac}"
        if ip:
            return f"host {ip} or ip6"
        logger.warning("PublicNetworkMode: no IP/MAC known — using restrictive fallback")
        return "host 0.0.0.0"

    def get_valid_ip_range(self) -> Optional[str]:
        """
        Returns the detected subnet for informational purposes only.
        The BPF filter still restricts to our single host.
        """
        ip = self._interface.ip_address
        mask = self._interface.netmask
        if ip and mask:
            return _cidr_from_ip_and_mask(ip, mask)
        return None

    def _get_capabilities(self) -> ModeCapabilities:
        return ModeCapabilities(
            can_see_other_devices=False,
            should_use_promiscuous=False,
            scope=NetworkScope.OWN_TRAFFIC_ONLY,
            can_arp_scan=False,
            can_arp_cache_scan=False,
            can_do_passive_discovery=False,
            safe_for_public=True,
            description=(
                "Public / safe mode — own traffic only, no active scanning, "
                "no promiscuous mode, no device discovery. No ARP cache or "
                "network probing is performed. "
                "Designed for untrusted networks (coffee shops, airports, campus WiFi)."
            ),
        )

    # ------------------------------------------------------------------ #
    # Overrides
    # ------------------------------------------------------------------ #

    def get_description(self) -> str:
        ip = self._interface.ip_address or "no IP"
        ssid = self._interface.ssid
        net_info = f"SSID: {ssid}" if ssid else "wired"
        return f"Public Network (Safe Mode) — {ip} ({net_info}), own traffic only"
