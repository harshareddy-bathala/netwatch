"""
wifi_client_mode.py - WiFi Client Monitoring Mode
===================================================

Active when this device is connected to a WiFi network **as a client**
(i.e. NOT hosting a hotspot).

Key behaviour:
    - Promiscuous mode: OFF
    - Scope: OWN_TRAFFIC_ONLY
    - BPF filter: ``ether host <our_mac>`` — only our own packets
    - ARP scan: ENABLED (discovers other LAN devices for display)
    - Traffic capture: own traffic only (BPF filter enforced)
    - Safe for private/trusted WiFi networks

**Why does WiFi client mode enable ARP scanning but only capture own
traffic?**

The user wants to see what devices are on their local network (awareness)
without eavesdropping on other clients' traffic.  ARP scanning (L2
broadcast) is safe on private networks — the AP will respond to ARP
requests for all directly connected clients.  However, promiscuous mode
remains OFF because:

1. AP isolation: Most access points enable client isolation, so the NIC
   will never receive other clients' unicast frames regardless of
   promiscuous mode.  Enabling it wastes CPU for no benefit.
2. Noise: Even when frames *are* visible (open networks without
   isolation), they are almost always encrypted at L2 (WPA2/3) and
   therefore useless without the per-client PTK.
3. Performance: Promiscuous mode forces the NIC driver to deliver every
   frame to the kernel, increasing CPU and memory pressure on laptops.

The correct filter is  ``ether host <our_mac>``  which tells the kernel to
discard everything that isn't to/from us before it even reaches Scapy.
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


class WiFiClientMode(BaseMode):
    """
    Monitoring mode for a standard WiFi client connection.

    This is the mode that should be returned when the laptop is connected
    to someone else's WiFi — the exact scenario that the old
    ``_detect_windows_hotspot()`` was incorrectly classifying as hotspot.
    """

    # ------------------------------------------------------------------ #
    # Abstract method implementations
    # ------------------------------------------------------------------ #

    def get_mode_name(self) -> ModeName:
        return ModeName.WIFI_CLIENT

    def get_bpf_filter(self) -> str:
        """
        BPF filter: only capture packets involving our own machine.

        This is the single most important filter for fixing the original bug.
        Instead of capturing *all* wireless traffic (which is what an empty
        filter does in promiscuous mode), we restrict to our traffic only.

        **Why ``ether host <mac>`` instead of ``host <ip>``?**
        ``host <ip>`` only matches IPv4 packets.  Modern services (YouTube,
        Google, Facebook, etc.) heavily use IPv6 for streaming.  A pure
        IPv4 BPF filter silently drops all IPv6 video traffic, causing
        bandwidth readings 10-100x lower than reality.
        ``ether host <mac>`` matches on the Ethernet (L2) MAC address,
        capturing IPv4, IPv6, ARP, and any other L3 protocol in a single
        efficient kernel filter.
        """
        mac = self._interface.mac_address
        ip = self._interface.ip_address
        if mac:
            return f"ether host {mac}"
        if ip:
            # Fallback: IPv4 + all IPv6 (we can't filter IPv6 without MAC)
            return f"host {ip} or ip6"
        # If we somehow don't know our IP, capture nothing rather than everything.
        logger.warning("WiFiClientMode: no IP/MAC known — using restrictive fallback filter")
        return "host 0.0.0.0"

    def get_valid_ip_range(self) -> Optional[str]:
        """
        Return the local subnet CIDR if known, for informational purposes.

        Note: even though we know the subnet, our BPF filter is still
        ``host <our_ip>`` — we never capture other hosts' traffic.
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
            can_arp_cache_scan=True,
            can_do_passive_discovery=False,
            safe_for_public=True,
            description=(
                "WiFi client mode — monitoring own traffic only. "
                "Promiscuous mode disabled (AP isolation makes it useless). "
                "No active ARP scanning; only passive ARP cache reads to avoid "
                "probing other clients on the WLAN. Traffic capture is "
                "restricted to own MAC via BPF filter."
            ),
        )

    # ------------------------------------------------------------------ #
    # Overrides
    # ------------------------------------------------------------------ #

    def get_description(self) -> str:
        ssid = self._interface.ssid or "unknown network"
        ip = self._interface.ip_address or "no IP"
        return f"WiFi Client — connected to '{ssid}' ({ip}), own traffic only"
