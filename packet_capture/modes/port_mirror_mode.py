"""
port_mirror_mode.py - SPAN / Port Mirror Monitoring Mode
==========================================================

Active when this device is connected to a switch port configured for
SPAN (Switched Port Analyzer) / port mirroring, or when traffic analysis
reveals a high ratio of foreign-source MACs indicating mirrored traffic.

Key behaviour:
    - Promiscuous mode: ON (we need every frame the mirror sends)
    - Scope: ALL_TRAFFIC — we see the full switch backplane (or a subset)
    - BPF filter: ``""`` (empty — capture everything)
    - ARP scan: allowed
    - Detection heuristic: >50 % of source MACs are foreign (not ours)

This mode is typically used in enterprise environments where a network
engineer has configured a SPAN port to let NetWatch observe traffic across
the entire VLAN or selected ports.
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


class PortMirrorMode(BaseMode):
    """
    Monitoring mode for SPAN / port-mirror connections.

    **How do you detect a port mirror?**

    After a short sample capture (~100 packets) we count unique source MAC
    addresses.  If > 50 % of source MACs are *not* our own NIC's MAC, we
    are seeing mirrored traffic that isn't destined for us — the hallmark
    of a SPAN port.

    The threshold is configurable via ``PORT_MIRROR_FOREIGN_MAC_THRESHOLD``
    in ``config.py``.
    """

    # ------------------------------------------------------------------ #
    # Abstract method implementations
    # ------------------------------------------------------------------ #

    def get_mode_name(self) -> ModeName:
        return ModeName.PORT_MIRROR

    def get_bpf_filter(self) -> str:
        """
        Empty filter — capture **everything**.

        On a mirror port the whole point is full visibility.  Any BPF
        filter would defeat the purpose.
        """
        return ""

    def get_valid_ip_range(self) -> Optional[str]:
        """
        Return the local subnet if known, but this is purely informational;
        the BPF filter does not restrict by subnet.
        """
        ip = self._interface.ip_address
        mask = self._interface.netmask
        if ip and mask:
            return _cidr_from_ip_and_mask(ip, mask)
        return None

    def _get_capabilities(self) -> ModeCapabilities:
        return ModeCapabilities(
            can_see_other_devices=True,
            should_use_promiscuous=True,
            scope=NetworkScope.ALL_TRAFFIC,
            can_arp_scan=True,
            can_do_passive_discovery=True,
            safe_for_public=False,
            description=(
                "Port mirror / SPAN mode — full traffic visibility. "
                "Promiscuous mode enabled, no BPF filter."
            ),
        )

    # ------------------------------------------------------------------ #
    # Port-mirror-specific helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def detect_mirror_traffic(
        source_macs: list,
        own_mac: Optional[str],
        threshold: float = 0.50,
    ) -> bool:
        """
        Analyse a list of source MAC addresses from a sample capture.

        Args:
            source_macs: List of source MAC strings from captured packets.
            own_mac:     Our NIC's MAC address.
            threshold:   Fraction of foreign MACs above which we declare
                         port-mirror mode (default 50 %).

        Returns:
            ``True`` if the traffic pattern suggests a SPAN/mirror port.

        **What's the difference between monitoring scope in each mode?**

        - OWN_TRAFFIC_ONLY: Filter ``host <ip>`` – only our packets.
        - CONNECTED_CLIENTS: Filter ``net <hotspot_subnet>`` – our hotspot.
        - LOCAL_NETWORK: Filter ``net <LAN_subnet>`` – our Ethernet segment.
        - ALL_TRAFFIC: No filter – everything on the wire (port mirror).

        Port mirror is the only mode where ALL_TRAFFIC is appropriate
        because the switch is explicitly sending us other hosts' frames.
        """
        if not source_macs or not own_mac:
            return False

        own_mac_normalised = own_mac.lower().replace("-", ":")
        total = len(source_macs)
        foreign = sum(
            1 for m in source_macs
            if m.lower().replace("-", ":") != own_mac_normalised
        )
        ratio = foreign / total if total else 0.0

        logger.debug(
            f"Port-mirror detection: {foreign}/{total} foreign MACs "
            f"({ratio:.1%}), threshold={threshold:.0%}"
        )
        return ratio >= threshold

    # ------------------------------------------------------------------ #
    # Overrides
    # ------------------------------------------------------------------ #

    def get_description(self) -> str:
        ip = self._interface.ip_address or "no IP"
        iface = self._interface.friendly_name or self._interface.name
        return f"Port Mirror / SPAN — {iface} ({ip}), capturing all traffic"
