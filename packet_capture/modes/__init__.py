"""
NetWatch Network Monitoring Modes Package
==========================================

Provides the mode detection framework: an abstract ``BaseMode`` class and
five concrete implementations representing distinct network topologies.

Quick reference
---------------
=================  ============  =============  ============  =========
Mode               Promiscuous   BPF filter     ARP scan      Scope
=================  ============  =============  ============  =========
HotspotMode        ON            net <subnet>   Yes           CONNECTED_CLIENTS
WiFiClientMode     OFF           host <ip>      No            OWN_TRAFFIC_ONLY
EthernetMode       ON            net <subnet>   Yes           LOCAL_NETWORK
PublicNetworkMode  OFF           host <ip>      No            OWN_TRAFFIC_ONLY
PortMirrorMode     ON            (none)         Yes           ALL_TRAFFIC
=================  ============  =============  ============  =========

Usage::

    from packet_capture.modes import (
        BaseMode, ModeName, NetworkScope, InterfaceInfo,
        HotspotMode, WiFiClientMode, EthernetMode,
        PublicNetworkMode, PortMirrorMode,
    )
"""

from .base_mode import (
    BaseMode,
    InterfaceInfo,
    ModeCapabilities,
    ModeName,
    NetworkScope,
)
from .ethernet_mode import EthernetMode
from .hotspot_mode import HotspotMode
from .port_mirror_mode import PortMirrorMode
from .public_network_mode import PublicNetworkMode
from .wifi_client_mode import WiFiClientMode

__all__ = [
    # Base
    "BaseMode",
    "InterfaceInfo",
    "ModeCapabilities",
    "ModeName",
    "NetworkScope",
    # Concrete modes
    "HotspotMode",
    "WiFiClientMode",
    "EthernetMode",
    "PublicNetworkMode",
    "PortMirrorMode",
]
