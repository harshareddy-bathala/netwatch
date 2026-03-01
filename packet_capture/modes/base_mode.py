"""
base_mode.py - Abstract Base Class for Network Monitoring Modes
================================================================

Defines the core abstractions that all network monitoring modes must implement.
Each mode represents a distinct network configuration (hotspot, ethernet,
public network, port mirror) and specifies how packet capture should
behave in that context.

Key abstractions:
    - NetworkScope: What traffic this mode can see
    - ModeCapabilities: What the mode is allowed/able to do
    - BaseMode: Abstract interface every mode must implement
"""

import ipaddress
import logging
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class NetworkScope(Enum):
    """
    Defines the scope of traffic visible to a monitoring mode.

    OWN_TRAFFIC_ONLY  – Only packets to/from this machine (public network).
    CONNECTED_CLIENTS – Traffic of devices connected to our hotspot.
    LOCAL_NETWORK     – Visible traffic on the local LAN segment (ethernet).
    ALL_TRAFFIC       – Everything on the wire (port-mirror / SPAN).
    """
    OWN_TRAFFIC_ONLY = auto()
    CONNECTED_CLIENTS = auto()
    LOCAL_NETWORK = auto()
    ALL_TRAFFIC = auto()


class ModeName(Enum):
    """Canonical names for each monitoring mode."""
    HOTSPOT = "hotspot"
    ETHERNET = "ethernet"
    PUBLIC_NETWORK = "public_network"
    PORT_MIRROR = "port_mirror"
    UNKNOWN = "unknown"


# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass(frozen=True)
class ModeCapabilities:
    """
    Declares what a monitoring mode is permitted and able to do.

    Attributes:
        can_see_other_devices:  True if other hosts' traffic is visible.
        should_use_promiscuous: True if the NIC should be set to promiscuous.
        scope:                  NetworkScope enum value.
        can_arp_scan:           True if active ARP discovery is allowed.
        can_arp_cache_scan:     True if reading the OS ARP cache is allowed
                                (passive — no packets sent).
        can_do_passive_discovery: True if passive MAC/IP snooping is useful.
        safe_for_public:        True if safe to run on untrusted networks.
        description:            Human-readable summary.
    """
    can_see_other_devices: bool
    should_use_promiscuous: bool
    scope: NetworkScope
    can_arp_scan: bool = True
    can_arp_cache_scan: bool = True
    can_do_passive_discovery: bool = True
    safe_for_public: bool = False
    description: str = ""


@dataclass
class InterfaceInfo:
    """
    Snapshot of a network interface's state at detection time.

    Populated by the mode detector and attached to every BaseMode instance so
    that mode methods have the information they need without re-querying the OS.
    """
    name: str = ""                          # Raw OS interface name
    friendly_name: str = ""                 # Human-friendly name (e.g. "Wi-Fi")
    ip_address: Optional[str] = None        # IPv4 address on this interface
    mac_address: Optional[str] = None       # Hardware address
    netmask: Optional[str] = None           # Subnet mask (e.g. "255.255.255.0")
    gateway: Optional[str] = None           # Default gateway through this iface
    ssid: Optional[str] = None              # WiFi SSID (None for wired)
    interface_type: str = "unknown"         # wifi | ethernet | virtual | loopback | …
    is_active: bool = False


# =============================================================================
# HELPER — subnet calculation
# =============================================================================

def _cidr_from_ip_and_mask(ip: str, netmask: str) -> Optional[str]:
    """
    Return a CIDR string like ``192.168.1.0/24`` from an IP and netmask.

    Returns None if the inputs are invalid.
    """
    try:
        iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
        return str(iface.network)
    except (ValueError, TypeError):
        return None


# =============================================================================
# PLATFORM HELPERS — used by several modes
# =============================================================================

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"


def run_command(args: List[str], timeout: int = 3) -> Optional[str]:
    """
    Run a subprocess safely and return its stdout, or ``None`` on any error.
    """
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


# =============================================================================
# ABSTRACT BASE CLASS
# =============================================================================

class BaseMode(ABC):
    """
    Abstract base class for all network monitoring modes.

    Every concrete mode **must** implement:
        - ``get_bpf_filter()``   → BPF filter string for Scapy/tcpdump.
        - ``get_valid_ip_range()`` → CIDR string or None.
        - ``_get_capabilities()``  → ModeCapabilities dataclass.

    The base class provides public convenience methods built on top of those
    abstract methods so that callers never need to care about internals.

    Usage example::

        mode = PublicNetworkMode(interface_info)
        print(mode.get_bpf_filter())        # "host 192.168.1.42"
        print(mode.should_use_promiscuous()) # False
        print(mode.get_scope())              # NetworkScope.OWN_TRAFFIC_ONLY
    """

    def __init__(self, interface_info: InterfaceInfo):
        self._interface = interface_info
        self._capabilities: Optional[ModeCapabilities] = None

    # --------------------------------------------------------------------- #
    # Abstract methods — every subclass MUST implement these
    # --------------------------------------------------------------------- #

    @abstractmethod
    def get_bpf_filter(self) -> str:
        """Return a BPF filter string appropriate for this mode."""
        ...

    @abstractmethod
    def get_valid_ip_range(self) -> Optional[str]:
        """Return the CIDR range to monitor, or ``None`` if not applicable."""
        ...

    @abstractmethod
    def _get_capabilities(self) -> ModeCapabilities:
        """Return a ``ModeCapabilities`` instance describing this mode."""
        ...

    @abstractmethod
    def get_mode_name(self) -> ModeName:
        """Return the canonical ``ModeName`` enum for this mode."""
        ...

    # --------------------------------------------------------------------- #
    # Public convenience methods
    # --------------------------------------------------------------------- #

    @property
    def capabilities(self) -> ModeCapabilities:
        """Lazily compute and cache capabilities."""
        if self._capabilities is None:
            self._capabilities = self._get_capabilities()
        return self._capabilities

    def should_use_promiscuous(self) -> bool:
        """Whether the NIC should be placed in promiscuous mode."""
        return self.capabilities.should_use_promiscuous

    def get_scope(self) -> NetworkScope:
        """Return the ``NetworkScope`` of this mode."""
        return self.capabilities.scope

    def is_safe_for_public_network(self) -> bool:
        """True when this mode will not probe or sniff other hosts."""
        return self.capabilities.safe_for_public

    def can_arp_scan(self) -> bool:
        """True if active ARP scanning is appropriate."""
        return self.capabilities.can_arp_scan

    def get_description(self) -> str:
        """Return a human-readable description of the active mode."""
        name = self.get_mode_name().value.replace("_", " ").title()
        ip = self._interface.ip_address or "unknown IP"
        ssid = self._interface.ssid
        extra = f" (SSID: {ssid})" if ssid else ""
        return f"{name} — {ip}{extra}"

    @property
    def interface(self) -> InterfaceInfo:
        """Read-only access to the interface snapshot."""
        return self._interface

    def to_dict(self) -> Dict:
        """Serialize mode state for the REST API / frontend."""
        return {
            "mode": self.get_mode_name().value,
            "description": self.get_description(),
            "bpf_filter": self.get_bpf_filter(),
            "ip_range": self.get_valid_ip_range(),
            "promiscuous": self.should_use_promiscuous(),
            "scope": self.get_scope().name,
            "safe_for_public": self.is_safe_for_public_network(),
            "can_arp_scan": self.can_arp_scan(),
            "can_arp_cache_scan": self.capabilities.can_arp_cache_scan,
            "interface": {
                "name": self._interface.name,
                "friendly_name": self._interface.friendly_name,
                "ip": self._interface.ip_address,
                "mac": self._interface.mac_address,
                "gateway": self._interface.gateway,
                "ssid": self._interface.ssid,
                "type": self._interface.interface_type,
            },
        }

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"mode={self.get_mode_name().value} "
            f"iface={self._interface.name} "
            f"ip={self._interface.ip_address}>"
        )
