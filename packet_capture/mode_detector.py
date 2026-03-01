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
import time
from typing import Dict, List, Optional

from .modes.base_mode import (
    BaseMode,
    InterfaceInfo,
    IS_LINUX,
    IS_MACOS,
    IS_WINDOWS,
    run_command,
    _cidr_from_ip_and_mask,
)
from .modes.ethernet_mode import EthernetMode
from .modes.hotspot_mode import HotspotMode
from .modes.port_mirror_mode import PortMirrorMode
from .modes.public_network_mode import PublicNetworkMode
from . import platform_helpers as ph

logger = logging.getLogger(__name__)

# Threshold: fraction of foreign source MACs that indicates a mirror port
try:
    from config import PORT_MIRROR_FOREIGN_MAC_THRESHOLD
except ImportError:
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
    _adapter_status_cache: Dict[str, str] = {}   # adapter name → "Up" / "Disconnected" / …
    _adapter_status_cache_time: float = 0
    _CACHE_TTL = 3  # seconds — reduced from 10s (Phase 5) for faster reaction to network changes

    # Track last detected mode to avoid log spam
    _last_logged_mode: Optional[str] = None

    # Port-mirror promiscuous probe cooldown — avoids running a 3s Scapy
    # sniff per interface on every detection cycle (15-30s).  The probe
    # runs immediately on first boot, then waits 5 minutes between retries.
    _mirror_probe_time: float = 0
    _MIRROR_PROBE_COOLDOWN = 300  # 5 minutes

    # macOS hardware port -> interface type cache
    _macos_hw_ports: Optional[Dict[str, str]] = None
    _macos_hw_ports_time: float = 0

    def __init__(self):
        self._all_interfaces: List[InterfaceInfo] = []

    # ================================================================== #
    #  PUBLIC API
    # ================================================================== #

    def detect(
        self,
        sample_source_macs: Optional[List[str]] = None,
        capture_interface_mac: Optional[str] = None,
    ) -> BaseMode:
        """
        Run the full detection pipeline and return the appropriate mode.

        Args:
            sample_source_macs: Optional list of source MAC addresses from
                a short sample capture.  Used for port-mirror heuristic.
            capture_interface_mac: MAC address of the interface these source
                MACs were captured on.  Used to scope the port-mirror check
                to the correct interface and avoid cross-interface false
                positives.

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

        # Step 1 — Port Mirror (check traffic pattern or probe promiscuously)
        # Port mirror requires physical Ethernet — Wi-Fi cannot carry
        # mirrored traffic (shared wireless medium causes false positives).
        mirror_mode = self._check_port_mirror(
            sample_source_macs or [], capture_interface_mac,
        )
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

        # Step 4 — WiFi Client (always returns PublicNetworkMode)
        wifi_mode = self._check_public_network_wifi()
        if wifi_mode:
            # Gateway fallback: if WMI didn't return a gateway for this
            # WiFi adapter, try netifaces as a secondary source.
            if not wifi_mode.interface.gateway:
                wifi_mode.interface.gateway = self._detect_gateway_fallback(
                    wifi_mode.interface.ip_address
                )
            detected_name = wifi_mode.get_mode_name().value.upper()
            self._log_mode_change(detected_name)
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

            wifi = self._check_public_network_wifi()
            if wifi:
                return wifi

            return self._safe_fallback()
        finally:
            self._all_interfaces = saved

    # ================================================================== #
    #  INTERFACE ENUMERATION
    # ================================================================== #

    @staticmethod
    def _dict_to_interface(d: dict) -> InterfaceInfo:
        """Convert a platform_helpers dict to an InterfaceInfo object."""
        return InterfaceInfo(
            name=d.get("name", ""),
            friendly_name=d.get("friendly_name", ""),
            ip_address=d.get("ip_address"),
            netmask=d.get("netmask"),
            gateway=d.get("gateway"),
            mac_address=d.get("mac_address"),
            ssid=d.get("ssid"),
            interface_type=d.get("interface_type", "unknown"),
            is_active=d.get("is_active", False),
        )

    def _prefetch_windows_data(self) -> None:
        """
        Run ipconfig, netsh wlan show interfaces, and netsh wlan show
        hostednetwork in PARALLEL threads via platform_helpers.
        Results are cached for ``_CACHE_TTL`` seconds so repeated
        detect() calls are near-instant.

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

        results = ph.prefetch_windows_commands(needs_ipconfig, needs_ssid, needs_hosted)

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
        # checks (ethernet, public_network, port_mirror) already exclude
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
        """Build interface list via platform_helpers (WMI, then ipconfig fallback)."""
        raw = ph.enumerate_windows_interfaces_wmi()
        if raw:
            interfaces = [self._dict_to_interface(d) for d in raw]
            # Enrich WiFi interfaces with SSID
            ssid = ph.get_windows_ssid(ModeDetector._ssid_cache)
            if ssid:
                for iface in interfaces:
                    if iface.interface_type == "wifi":
                        iface.ssid = ssid
            return interfaces

        # Fallback: parse ipconfig (English-only labels)
        raw = ph.enumerate_windows_interfaces_ipconfig(ModeDetector._ipconfig_cache)
        interfaces = [self._dict_to_interface(d) for d in raw]
        ssid = ph.get_windows_ssid(ModeDetector._ssid_cache)
        if ssid:
            for iface in interfaces:
                if iface.interface_type == "wifi":
                    iface.ssid = ssid
        return interfaces

    # ---- Linux ---------------------------------------------------------- #

    def _enumerate_linux_interfaces(self) -> List[InterfaceInfo]:
        """Build interface list via platform_helpers."""
        raw = ph.enumerate_linux_interfaces()
        return [self._dict_to_interface(d) for d in raw]

    # ---- macOS ---------------------------------------------------------- #

    def _enumerate_macos_interfaces(self) -> List[InterfaceInfo]:
        """Build interface list via platform_helpers."""
        now = time.time()
        if (
            ModeDetector._macos_hw_ports is None
            or now - ModeDetector._macos_hw_ports_time > 30
        ):
            ModeDetector._macos_hw_ports = ph.fetch_macos_hardware_ports()
            ModeDetector._macos_hw_ports_time = now

        raw = ph.enumerate_macos_interfaces(ModeDetector._macos_hw_ports)
        return [self._dict_to_interface(d) for d in raw]

    # ================================================================== #
    #  MODE CHECKS — in priority order
    # ================================================================== #

    def _check_port_mirror(
        self,
        source_macs: List[str],
        capture_interface_mac: Optional[str] = None,
    ) -> Optional[PortMirrorMode]:
        """Return PortMirrorMode if traffic analysis suggests a SPAN port.

        Port mirroring requires a physical Ethernet cable to a managed
        switch's SPAN port.  Wi-Fi, virtual, bluetooth, and hotspot
        adapters can NEVER carry mirrored traffic, so only ``"ethernet"``
        type interfaces are considered.

        When ``capture_interface_mac`` is provided the check is scoped to
        that specific interface to avoid cross-interface false positives
        (e.g. Wi-Fi MACs tested against an Ethernet adapter's MAC).
        """
        if source_macs and capture_interface_mac:
            # Scoped check: only test against the interface the MACs
            # were actually captured on.
            capture_iface = None
            cap_mac = capture_interface_mac.lower().replace("-", ":")
            for iface in self._all_interfaces:
                if (iface.mac_address
                        and iface.mac_address.lower().replace("-", ":") == cap_mac):
                    capture_iface = iface
                    break

            # Port mirror only on physical Ethernet
            if capture_iface and capture_iface.interface_type == "ethernet":
                is_mirror = PortMirrorMode.detect_mirror_traffic(
                    source_macs,
                    capture_interface_mac,
                    threshold=PORT_MIRROR_FOREIGN_MAC_THRESHOLD,
                )
                if is_mirror:
                    return PortMirrorMode(capture_iface)
            # Scoped check didn't match — fall through to promiscuous
            # probe which may detect a SPAN port on a *different* ethernet
            # adapter (e.g. when the current capture is on Wi-Fi).
            pass

        if source_macs and not capture_interface_mac:
            # Source MACs without capture interface info (legacy / safety).
            # Check only Ethernet interfaces.
            for iface in self._all_interfaces:
                if iface.mac_address and iface.interface_type == "ethernet":
                    is_mirror = PortMirrorMode.detect_mirror_traffic(
                        source_macs,
                        iface.mac_address,
                        threshold=PORT_MIRROR_FOREIGN_MAC_THRESHOLD,
                    )
                    if is_mirror:
                        return PortMirrorMode(iface)
            return None

        # No source MACs available — fall back to promiscuous probe with
        # cooldown to avoid running a 3s Scapy sniff every detection cycle.
        now = time.time()
        if (now - ModeDetector._mirror_probe_time) < ModeDetector._MIRROR_PROBE_COOLDOWN:
            return None  # Too recent — skip expensive probe
        ModeDetector._mirror_probe_time = now
        mirror_iface = self._probe_promiscuous_mode()
        if mirror_iface:
            return PortMirrorMode(mirror_iface)

        return None

    def _probe_promiscuous_mode(self) -> Optional[InterfaceInfo]:
        """
        Short Scapy sniff in promiscuous mode to detect mirrored traffic.

        Captures ~20 packets and checks whether a majority have foreign
        source MACs — the hallmark of a SPAN/mirror port.

        Only probes ``"ethernet"`` interfaces.  Wi-Fi in promiscuous mode
        naturally sees foreign MACs from the shared wireless medium, which
        would cause false positives.
        """
        try:
            from scapy.all import sniff, Ether  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("Scapy not available for promiscuous probe")
            return None

        for iface in self._all_interfaces:
            if not iface.mac_address or iface.interface_type != "ethernet":
                continue  # Port mirror only possible on physical Ethernet
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
           for ICS).  However, the adapter **retains its IP even when
           the hotspot is turned off**, so we additionally verify the
           adapter's ``MediaConnectState`` via ``Get-NetAdapter``:
           an active hotspot shows ``Status: Up`` whereas a deactivated
           one shows ``Disconnected``.

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

                # Verify the adapter is actually connected (Up).
                # On Windows the hotspot virtual adapter retains its IP
                # even after the Mobile Hotspot is turned off, so the IP
                # check alone is not sufficient.
                if not self._is_hotspot_adapter_active(iface.name):
                    logger.debug(
                        "Hotspot adapter %s has IP %s but adapter status "
                        "is not Up — skipping",
                        iface.name, iface.ip_address,
                    )
                    continue

                # Enrich interface with hotspot SSID if available
                iface.ssid = ph.get_hotspot_ssid(ModeDetector._hostednet_cache)

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
                    iface.ssid = ph.get_hotspot_ssid(ModeDetector._hostednet_cache)
                    logger.info(
                        "Hotspot detected via legacy hosted network: %s (%s), subnet=%s",
                        iface.name, iface.ip_address, subnet,
                    )
                    return HotspotMode(iface, hotspot_subnet=subnet)

            # Fallback: any adapter on 192.168.137.x (ICS default subnet)
            # Only match the ICS HOST — the host has NO gateway on the sharing
            # adapter (it IS the gateway).  ICS clients have a gateway (= the
            # host's IP) and should fall through to ethernet detection instead.
            for iface in self._all_interfaces:
                if (iface.ip_address
                        and iface.ip_address.startswith("192.168.137.")
                        and not iface.gateway):
                    subnet = _cidr_from_ip_and_mask(
                        iface.ip_address,
                        iface.netmask or "255.255.255.0",
                    )
                    return HotspotMode(iface, hotspot_subnet=subnet)

        logger.debug("No active hotspot detected on Windows")
        return None

    def _is_hotspot_adapter_active(self, adapter_name: str) -> bool:
        """Return *True* only if the Windows hotspot adapter is genuinely active.

        Delegates the subprocess call (``Get-NetAdapter``) to
        ``platform_helpers.check_hotspot_adapter_status()``.  Cache
        management stays here.

        **Fail-closed:** if the PowerShell command fails we return
        ``False`` to avoid falsely entering hotspot mode on a WiFi
        client connection.

        Results are cached for ``_CACHE_TTL`` seconds.
        """
        now = time.time()
        if (
            ModeDetector._adapter_status_cache
            and (now - ModeDetector._adapter_status_cache_time) < ModeDetector._CACHE_TTL
            and adapter_name in ModeDetector._adapter_status_cache
        ):
            return ModeDetector._adapter_status_cache[adapter_name] == "Up"

        status, media_state = ph.check_hotspot_adapter_status(adapter_name)

        if not status:
            logger.debug(
                "Could not query adapter status for %s — assuming inactive (fail-closed)",
                adapter_name,
            )
            return False

        # MediaConnectionState: 1 = Connected, 0 = Disconnected, 2 = Unknown
        # The adapter must be Up AND media-connected for a real hotspot.
        is_active = (status == "Up" and media_state in ("1", "Connected"))

        # Cache the effective status
        effective = "Up" if is_active else status
        ModeDetector._adapter_status_cache[adapter_name] = effective
        ModeDetector._adapter_status_cache_time = time.time()

        logger.debug(
            "Adapter %s status=%s, media_state=%s → active=%s",
            adapter_name, status, media_state, is_active,
        )
        return is_active

    def _check_hotspot_linux(self) -> Optional[HotspotMode]:
        """
        Linux: hosting if ``hostapd`` or ``dnsmasq`` is running on a wifi iface.
        Subprocess checks delegated to ``platform_helpers``.
        """
        hostapd_running, dnsmasq_running, hostapd_iface = ph.check_linux_hotspot_processes()

        if not (hostapd_running or dnsmasq_running):
            return None

        for iface in self._all_interfaces:
            if hostapd_iface and iface.name == hostapd_iface:
                return HotspotMode(iface)
            if iface.interface_type == "wifi" and hostapd_running:
                return HotspotMode(iface)

        return None

    def _check_hotspot_macos(self) -> Optional[HotspotMode]:
        """
        macOS: Check Internet Sharing pref and bridge100 interface.
        Subprocess check delegated to ``platform_helpers``.
        """
        # Internet Sharing creates a bridge100 interface on 192.168.2.x
        for iface in self._all_interfaces:
            if iface.name.startswith("bridge") and iface.ip_address:
                if iface.ip_address.startswith("192.168.2."):
                    return HotspotMode(iface, hotspot_subnet="192.168.2.0/24")

        # Also check the preference plist
        if ph.check_macos_internet_sharing():
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

    def _check_public_network_wifi(self) -> Optional[BaseMode]:
        """
        Return PublicNetworkMode for any WiFi connection.

        **This is NOT a hotspot.**  We only reach this point because
        ``_check_hotspot()`` already returned None — meaning the machine is
        NOT hosting.  Being *connected to* someone else's WiFi (or phone
        hotspot) is a client relationship.

        All WiFi client connections (home, campus, hotspot) use
        ``PublicNetworkMode`` with a restrictive posture.
        """
        wifi_iface: Optional[InterfaceInfo] = None
        for iface in self._all_interfaces:
            if iface.interface_type == "wifi" and iface.ssid:
                wifi_iface = iface
                break

        # Fallback: WiFi adapter active but no SSID (odd but possible)
        if wifi_iface is None:
            for iface in self._all_interfaces:
                if iface.interface_type == "wifi" and iface.ip_address:
                    wifi_iface = iface
                    break

        if wifi_iface is None:
            return None

        return PublicNetworkMode(wifi_iface)

    def _is_public_network(self, iface: InterfaceInfo) -> bool:
        """Return *True* if the WiFi network should be treated as public.

        On Windows, uses ``detect_network_category()`` (NLM / PowerShell).
        On other platforms, falls back to a subnet-size heuristic: any
        subnet larger than /22 (>1 024 hosts) is considered public
        because home networks almost never exceed that.
        """
        # --- Windows: authoritative OS-level category ------------------
        if IS_WINDOWS:
            category = ph.detect_network_category()
            if category in ("public", "domain_authenticated"):
                return True
            if category == "private":
                return False
            # category is None (detection failed) — fall through to
            # the subnet heuristic so we still have a reasonable guess.

        # --- Cross-platform heuristic: subnet size ---------------------
        mask = iface.netmask
        if mask:
            try:
                prefix_len = ipaddress.IPv4Network(
                    f"0.0.0.0/{mask}"
                ).prefixlen
                if prefix_len < 22:          # > 1 024 hosts
                    logger.debug(
                        "Subnet /%d is large — treating as public",
                        prefix_len,
                    )
                    return True
            except (ValueError, TypeError):
                pass

        return False

    # Cache for gateway fallback detection — avoids re-running netifaces/route
    # on every 30-second detect() cycle.
    _gw_fallback_cache: Optional[str] = None
    _gw_fallback_cache_time: float = 0
    _GW_FALLBACK_TTL = 60  # seconds — re-check once a minute

    @staticmethod
    def _detect_gateway_fallback(our_ip: Optional[str]) -> Optional[str]:
        """Try alternative methods to detect the default gateway IP.

        Called when WMI / PowerShell returned no gateway for a WiFi
        adapter (common on campus networks and some DHCP configs).

        Tries (via platform_helpers):
        1. ``netifaces.gateways()['default']`` -- cross-platform
        2. ``route print`` parsing (Windows) -- matches our IP's subnet

        Results are cached for 60 seconds so this is not re-run on
        every detect() cycle.
        """
        now = time.time()
        if (ModeDetector._gw_fallback_cache
                and now - ModeDetector._gw_fallback_cache_time < ModeDetector._GW_FALLBACK_TTL):
            return ModeDetector._gw_fallback_cache

        # 1. netifaces
        gw_ip = ph.detect_gateway_netifaces()
        if gw_ip:
            if gw_ip != ModeDetector._gw_fallback_cache:
                logger.info("Gateway detected (netifaces): %s", gw_ip)
            ModeDetector._gw_fallback_cache = gw_ip
            ModeDetector._gw_fallback_cache_time = now
            return gw_ip

        # 2. route print (Windows only)
        if IS_WINDOWS and our_ip:
            gw_ip = ph.detect_gateway_route_print(our_ip)
            if gw_ip:
                if gw_ip != ModeDetector._gw_fallback_cache:
                    logger.info("Gateway detected (route print): %s", gw_ip)
                ModeDetector._gw_fallback_cache = gw_ip
                ModeDetector._gw_fallback_cache_time = now
                return gw_ip

        ModeDetector._gw_fallback_cache_time = now
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
