"""
orchestration/discovery_manager.py - Device Discovery Loop
=============================================================

Periodically runs ARP scans, ARP cache reads, and ping sweeps to discover
devices on the local network.  Found devices are upserted into the database
and enqueued for background hostname resolution.

Also provides shared network-helper functions used by other orchestration
modules: ``get_all_local_ips()``, ``get_all_local_macs()``, and
``resolve_scapy_iface()``.
"""

import ipaddress
import logging
import sys
import threading

from orchestration import state
from config import IS_WINDOWS
from database.connection import get_connection
from packet_capture.hostname_resolver import enqueue_for_resolution as _enqueue_resolution
from packet_capture.network_discovery import NetworkDiscovery

logger = logging.getLogger(__name__)


# =========================================================================
# Shared network helpers
# =========================================================================

def get_all_local_ips() -> set:
    """Collect ALL IPv4 addresses from all local network adapters.

    Used to filter out our own device from discovery results -- prevents
    cross-adapter IPs (e.g. WiFi IP showing as hotspot client) from
    appearing as separate devices.
    """
    local_ips: set = set()
    try:
        import psutil
        for _name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == 'AF_INET':
                    ip = addr.address
                    if ip and ip not in ('0.0.0.0', '127.0.0.1'):
                        local_ips.add(ip)
    except ImportError:
        pass
    except Exception:
        pass
    # Also include the current mode's IP in case psutil missed it
    if state.interface_manager:
        try:
            cur_mode = state.interface_manager.get_current_mode()
            if cur_mode and cur_mode.interface.ip_address:
                local_ips.add(cur_mode.interface.ip_address)
        except Exception:
            pass
    return local_ips


def get_all_local_macs() -> set:
    """Collect ALL MAC addresses from all local network adapters.

    Returns upper-cased MACs.  Used together with ``get_all_local_ips``
    to prevent the hotspot virtual adapter's MAC (which differs from the
    physical WiFi MAC) from being counted as a client device.
    """
    local_macs: set = set()
    try:
        import psutil
        for _name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                # AF_LINK / AF_PACKET carries the hardware address
                if addr.family.name in ('AF_LINK', 'AF_PACKET'):
                    mac = addr.address
                    if mac and mac not in ('', '00:00:00:00:00:00'):
                        local_macs.add(mac.upper().replace('-', ':'))
    except ImportError:
        pass
    except Exception:
        pass
    return local_macs


def resolve_scapy_iface(friendly_name: str, ip_address: str = None) -> str:
    """Resolve a Windows interface name to one that Npcap can open.

    Windows hotspot adapters create interfaces with names like
    ``Local Area Connection* 10`` -- the ``*`` is a wildcard character
    that Npcap rejects with ``ERROR_INVALID_NAME (123)``.

    This function looks up the interface in Scapy's ``conf.ifaces`` by
    IP address (most reliable) or by name/description match, and returns
    the Npcap-compatible device name (``\\\\Device\\\\NPF_{GUID}``).

    On non-Windows platforms this is a no-op.
    """
    if sys.platform != 'win32':
        return friendly_name

    try:
        from scapy.config import conf

        # Method 1: Match by IP address -- most reliable for hotspot adapters
        if ip_address:
            for iface_obj in conf.ifaces.values():
                iface_ip = getattr(iface_obj, 'ip', None)
                if iface_ip and iface_ip == ip_address:
                    pcap_name = getattr(iface_obj, 'pcap_name', None)
                    if pcap_name:
                        logger.info(
                            "Resolved interface '%s' -> '%s' (by IP %s)",
                            friendly_name, pcap_name, ip_address,
                        )
                        return pcap_name
                    scapy_name = getattr(iface_obj, 'name', None)
                    if scapy_name:
                        logger.info(
                            "Resolved interface '%s' -> '%s' (by IP %s, name)",
                            friendly_name, scapy_name, ip_address,
                        )
                        return scapy_name

        # Method 2: Match by name/description/network_name in Scapy's iface table
        for iface_obj in conf.ifaces.values():
            name = getattr(iface_obj, 'name', '')
            desc = getattr(iface_obj, 'description', '')
            net_name = getattr(iface_obj, 'network_name', '')
            if friendly_name in (name, desc, net_name):
                pcap_name = getattr(iface_obj, 'pcap_name', None)
                if pcap_name:
                    logger.info(
                        "Resolved interface '%s' -> '%s' (by name match)",
                        friendly_name, pcap_name,
                    )
                    return pcap_name

    except Exception as exc:
        logger.warning(
            "Failed to resolve Npcap interface for '%s': %s", friendly_name, exc,
        )

    return friendly_name


# =========================================================================
# Device upsert helpers (used by discovery_loop)
# =========================================================================

def _upsert_devices(devices, current_mode_name, local_ips=None):
    """Upsert discovered devices into the devices table.

    Filters out our own machine's IP before alerting so we don't
    create a spurious "new device" alert for ourselves when the
    capture interface changes.

    Also enqueues newly-discovered devices for background hostname
    resolution so hostnames are resolved without waiting for the
    next API request.
    """
    if not devices:
        return

    all_local_ips = local_ips if local_ips is not None else get_all_local_ips()

    with get_connection() as conn:
        cursor = conn.cursor()
        for dev in devices:
            hostname = dev.get('hostname') or ''
            mac = dev.get('mac', '')
            ip = dev.get('ip', '')
            vendor = dev.get('vendor', '')

            # Skip our own device entirely (any local adapter IP)
            if ip and ip in all_local_ips:
                continue

            # Security: alert on new/unknown devices
            if state.detector and hasattr(state.detector, 'alert_engine'):
                if ip:
                    try:
                        state.detector.alert_engine.check_new_device(
                            mac=mac, ip=ip,
                            hostname=hostname,
                            vendor=vendor,
                            mode_name=current_mode_name,
                        )
                    except Exception:
                        pass

            if hostname and ip:
                cursor.execute("""
                    UPDATE devices
                    SET hostname = CASE WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address) THEN ? ELSE hostname END,
                        vendor = CASE WHEN (vendor IS NULL OR vendor = '') THEN ? ELSE vendor END,
                        last_seen = datetime('now')
                    WHERE ip_address = ? OR mac_address = ?
                """, (hostname, vendor, ip, mac))

            # Enqueue for background hostname resolution
            if ip:
                _enqueue_resolution(ip, mac or None)
        conn.commit()


def _upsert_arp_cache_devices(devices, current_mode_name, set_active_mode=False, local_ips=None):
    """Upsert ARP-cache-discovered devices with active_mode=NULL.

    These devices are visible on the Devices page (detected_mode is set)
    but do NOT count as "active" for the dashboard card because
    active_mode stays NULL -- only traffic-producing devices get
    active_mode set via ``save_packet()``.

    When *set_active_mode* is True (e.g. public_network mode ARP scans),
    active_mode is set to *current_mode_name* so that discovered
    devices appear in the dashboard device list immediately.
    """
    if not devices:
        return

    all_local_ips = local_ips if local_ips is not None else get_all_local_ips()
    own_subnet = None
    if state.interface_manager:
        try:
            cur_mode = state.interface_manager.get_current_mode()
            if cur_mode and cur_mode.interface.ip_address:
                own_ip = cur_mode.interface.ip_address
                parts = own_ip.split('.')
                if len(parts) == 4:
                    own_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}."
        except Exception:
            pass

    active_mode_val = current_mode_name if set_active_mode else None

    with get_connection() as conn:
        cursor = conn.cursor()
        for dev in devices:
            hostname = dev.get('hostname') or ''
            mac = dev.get('mac', '')
            ip = dev.get('ip', '')
            vendor = dev.get('vendor', '')

            if not mac or mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                continue

            # Skip our own device (any local adapter IP)
            if ip and ip in all_local_ips:
                continue

            # Skip devices outside the current subnet
            if own_subnet and ip and not ip.startswith(own_subnet):
                continue

            cursor.execute("""
                INSERT INTO devices
                    (mac_address, ip_address, ipv4_address,
                     hostname, vendor,
                     first_seen, last_seen,
                     detected_mode, active_mode)
                VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'),
                        ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address   = COALESCE(NULLIF(ip_address, ''), excluded.ip_address),
                    ipv4_address = COALESCE(NULLIF(ipv4_address, ''), excluded.ipv4_address),
                    hostname     = CASE
                        WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                        THEN COALESCE(NULLIF(excluded.hostname, ''), hostname)
                        ELSE hostname END,
                    vendor       = CASE
                        WHEN (vendor IS NULL OR vendor = '')
                        THEN COALESCE(NULLIF(excluded.vendor, ''), vendor)
                        ELSE vendor END,
                    last_seen    = datetime('now'),
                    detected_mode = COALESCE(detected_mode, excluded.detected_mode),
                    active_mode  = CASE
                        WHEN excluded.active_mode IS NOT NULL
                        THEN COALESCE(active_mode, excluded.active_mode)
                        ELSE active_mode END
            """, (mac, ip, ip, hostname, vendor, current_mode_name, active_mode_val))

            if ip:
                _enqueue_resolution(ip, mac or None)
        conn.commit()


# =========================================================================
# Discovery loop
# =========================================================================

def _discovery_loop():
    """Main discovery loop -- runs in a daemon thread.

    Uses ARP scans, ARP cache reads, ping sweeps, and hotspot client
    enumeration to discover devices on the local network.
    """
    _cached_iface = None
    _cached_network = None
    _iteration = 0
    _last_mode_name = None

    while not state.shutdown_event.is_set():
        try:
            # Cache local IPs for this iteration to avoid repeated psutil calls
            _cycle_local_ips = get_all_local_ips()

            # Only run if we have an interface manager with a valid mode
            if state.interface_manager:
                mode = state.interface_manager.get_current_mode()
                iface_name = mode.interface.name if mode else None
                ip_addr = mode.interface.ip_address if mode else None

                # Mode-aware discovery gating
                can_arp = mode.capabilities.can_arp_scan if mode else False
                can_passive = mode.capabilities.can_do_passive_discovery if mode else False
                can_arp_cache = mode.capabilities.can_arp_cache_scan if mode else False

                # Stagger discovery after mode change
                current_mode_label = mode.get_mode_name().value if mode else None
                if current_mode_label != _last_mode_name:
                    _last_mode_name = current_mode_label
                    logger.debug(
                        "Mode changed to '%s' -- staggering discovery by 3s",
                        current_mode_label,
                    )
                    state.shutdown_event.wait(3)
                    if state.shutdown_event.is_set():
                        break

                if not can_arp and not can_passive and not can_arp_cache:
                    # Nothing to discover in this mode
                    with state.cached_discovery_lock:
                        if state.cached_discovery is not None:
                            try:
                                state.cached_discovery.stop_continuous_discovery()
                            except Exception:
                                pass
                            state.cached_discovery = None
                            _cached_iface = None
                            _cached_network = None
                    state.shutdown_event.wait(60)
                    continue

                # ARP-cache-only path (public_network)
                if not can_arp and not can_passive and can_arp_cache:
                    if iface_name and ip_addr:
                        try:
                            prefix_len = 24
                            try:
                                import netifaces
                                addrs = netifaces.ifaddresses(iface_name)
                                ipv4_list = addrs.get(netifaces.AF_INET, [])
                                for entry in ipv4_list:
                                    if entry.get('addr') == ip_addr:
                                        netmask = entry.get('netmask', '255.255.255.0')
                                        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                                        break
                            except Exception:
                                pass
                            network = str(ipaddress.IPv4Network(f"{ip_addr}/{prefix_len}", strict=False))

                            need_new = (
                                state.cached_discovery is None
                                or iface_name != _cached_iface
                                or network != _cached_network
                            )
                            if need_new:
                                with state.cached_discovery_lock:
                                    if state.cached_discovery is not None:
                                        try:
                                            state.cached_discovery.stop_continuous_discovery()
                                        except Exception:
                                            pass
                                    _resolved_iface = resolve_scapy_iface(iface_name, ip_addr) if IS_WINDOWS else iface_name
                                    state.cached_discovery = NetworkDiscovery(interface=_resolved_iface, subnet=network)
                                    state.cached_discovery.set_exclusions(
                                        ips=_cycle_local_ips,
                                        macs=get_all_local_macs(),
                                    )
                                _cached_iface = iface_name
                                _cached_network = network

                            current_mode_name = mode.get_mode_name().value if mode else ""
                            with state.cached_discovery_lock:
                                disc = state.cached_discovery
                            if disc is not None:
                                cache_devices = disc.arp_cache_scan()
                                _upsert_arp_cache_devices(cache_devices, current_mode_name, local_ips=_cycle_local_ips)
                            else:
                                cache_devices = []
                            logger.debug(
                                "ARP cache scan (%s): %d device(s) found",
                                current_mode_name, len(cache_devices),
                            )
                        except Exception as e:
                            logger.debug("ARP cache discovery error: %s", e)
                    # 30-second interval for passive cache scanning
                    state.shutdown_event.wait(30)
                    continue

                if iface_name and ip_addr:
                    try:
                        # Use actual subnet mask from netifaces instead of hardcoded /24
                        prefix_len = 24
                        try:
                            import netifaces
                            addrs = netifaces.ifaddresses(iface_name)
                            ipv4_list = addrs.get(netifaces.AF_INET, [])
                            for entry in ipv4_list:
                                if entry.get('addr') == ip_addr:
                                    netmask = entry.get('netmask', '255.255.255.0')
                                    prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                                    break
                        except Exception:
                            pass
                        network = str(ipaddress.IPv4Network(f"{ip_addr}/{prefix_len}", strict=False))

                        need_new = (
                            state.cached_discovery is None
                            or iface_name != _cached_iface
                            or network != _cached_network
                        )
                        if need_new:
                            with state.cached_discovery_lock:
                                if state.cached_discovery is not None:
                                    logger.info(
                                        "Interface/subnet changed (%s/%s -> %s/%s) -- creating new NetworkDiscovery",
                                        _cached_iface, _cached_network, iface_name, network,
                                    )
                                    try:
                                        state.cached_discovery.stop_continuous_discovery()
                                    except Exception:
                                        pass
                                _resolved_iface = resolve_scapy_iface(iface_name, ip_addr) if IS_WINDOWS else iface_name
                                state.cached_discovery = NetworkDiscovery(interface=_resolved_iface, subnet=network)
                                state.cached_discovery.set_exclusions(
                                    ips=_cycle_local_ips,
                                    macs=get_all_local_macs(),
                                )
                            _cached_iface = iface_name
                            _cached_network = network
                            _iteration = 0  # reset on interface change

                        # Use local-copy pattern with lock
                        with state.cached_discovery_lock:
                            discovery = state.cached_discovery
                        if discovery is None:
                            state.shutdown_event.wait(10)
                            continue
                        current_mode_name = mode.get_mode_name().value if mode else ""
                        is_discovery_only = (
                            mode and mode.get_scope().name in ("OWN_TRAFFIC_ONLY", "CONNECTED_CLIENTS")
                        )

                        # 1. ARP scan (primary -- fast, L2)
                        devices = discovery.arp_scan(timeout=3)
                        _upsert_devices(devices, current_mode_name, local_ips=_cycle_local_ips)
                        if is_discovery_only and devices:
                            _upsert_arp_cache_devices(
                                devices, current_mode_name, set_active_mode=True,
                                local_ips=_cycle_local_ips,
                            )

                        # 2. ARP cache scan (supplement)
                        try:
                            cache_devices = discovery.arp_cache_scan()
                            _upsert_devices(cache_devices, current_mode_name, local_ips=_cycle_local_ips)
                            if is_discovery_only and cache_devices:
                                _upsert_arp_cache_devices(
                                    cache_devices, current_mode_name,
                                    set_active_mode=True,
                                    local_ips=_cycle_local_ips,
                                )
                        except Exception:
                            pass

                        # 3. Ping sweep -- first iteration and every 5th cycle
                        if _iteration == 0 or _iteration % 5 == 0:
                            try:
                                ping_devices = discovery.ping_sweep(
                                    max_workers=20,
                                )
                                _upsert_devices(ping_devices, current_mode_name, local_ips=_cycle_local_ips)
                                if is_discovery_only and ping_devices:
                                    _upsert_arp_cache_devices(
                                        ping_devices, current_mode_name,
                                        set_active_mode=True,
                                        local_ips=_cycle_local_ips,
                                    )
                                # Re-check ARP cache after pinging
                                if ping_devices:
                                    try:
                                        cache2 = discovery.arp_cache_scan()
                                        _upsert_devices(cache2, current_mode_name, local_ips=_cycle_local_ips)
                                        if is_discovery_only and cache2:
                                            _upsert_arp_cache_devices(
                                                cache2, current_mode_name,
                                                set_active_mode=True,
                                                local_ips=_cycle_local_ips,
                                            )
                                    except Exception:
                                        pass
                            except Exception as e:
                                logger.debug("Ping sweep error: %s", e)

                        # 4. Hotspot mode: get_connected_clients()
                        if mode and mode.get_mode_name().value == "hotspot":
                            try:
                                clients = mode.get_connected_clients()
                                if clients:
                                    _upsert_arp_cache_devices(
                                        clients, current_mode_name,
                                        set_active_mode=True,
                                        local_ips=_cycle_local_ips,
                                    )
                            except Exception as e:
                                logger.debug("Hotspot get_connected_clients error: %s", e)

                        _iteration += 1

                        total = len(discovery.get_all_devices()) if hasattr(discovery, 'get_all_devices') else len(devices)
                        logger.debug("Discovery scan: %d device(s) known", total)
                    except ImportError:
                        pass
                    except Exception as e:
                        logger.debug("Discovery scan error: %s", e)
        except Exception as e:
            logger.debug("Discovery loop error: %s", e)

        # Hotspot needs faster discovery (30s)
        wait_time = 30 if (state.interface_manager and
                          state.interface_manager.get_current_mode().get_mode_name().value == "hotspot") else 60
        state.shutdown_event.wait(wait_time)


def start_discovery_task():
    """Periodically run NetworkDiscovery.scan() and upsert device names into DB."""
    state.discovery_thread = threading.Thread(
        target=_discovery_loop,
        daemon=True,
        name="DiscoveryTask"
    )
    state.discovery_thread.start()
    return True
