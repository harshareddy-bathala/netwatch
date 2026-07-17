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
import sqlite3
import sys
import threading
import time

from orchestration import state
from config import IS_WINDOWS, HOTSPOT_STALE_DEVICE_SECONDS
from database.connection import get_connection
from packet_capture.hostname_resolver import enqueue_for_resolution as _enqueue_resolution
from packet_capture.network_discovery import NetworkDiscovery

logger = logging.getLogger(__name__)


# Recently confirmed hotspot MACs (ARP scan / ping / explicit connected status).
# Used as a short grace window so intermittent discovery misses don't instantly
# drop active_mode and make dashboard/device counts flap to zero.
_recent_confirmed_macs = {}
_recent_confirmed_macs_lock = threading.Lock()


def _should_promote_hotspot_cache_client(client: dict, active_discovered_ips: set) -> bool:
    """Return True when a weak hotspot client should be treated as active.

    ARP/cache-only client rows are promoted only when corroborated by
    independent discovery in this cycle (currently: ping/ARP active IP set).
    """
    status = str((client or {}).get("status") or "").strip().lower()
    if status not in {"arp", "cache", "unknown", ""}:
        return False

    source = str((client or {}).get("source") or "").strip().lower()
    ip_val = str((client or {}).get("ip") or "").strip()
    if not ip_val:
        return False

    return source == "arp" and ip_val in (active_discovered_ips or set())


def _mark_recently_confirmed_macs(macs: set) -> None:
    """Record MACs confirmed active in the current discovery cycle."""
    if not macs:
        return

    now = time.time()
    prune_cutoff = now - max(HOTSPOT_STALE_DEVICE_SECONDS * 2, 120)

    with _recent_confirmed_macs_lock:
        for mac in macs:
            if not mac:
                continue
            norm = str(mac).upper().replace('-', ':').strip()
            if norm:
                _recent_confirmed_macs[norm] = now

        stale = [m for m, ts in _recent_confirmed_macs.items() if ts < prune_cutoff]
        for m in stale:
            _recent_confirmed_macs.pop(m, None)


def _get_recently_confirmed_macs(max_age_seconds: int) -> set:
    """Return MACs confirmed active within ``max_age_seconds``."""
    now = time.time()
    age = max(5, int(max_age_seconds or HOTSPOT_STALE_DEVICE_SECONDS))
    cutoff = now - age
    prune_cutoff = now - max(age * 2, 120)

    active = set()
    with _recent_confirmed_macs_lock:
        for mac, ts in list(_recent_confirmed_macs.items()):
            if ts >= cutoff:
                active.add(mac)
            elif ts < prune_cutoff:
                _recent_confirmed_macs.pop(mac, None)

    return active


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

    # Fallback: ensure the active interface MAC is always present even
    # when psutil omits virtual hotspot adapters.
    if state.interface_manager:
        try:
            cur_mode = state.interface_manager.get_current_mode()
            if cur_mode and getattr(cur_mode.interface, "mac_address", None):
                local_macs.add(cur_mode.interface.mac_address.upper().replace('-', ':'))
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

def _current_mode_generation() -> int:
    """Return the current global mode-transition generation."""
    with state.mode_generation_lock:
        return state.mode_generation


def _upsert_devices(
    devices,
    current_mode_name,
    local_ips=None,
    expected_generation=None,
    update_memory=False,
):
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

    if expected_generation is not None and _current_mode_generation() != expected_generation:
        return

    all_local_ips = local_ips if local_ips is not None else get_all_local_ips()
    all_local_macs = get_all_local_macs()

    with get_connection() as conn:
        cursor = conn.cursor()
        for dev in devices:
            if expected_generation is not None and _current_mode_generation() != expected_generation:
                return

            hostname = dev.get('hostname') or ''
            mac = dev.get('mac', '')
            ip = dev.get('ip', '')
            vendor = dev.get('vendor', '')

            # Skip our own device entirely (any local adapter IP or MAC)
            if ip and ip in all_local_ips:
                continue
            if mac and mac.upper().replace('-', ':') in all_local_macs:
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

            # For connected-idle visibility (hotspot), push actively-discovered
            # devices into in-memory state even before traffic is seen.
            # Do this before DB writes so transient DB locks don't blank UI.
            if update_memory and current_mode_name == "hotspot":
                try:
                    from utils.realtime_state import dashboard_state
                    dashboard_state.upsert_discovered_device(
                        mac_address=mac,
                        ip_address=ip,
                        hostname=hostname,
                        vendor=vendor,
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

        if expected_generation is not None and _current_mode_generation() != expected_generation:
            return
        conn.commit()


def _upsert_arp_cache_devices(
    devices,
    current_mode_name,
    set_active_mode=False,
    local_ips=None,
    expected_generation=None,
    clear_active_mode_when_inactive=False,
    preserve_active_macs=None,
):
    """Upsert ARP-cache-discovered devices with active_mode=NULL.

    These devices are visible on the Devices page (detected_mode is set)
    but do NOT count as "active" for the dashboard card because
    active_mode stays NULL -- only traffic-producing devices get
    active_mode set via ``save_packet()``.

    When *set_active_mode* is True (e.g. hotspot connected clients),
    active_mode is set to *current_mode_name* so that discovered
    devices appear in the dashboard device list immediately.

    When *clear_active_mode_when_inactive* is True and *set_active_mode*
    is False, active_mode is cleared for cache-only entries unless the
    device MAC is present in *preserve_active_macs* for this cycle.
    """
    if not devices:
        return

    if expected_generation is not None and _current_mode_generation() != expected_generation:
        return

    all_local_ips = local_ips if local_ips is not None else get_all_local_ips()
    all_local_macs = get_all_local_macs()
    preserve_active_macs = {
        (m or "").upper().replace('-', ':')
        for m in (preserve_active_macs or set())
        if m
    }
    own_network = None
    if state.interface_manager:
        try:
            cur_mode = state.interface_manager.get_current_mode()
            if cur_mode and cur_mode.interface.ip_address:
                own_ip = cur_mode.interface.ip_address
                own_mask = cur_mode.interface.netmask or "255.255.255.0"
                own_network = ipaddress.IPv4Network(f"{own_ip}/{own_mask}", strict=False)
        except Exception:
            pass

    active_mode_val = current_mode_name if set_active_mode else None

    with get_connection() as conn:
        cursor = conn.cursor()
        for dev in devices:
            if expected_generation is not None and _current_mode_generation() != expected_generation:
                return

            hostname = dev.get('hostname') or ''
            mac = dev.get('mac', '')
            ip = dev.get('ip', '')
            vendor = dev.get('vendor', '')
            normalized_mac = (mac or "").upper().replace('-', ':')

            if not mac or mac in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                continue

            # Skip our own device (any local adapter IP)
            if ip and ip in all_local_ips:
                continue

            # Skip our own adapter MACs — prevents the host from appearing
            # as a client device (e.g. hotspot virtual adapter MAC).
            if normalized_mac and normalized_mac in all_local_macs:
                continue

            # Skip devices outside the current subnet (CIDR-aware; no /24 assumptions)
            if own_network and ip:
                try:
                    if ipaddress.IPv4Address(ip) not in own_network:
                        continue
                except ValueError:
                    continue

            clear_active_mode = (
                clear_active_mode_when_inactive
                and not set_active_mode
                and normalized_mac not in preserve_active_macs
            )

            # In hotspot mode, keep in-memory visibility even if DB is briefly
            # locked. This preserves dashboard/device list continuity.
            if set_active_mode:
                try:
                    from utils.realtime_state import dashboard_state
                    dashboard_state.upsert_discovered_device(
                        mac_address=mac,
                        ip_address=ip,
                        hostname=hostname,
                        vendor=vendor,
                    )
                except Exception:
                    pass

            cursor.execute("""
                INSERT INTO devices
                    (mac_address, ip_address, ipv4_address,
                     hostname, vendor,
                     first_seen, last_seen,
                     detected_mode, active_mode)
                VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'),
                        ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address   = CASE
                        WHEN excluded.ip_address IS NOT NULL AND excluded.ip_address != ''
                        THEN excluded.ip_address
                        ELSE ip_address END,
                    ipv4_address = CASE
                        WHEN excluded.ipv4_address IS NOT NULL AND excluded.ipv4_address != ''
                        THEN excluded.ipv4_address
                        ELSE ipv4_address END,
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
                        THEN excluded.active_mode
                        WHEN ? = 1
                        THEN NULL
                        ELSE active_mode END
            """, (
                mac,
                ip,
                ip,
                hostname,
                vendor,
                current_mode_name,
                active_mode_val,
                1 if clear_active_mode else 0,
            ))

            if ip:
                _enqueue_resolution(ip, mac or None)

        if expected_generation is not None and _current_mode_generation() != expected_generation:
            return
        conn.commit()


def _clear_stale_active_mode_devices(mode_name: str, max_age_seconds: int) -> int:
    """Clear active_mode for devices stale beyond *max_age_seconds*.

    This is a safety net for hotspot churn: if a device disconnects and no
    longer appears in ARP cache, it can still linger with active_mode set.
    Clearing by last_seen keeps /api/devices aligned with real-time clients.
    """
    if not mode_name or max_age_seconds <= 0:
        return 0

    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE devices
                    SET active_mode = NULL
                    WHERE active_mode = ?
                      AND last_seen < datetime('now', ?)
                    """,
                    (mode_name, f"-{int(max_age_seconds)} seconds"),
                )
                cleared = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
                # Commit even when nothing matched: the UPDATE opened a write
                # transaction regardless, and returning the connection to the
                # pool with it open holds the write lock until the pool's
                # safety net rolls it back.
                conn.commit()
                return cleared
        except sqlite3.OperationalError as exc:
            msg = str(exc).lower()
            is_locked = "locked" in msg or "busy" in msg
            if not is_locked or attempt >= max_attempts - 1:
                logger.debug("Failed clearing stale active_mode devices for %s: %s", mode_name, exc)
                return 0

            delay = 0.15 * (2 ** attempt)
            logger.debug(
                "clear_stale_active_mode: DB locked (attempt %d/%d), retrying in %.2fs",
                attempt + 1,
                max_attempts,
                delay,
            )
            time.sleep(delay)
        except Exception as exc:
            logger.debug("Failed clearing stale active_mode devices for %s: %s", mode_name, exc)
            return 0

    return 0


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
                mode_generation = _current_mode_generation()

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
                                _upsert_arp_cache_devices(
                                    cache_devices,
                                    current_mode_name,
                                    local_ips=_cycle_local_ips,
                                    expected_generation=mode_generation,
                                )
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
                        active_discovered_macs = set()
                        active_discovered_ips = set()

                        def _remember_active_signals(found_devices):
                            confirmed_macs = set()
                            confirmed_ips = set()
                            for found in found_devices or []:
                                mac_val = (found.get("mac") or "").upper().replace('-', ':')
                                ip_val = str(found.get("ip") or "").strip()
                                if mac_val:
                                    confirmed_macs.add(mac_val)
                                if ip_val and ip_val not in {"0.0.0.0", "unknown"}:
                                    confirmed_ips.add(ip_val)
                            if confirmed_macs:
                                active_discovered_macs.update(confirmed_macs)
                                _mark_recently_confirmed_macs(confirmed_macs)
                            if confirmed_ips:
                                active_discovered_ips.update(confirmed_ips)

                        # In hotspot mode every client's traffic already crosses
                        # our adapter, so we discover them PASSIVELY (captured
                        # packets + ARP cache). Actively ARP-scanning / ping-
                        # sweeping all 254 host IPs is redundant there and only
                        # adds network+CPU load that can degrade forwarding for
                        # clients ("NetWatch shouldn't affect the network").
                        # Opt back in with HOTSPOT_ACTIVE_PROBING=true.
                        try:
                            from config import HOTSPOT_ACTIVE_PROBING as _HAP
                        except Exception:
                            _HAP = False
                        _active_probing_ok = (current_mode_name != "hotspot") or _HAP

                        # 1. ARP scan (primary -- fast, L2) — passive-only in hotspot
                        devices = discovery.arp_scan(timeout=3) if _active_probing_ok else []
                        _upsert_devices(
                            devices,
                            current_mode_name,
                            local_ips=_cycle_local_ips,
                            expected_generation=mode_generation,
                            update_memory=is_discovery_only,
                        )
                        if is_discovery_only and devices:
                            _remember_active_signals(devices)
                            _upsert_arp_cache_devices(
                                devices, current_mode_name, set_active_mode=True,
                                local_ips=_cycle_local_ips,
                                expected_generation=mode_generation,
                            )

                        # 2. ARP cache scan (supplement)
                        # NOTE: ARP cache may contain stale entries from
                        # previously-connected devices, so we never set
                        # active_mode here — only actively-probed devices
                        # (ARP scan, ping sweep) get active_mode=True.
                        try:
                            cache_devices = discovery.arp_cache_scan()
                            _upsert_devices(
                                cache_devices,
                                current_mode_name,
                                local_ips=_cycle_local_ips,
                                expected_generation=mode_generation,
                                update_memory=False,
                            )
                            if is_discovery_only and cache_devices:
                                preserve_macs = active_discovered_macs | _get_recently_confirmed_macs(
                                    HOTSPOT_STALE_DEVICE_SECONDS,
                                )
                                _upsert_arp_cache_devices(
                                    cache_devices, current_mode_name,
                                    set_active_mode=False,
                                    local_ips=_cycle_local_ips,
                                    expected_generation=mode_generation,
                                    clear_active_mode_when_inactive=True,
                                    preserve_active_macs=preserve_macs,
                                )
                        except Exception:
                            pass

                        # 3. Ping sweep -- first iteration and every 5th cycle
                        #    (skipped in hotspot: passive discovery suffices)
                        if _active_probing_ok and (_iteration == 0 or _iteration % 5 == 0):
                            try:
                                ping_devices = discovery.ping_sweep(
                                    max_workers=20,
                                )
                                _upsert_devices(
                                    ping_devices,
                                    current_mode_name,
                                    local_ips=_cycle_local_ips,
                                    expected_generation=mode_generation,
                                    update_memory=False,
                                )
                                if is_discovery_only and ping_devices:
                                    _remember_active_signals(ping_devices)
                                    preserve_macs = active_discovered_macs | _get_recently_confirmed_macs(
                                        HOTSPOT_STALE_DEVICE_SECONDS,
                                    )
                                    _upsert_arp_cache_devices(
                                        ping_devices, current_mode_name,
                                        set_active_mode=False,
                                        local_ips=_cycle_local_ips,
                                        expected_generation=mode_generation,
                                        clear_active_mode_when_inactive=True,
                                        preserve_active_macs=preserve_macs,
                                    )
                                # Re-check ARP cache after pinging
                                if ping_devices:
                                    try:
                                        cache2 = discovery.arp_cache_scan()
                                        _upsert_devices(
                                            cache2,
                                            current_mode_name,
                                            local_ips=_cycle_local_ips,
                                            expected_generation=mode_generation,
                                            update_memory=False,
                                        )
                                        if is_discovery_only and cache2:
                                            preserve_macs = active_discovered_macs | _get_recently_confirmed_macs(
                                                HOTSPOT_STALE_DEVICE_SECONDS,
                                            )
                                            _upsert_arp_cache_devices(
                                                cache2, current_mode_name,
                                                set_active_mode=False,
                                                local_ips=_cycle_local_ips,
                                                expected_generation=mode_generation,
                                                clear_active_mode_when_inactive=True,
                                                preserve_active_macs=preserve_macs,
                                            )
                                    except Exception:
                                        pass
                            except Exception as e:
                                logger.debug("Ping sweep error: %s", e)

                        # 4. Hotspot mode: get_connected_clients()
                        # Uses _parse_arp_table() internally which may
                        # include stale entries — don't set active_mode.
                        if mode and mode.get_mode_name().value == "hotspot":
                            try:
                                clients = mode.get_connected_clients()
                                if clients:
                                    confirmed_clients = []
                                    cache_only_clients = []
                                    recent_confirmed = _get_recently_confirmed_macs(
                                        HOTSPOT_STALE_DEVICE_SECONDS,
                                    )
                                    for client in clients:
                                        status = str(client.get("status") or "").strip().lower()
                                        source = str(client.get("source") or "").strip().lower()
                                        mac_norm = str(client.get("mac") or "").upper().replace('-', ':').strip()
                                        ip_val = str(client.get("ip") or "").strip()

                                        # Cache-derived statuses are weak signals by design.
                                        if status in {"arp", "cache", "unknown", ""}:
                                            # ARP-only fallback clients are promoted only when
                                            # corroborated by this cycle's active discovery (e.g. ping).
                                            if _should_promote_hotspot_cache_client(client, active_discovered_ips):
                                                confirmed_clients.append(client)
                                                continue
                                            cache_only_clients.append(client)
                                            continue

                                        # netsh hostednetwork statuses can be stale on Windows.
                                        # Promote to active only when corroborated by fresh
                                        # discovery evidence (IP present now, seen in this cycle,
                                        # or recently confirmed).
                                        strong_status = status in {"connected", "associated", "authenticated", "leased"}
                                        has_fresh_signal = bool(ip_val) or (
                                            mac_norm
                                            and (
                                                mac_norm in active_discovered_macs
                                                or mac_norm in recent_confirmed
                                            )
                                        ) or source == "hostednetwork"

                                        if strong_status and has_fresh_signal:
                                            confirmed_clients.append(client)
                                        else:
                                            cache_only_clients.append(client)

                                    logger.debug(
                                        "hotspot clients classified: total=%d confirmed=%d cache_only=%d arp_confirmed_cycle=%d",
                                        len(clients),
                                        len(confirmed_clients),
                                        len(cache_only_clients),
                                        len(active_discovered_macs),
                                    )

                                    if confirmed_clients:
                                        _remember_active_signals(confirmed_clients)
                                        _upsert_arp_cache_devices(
                                            confirmed_clients,
                                            current_mode_name,
                                            set_active_mode=True,
                                            local_ips=_cycle_local_ips,
                                            expected_generation=mode_generation,
                                        )

                                    if cache_only_clients:
                                        preserve_macs = active_discovered_macs | _get_recently_confirmed_macs(
                                            HOTSPOT_STALE_DEVICE_SECONDS,
                                        )
                                        _upsert_arp_cache_devices(
                                            cache_only_clients,
                                            current_mode_name,
                                            set_active_mode=False,
                                            local_ips=_cycle_local_ips,
                                            expected_generation=mode_generation,
                                            clear_active_mode_when_inactive=True,
                                            preserve_active_macs=preserve_macs,
                                        )
                            except Exception as e:
                                logger.debug("Hotspot get_connected_clients error: %s", e)

                            # 5. Prune stale devices from in-memory dashboard
                            # so disconnected clients disappear quickly.
                            try:
                                from utils.realtime_state import dashboard_state
                                dashboard_state.remove_stale_devices(
                                    max_age_seconds=HOTSPOT_STALE_DEVICE_SECONDS
                                )
                            except Exception:
                                pass

                            # 6. Prune stale active_mode flags in DB too, so
                            # /api/devices cannot keep disconnected hotspot
                            # clients after ARP cache drops them.
                            _clear_stale_active_mode_devices(
                                current_mode_name,
                                HOTSPOT_STALE_DEVICE_SECONDS,
                            )

                        _iteration += 1

                        total = len(discovery.get_all_devices()) if hasattr(discovery, 'get_all_devices') else len(devices)
                        logger.debug("Discovery scan: %d device(s) known", total)
                    except ImportError:
                        pass
                    except Exception as e:
                        logger.debug("Discovery scan error: %s", e)
        except Exception as e:
            logger.debug("Discovery loop error: %s", e)

        # Hotspot needs faster discovery (15s) for quick device detection/removal
        wait_time = 15 if (state.interface_manager and
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
