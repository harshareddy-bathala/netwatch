"""
orchestration/mode_handler.py - Network Mode Transition Handler
================================================================

Handles mode change callbacks from InterfaceManager:

- Creates/restarts the CaptureEngine for the new mode.
- Resets in-memory state, caches, and subnet filters.
- Registers known IPs/MACs to prevent false alerts.
- Sends SSE events for frontend mode transitions.
"""

import logging
import subprocess
import re
import sys
import threading
import time

from orchestration import state
from orchestration.discovery_manager import (
    get_all_local_ips, get_all_local_macs, resolve_scapy_iface,
)
from packet_capture.capture_engine import CaptureEngine
from packet_capture.hostname_resolver import (
    learn_hostname as _learn_hostname,
    enqueue_for_resolution as _enqueue_resolution,
    set_restrict_mode as _set_resolver_restrict_mode,
)
from config import IS_WINDOWS

logger = logging.getLogger(__name__)

# MAC → (hostname, source) pending cache for DHCP hostnames learned
# before the device has an IP address (DISCOVER/REQUEST with 0.0.0.0).
# Keyed by lowercase MAC.  Applied when subsequent traffic from the same
# MAC carries a real IP address.
_pending_mac_hostnames: dict = {}
_pending_mac_lock = threading.Lock()


# =========================================================================
# Gateway MAC resolution
# =========================================================================

def resolve_gateway_mac(gateway_ip: str) -> str:
    """Look up the MAC address corresponding to a gateway IP.

    Tries:
    1. The ``devices`` table (gateway already discovered via ARP/traffic).
    2. Platform ARP table (``arp -a`` / ``ip neigh``).

    Returns an empty string when resolution fails.
    """
    if not gateway_ip:
        return ""

    # 1. Check the devices table
    try:
        from database.connection import get_connection
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT mac_address FROM devices "
                "WHERE ipv4_address = ? OR ip_address = ? LIMIT 1",
                (gateway_ip, gateway_ip),
            )
            row = cur.fetchone()
            if row:
                mac = row["mac_address"] if isinstance(row, dict) else row[0]
                if mac and mac.lower() not in ("", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    return mac.lower()
    except Exception:
        pass

    # 2. Parse platform ARP table
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["arp", "-a", gateway_ip],
                text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            out = subprocess.check_output(
                ["arp", "-n", gateway_ip], text=True, timeout=3,
            )
        mac_re = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", out)
        if mac_re:
            return mac_re.group(0).replace("-", ":").lower()
    except Exception:
        pass

    return ""


# =========================================================================
# Capture engine factory + callbacks
# =========================================================================

def _create_capture_engine(mode):
    """Factory: create the Scapy-based capture engine.

    Uses Npcap on Windows for reliable packet capture.
    Passes the capture strategy from InterfaceManager when available.
    """
    iface = mode.interface.name
    # On Windows, resolve the friendly name to an Npcap-compatible device
    if IS_WINDOWS:
        iface = resolve_scapy_iface(iface, mode.interface.ip_address)
    strategy = None
    if state.interface_manager:
        try:
            strategy = state.interface_manager.get_capture_strategy()
        except Exception as e:
            logger.debug("Could not get capture strategy: %s", e)
    logger.info(
        "Creating Scapy/Npcap capture engine on '%s' (strategy=%s)",
        iface, type(strategy).__name__ if strategy else 'None',
    )
    engine = CaptureEngine(mode, interface=iface, strategy=strategy)

    # Register callbacks
    engine.on_packet(_passive_hostname_callback)
    engine.on_interface_lost(_on_interface_lost)

    return engine


def _on_interface_lost():
    """Callback fired by CaptureEngine when the interface vanishes.

    Forces the InterfaceManager to skip the stability threshold and
    immediately switch to the best available mode.

    Dispatched to a background thread to avoid deadlock (the callback
    is invoked from the capture thread, which would deadlock if we
    tried to join() it during mode transition).
    """
    logger.warning("Capture interface lost -- triggering immediate mode re-detection")
    if state.interface_manager:
        def _redetect():
            try:
                state.interface_manager.notify_interface_lost()
            except Exception as e:
                logger.error("Error during interface-lost re-detection: %s", e)

        t = threading.Thread(target=_redetect, name="InterfaceLost-Redetect", daemon=True)
        t.start()


def _passive_hostname_callback(pkt_data):
    """Extract hostnames from mDNS, NetBIOS-NS, DNS, DHCP, SSDP packets
    and feed them to the hostname resolver's passive cache.

    Also enqueues devices without known hostnames for background resolution.

    Special handling for DHCP: the client's source IP is 0.0.0.0 during
    DISCOVER/REQUEST (before it has been assigned an IP).  In that case
    we resolve the device's actual IP via its MAC address from the
    in-memory device registry or the database, so the DHCP Option 12
    hostname is attributed to the correct device.

    If MAC → IP resolution also fails (device brand-new, not yet in DB),
    the hostname is cached by MAC in ``_pending_mac_hostnames`` and applied
    the next time ANY packet from that MAC carries a real IP address.
    """
    try:
        proto = (pkt_data.protocol or "").upper()
        if proto in ("MDNS", "NETBIOS-NS", "LLMNR", "DNS", "DHCP", "SSDP"):
            if pkt_data.device_name:
                ip = pkt_data.source_ip
                mac = pkt_data.source_mac

                # DHCP DISCOVER/REQUEST: source_ip is 0.0.0.0 — resolve
                # the device's real IP from its MAC address.
                if proto == "DHCP" and (not ip or ip == "0.0.0.0"):
                    ip = _resolve_ip_from_mac(mac)
                    # If still no IP, cache hostname by MAC for later
                    if not ip or ip == "0.0.0.0":
                        if mac:
                            with _pending_mac_lock:
                                _pending_mac_hostnames[mac.lower()] = (
                                    pkt_data.device_name, proto)
                            logger.debug(
                                "DHCP hostname '%s' cached by MAC %s (IP not yet known)",
                                pkt_data.device_name, mac,
                            )

                if ip and ip not in ("0.0.0.0", "255.255.255.255"):
                    _learn_hostname(ip, pkt_data.device_name, source=proto)
                    # Also update the in-memory dashboard state so the SSE
                    # device list shows the hostname immediately.
                    try:
                        from utils.realtime_state import dashboard_state
                        dashboard_state.update_device_hostname(ip, pkt_data.device_name)
                    except Exception:
                        pass
        else:
            ip = pkt_data.source_ip
            mac = pkt_data.source_mac
            if ip and mac:
                _enqueue_resolution(ip, mac)

            # Check if this MAC has a pending DHCP hostname waiting
            # for a real IP address.  If so, apply it now.
            if mac and ip and ip not in ("0.0.0.0", "255.255.255.255"):
                mac_lower = mac.lower()
                pending = None
                with _pending_mac_lock:
                    pending = _pending_mac_hostnames.pop(mac_lower, None)
                if pending:
                    hostname, source = pending
                    logger.info(
                        "Applying pending DHCP hostname '%s' to %s (MAC %s)",
                        hostname, ip, mac,
                    )
                    _learn_hostname(ip, hostname, source=source)
                    try:
                        from utils.realtime_state import dashboard_state
                        dashboard_state.update_device_hostname(ip, hostname)
                    except Exception:
                        pass
    except Exception:
        pass  # Never fail the capture pipeline


def _resolve_ip_from_mac(mac: str) -> str:
    """Look up a device's IPv4 address by its MAC from in-memory state or DB.

    Used when DHCP packets have source_ip=0.0.0.0 but we need the actual
    device IP to attribute the hostname correctly.
    """
    if not mac:
        return ""
    mac_lower = mac.lower().replace('-', ':')
    # 1. Check in-memory dashboard state (fastest)
    try:
        from utils.realtime_state import dashboard_state
        with dashboard_state._lock:
            dev = dashboard_state._devices.get(mac_lower)
            if dev and dev.ip_address and dev.ip_address != "0.0.0.0":
                return dev.ip_address
    except Exception:
        pass
    # 2. Fallback: check the database
    try:
        from database.connection import get_connection
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT ipv4_address, ip_address FROM devices "
                "WHERE mac_address = ? LIMIT 1",
                (mac_lower,),
            )
            row = cur.fetchone()
            if row:
                ip = (row["ipv4_address"] or row["ip_address"] or "")
                if ip and ip != "0.0.0.0":
                    return ip
    except Exception:
        pass
    return ""


# =========================================================================
# Route exposure
# =========================================================================

def expose_engine_to_routes():
    """Make the current engine, interface manager, detector, and health
    monitor accessible to Flask routes via ``app.config``."""
    if state.app:
        state.app.config['CAPTURE_ENGINE'] = state.capture_engine
        state.app.config['INTERFACE_MANAGER'] = state.interface_manager
        state.app.config['ANOMALY_DETECTOR'] = state.detector
        state.app.config['HEALTH_MONITOR'] = state.health_monitor
        # Clear the discovery singleton so it is re-created for the new interface
        state.app.config.pop('_DISCOVERY_SINGLETON', None)


# =========================================================================
# SSE mode-change push
# =========================================================================

def _send_mode_changed_sse(mode_name, is_disconnected=False):
    """Push a ``mode_changed`` SSE event to connected frontends."""
    try:
        import json
        from backend.blueprints.bandwidth_bp import _sse_push_event
        payload = json.dumps({
            'event': 'mode_changed',
            'mode': mode_name,
            'disconnected': is_disconnected,
        })
        _sse_push_event(payload)
    except Exception:
        pass  # SSE push is best-effort


# =========================================================================
# Mode change handler
# =========================================================================

def on_mode_change(old_mode, new_mode):
    """Callback fired by InterfaceManager when the network mode changes."""
    with state.engine_lock:
        _on_mode_change_locked(old_mode, new_mode)


def _on_mode_change_locked(old_mode, new_mode):
    """Inner implementation -- must be called while holding *engine_lock*.

    Acquires ``mode_transition_lock`` during the critical window between
    ``reset_subnet_cache()`` and the new engine being ready.  The
    ``DatabaseWriter`` checks this lock and re-queues (skips) DB writes
    while it is held, eliminating the race where packets are written
    against the wrong subnet.
    """
    old_name = old_mode.get_mode_name().value if old_mode else 'None'
    new_name = new_mode.get_mode_name().value

    # Skip if mode didn't actually change (same mode, same interface)
    if (old_mode is not None
        and old_name == new_name
        and old_mode.interface.name == new_mode.interface.name
        and old_mode.interface.ip_address == new_mode.interface.ip_address):
        logger.debug("Mode unchanged: %s -- skipping restart", new_name)
        return

    logger.info("Mode changed: %s -> %s -- restarting capture engine", old_name, new_name)

    # Detect if the network actually changed (different SSID or gateway)
    network_changed = (
        old_mode is None
        or old_name != new_name
        or getattr(old_mode.interface, 'ssid', None) != getattr(new_mode.interface, 'ssid', None)
        or getattr(old_mode.interface, 'gateway', None) != getattr(new_mode.interface, 'gateway', None)
        or getattr(old_mode.interface, 'ip_address', None) != getattr(new_mode.interface, 'ip_address', None)
    )

    # Check if we're now disconnected (no real interface)
    new_ip = new_mode.interface.ip_address
    new_iface_name = new_mode.interface.name
    is_disconnected = (
        not new_ip or new_ip == "0.0.0.0"
        or new_iface_name in ("none", "unknown", "")
        or getattr(new_mode.interface, "interface_type", "") == "disconnected"
    )

    if is_disconnected:
        logger.info("Network disconnected -- pausing capture engine")
        if state.capture_engine and state.capture_engine.is_running:
            try:
                state.capture_engine.stop()
            except Exception as e:
                logger.error("Error stopping capture engine: %s", e)
        state.capture_engine = None
        expose_engine_to_routes()
        _send_mode_changed_sse(new_name, is_disconnected=True)
        return

    # Acquire mode-transition lock
    state.mode_transition_lock.acquire()
    try:
        _send_mode_changed_sse(new_name, is_disconnected=False)

        # 1. Clear BandwidthCalculator on the old engine
        if state.capture_engine and hasattr(state.capture_engine, 'bandwidth'):
            try:
                state.capture_engine.bandwidth.reset()
            except Exception:
                pass

        # 2. Clear InMemoryDashboardState and set mode context
        #    Only clear byte counters when the network genuinely changed
        #    (different subnet/gateway/SSID).  Interface-only flaps (same
        #    network, different adapter) should NOT reset accumulated usage.
        own_traffic = False
        gw_mac_for_state = ''
        try:
            from utils.realtime_state import dashboard_state
            if network_changed:
                dashboard_state.clear()
            else:
                logger.debug("Same network, different interface — preserving dashboard state")

            own_traffic = (new_mode.get_scope().name == "OWN_TRAFFIC_ONLY")
            is_hotspot = (new_name == "hotspot")
            is_ethernet = (new_name == "ethernet")
            our_mac = getattr(new_mode.interface, 'mac_address', None) or ''
            gw_mac_for_state = resolve_gateway_mac(
                getattr(new_mode.interface, 'gateway', None) or ''
            )
            all_host_macs = get_all_local_macs()

            # In own-traffic mode (public_network) and ethernet mode, the
            # host's capture-interface MAC is a device we want to track —
            # remove it from the host-exclusion set so it appears in the
            # dashboard.  In hotspot mode the host IS the gateway and must
            # stay excluded.
            if (own_traffic or is_ethernet) and our_mac:
                our_mac_upper = our_mac.upper().replace('-', ':')
                all_host_macs.discard(our_mac_upper)
                all_host_macs.discard(our_mac.lower())

            dashboard_state.set_mode_context(
                our_mac=our_mac,
                gateway_mac=gw_mac_for_state,
                own_traffic_only=own_traffic,
                host_macs=all_host_macs,
                gateway_mac_exclude=own_traffic or is_hotspot,
                # IP-based host exclusion: only needed for hotspot mode
                # where the virtual adapter MAC may not be detected by
                # psutil.  In ethernet mode the host IS a device we track.
                our_ip=new_mode.interface.ip_address or '' if is_hotspot else '',
            )
        except Exception:
            pass

        # 2b. Clear stale device data on network change
        if network_changed:
            try:
                from database.connection import get_connection as _gc
                with _gc() as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE devices SET active_mode = NULL WHERE active_mode IS NOT NULL")
                    conn.commit()
                logger.info("Cleared device active_mode flags for network change")
            except Exception as e:
                logger.debug("Could not clear device data on network change: %s", e)
            try:
                from database.queries.device_queries import _device_cache
                _device_cache.clear()
            except Exception:
                pass

        # 3. Invalidate SSE cache + clear route-level TTL caches
        try:
            from backend.blueprints.bandwidth_bp import invalidate_sse_cache
            invalidate_sse_cache()
        except ImportError:
            pass
        try:
            from backend.helpers import clear_response_cache
            clear_response_cache()
        except ImportError:
            pass

        # 4. Stop old NetworkDiscovery before creating new
        with state.cached_discovery_lock:
            if state.cached_discovery is not None:
                try:
                    state.cached_discovery.stop_continuous_discovery()
                    logger.debug("Old NetworkDiscovery stopped")
                except Exception:
                    pass
                state.cached_discovery = None

        # 5. Update subnet cache and mode for device filtering
        try:
            from database.queries.device_queries import (
                set_subnet_from_ip, set_current_mode, reset_subnet_cache,
                set_gateway_ip, set_capture_interface, scope_devices_to_mode,
                set_gateway_mac,
            )
            reset_subnet_cache()
            if new_mode.interface.name:
                set_capture_interface(new_mode.interface.name)
            if new_mode.interface.ip_address:
                set_subnet_from_ip(new_mode.interface.ip_address)
                new_parts = new_mode.interface.ip_address.split('.')
                if len(new_parts) == 4:
                    new_prefix = f"{new_parts[0]}.{new_parts[1]}.{new_parts[2]}"
                    our_mac = getattr(new_mode.interface, 'mac_address', None) or ''
                    gw_mac = resolve_gateway_mac(
                        getattr(new_mode.interface, 'gateway', None) or ''
                    )
                    scope_devices_to_mode(
                        new_name, new_prefix,
                        our_mac=our_mac,
                        gateway_mac=gw_mac,
                    )
                    # Pre-seed own device in memory
                    if own_traffic and our_mac:
                        import socket as _sock
                        _hostname = _sock.gethostname()
                        from utils.realtime_state import dashboard_state
                        dashboard_state.set_own_device_info(
                            mac=our_mac,
                            hostname=_hostname,
                            ip=new_mode.interface.ip_address or "",
                        )
                        # Also write hostname to DB so /api/devices shows it
                        _self_ip = new_mode.interface.ip_address or ""
                        try:
                            from database.connection import get_connection as _dbgc
                            with _dbgc() as _conn:
                                _conn.execute(
                                    """INSERT INTO devices
                                           (mac_address, hostname, device_name,
                                            ip_address, ipv4_address,
                                            first_seen, last_seen)
                                       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                                       ON CONFLICT(mac_address) DO UPDATE SET
                                           hostname = ?,
                                           device_name = COALESCE(device_name, ?),
                                           ipv4_address = COALESCE(?, ipv4_address),
                                           ip_address = COALESCE(?, ip_address),
                                           last_seen = CURRENT_TIMESTAMP""",
                                    (our_mac, _hostname, _hostname,
                                     _self_ip, _self_ip,
                                     _hostname, _hostname, _self_ip, _self_ip),
                                )
                                _conn.commit()
                        except Exception:
                            pass
                        # Protect hostname in passive cache with highest priority
                        # so lower-priority sources (DNS, DHCP) can't overwrite it.
                        if _self_ip:
                            _learn_hostname(_self_ip, _hostname, source='MDNS')
                    set_gateway_mac(gw_mac)
            gw = getattr(new_mode.interface, "gateway", None)
            set_gateway_ip(gw or "")
            set_current_mode(new_name)
            if own_traffic and new_mode.interface.ip_address:
                _set_resolver_restrict_mode(new_mode.interface.ip_address)
            else:
                _set_resolver_restrict_mode(None)
            logger.info(
                "Device discovery updated for mode '%s' on %s (gw=%s)",
                new_name, new_mode.interface.ip_address, gw,
            )
        except Exception as e:
            logger.warning("Could not update subnet for new mode: %s", e)

        # 6. Register known IPs/MACs to prevent false alerts
        try:
            from alerts import get_shared_engine as _get_shared_engine
            ae = _get_shared_engine()
            if ae:
                new_mac = getattr(new_mode.interface, 'mac_address', None)
                if new_mac:
                    ae.add_known_mac(new_mac)
                new_ip_addr = new_mode.interface.ip_address
                if new_ip_addr:
                    ae.add_known_ip(new_ip_addr)
                for _lip in get_all_local_ips():
                    ae.add_known_ip(_lip)
                gw_ip = getattr(new_mode.interface, 'gateway', None)
                if gw_ip:
                    ae.add_known_ip(gw_ip)
                if gw_mac_for_state:
                    ae.add_known_mac(gw_mac_for_state)
        except Exception:
            pass

        # 7. Stop the old engine
        if state.capture_engine and state.capture_engine.is_running:
            try:
                state.capture_engine.stop()
            except Exception as e:
                logger.error("Error stopping old capture engine: %s", e)

        # 8. Wait briefly for the interface to be ready
        iface_name = new_mode.interface.name
        for attempt in range(3):
            try:
                import psutil
                if any(iface_name.lower() in name.lower() for name in psutil.net_if_addrs()):
                    break
            except ImportError:
                break
            except Exception:
                pass
            logger.debug("Waiting for interface '%s' to be ready (%d/3)...", iface_name, attempt + 1)
            time.sleep(1)

        # 9. Start a new engine with the new mode
        try:
            state.capture_engine = _create_capture_engine(new_mode)
            state.capture_engine.start()
            expose_engine_to_routes()
            logger.info("Capture engine restarted for mode '%s' on interface '%s'",
                        new_name, new_mode.interface.name)
        except Exception as e:
            logger.error("Failed to restart capture engine: %s", e)
    finally:
        state.mode_transition_lock.release()


# =========================================================================
# Startup
# =========================================================================

def start_packet_capture():
    """Start InterfaceManager + CaptureEngine."""
    from packet_capture.interface_manager import InterfaceManager

    try:
        state.interface_manager = InterfaceManager()
        state.interface_manager.start_monitoring()

        mode = state.interface_manager.get_current_mode()
        logger.info("Detected mode: %s on interface '%s'",
                     mode.get_mode_name().value, mode.interface.name)

        state.capture_engine = _create_capture_engine(mode)
        state.capture_engine.start()

        # Register mode-change callback
        state.interface_manager.on_mode_change(on_mode_change)

        return True
    except PermissionError:
        logger.error("Permission denied for packet capture. Run as Administrator/root.")
        return False
    except Exception as e:
        logger.error("Failed to start packet capture: %s", e)
        return False
