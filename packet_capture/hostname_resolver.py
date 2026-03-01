"""
hostname_resolver.py - Device Hostname Resolution (Phase 2)
=============================================================

Resolves device hostnames using multiple methods with priority on
**passive learning** from captured network traffic.

Resolution priority:
1. Passive hostname cache (from mDNS/NetBIOS/DHCP/DNS/SSDP packets) — 1 h TTL
2. TTL-bounded active cache (5 min TTL)
3. mDNS .local query (via zeroconf when available, fallback to raw UDP)
4. Reverse DNS lookup (short timeout)
5. NetBIOS name resolution (Windows nbtstat -A, rate-limited)
6. MAC vendor lookup (via manuf library)
7. Fallback to "Vendor (last_octet)" format

Background resolution:
- A periodic background thread resolves devices with ``hostname IS NULL``
  in the database every 10 seconds.
- New device MACs are enqueued for background resolution (not in API path).
- API queries ONLY read ``hostname`` from DB, never trigger resolution.

Thread-safe with a lock around the shared cache.
"""

import socket
import logging
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Optional, Dict, Tuple, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache Configuration
# ---------------------------------------------------------------------------
_CACHE_MAX_SIZE = 1024              # Maximum cached entries
_CACHE_TTL_SECONDS = 300            # 5 minutes (active resolution)
_PASSIVE_CACHE_TTL_SECONDS = 3600   # 1 hour (passive learning — more reliable)
_PASSIVE_CACHE_MAX_SIZE = 5000      # Maximum passive cache entries before LRU eviction
_DNS_TIMEOUT_SECONDS = 1.5          # Per-resolve timeout

# NetBIOS rate limiting (increased from 3 → 8 for better concurrency)
_NBTSTAT_MAX_PENDING = 8
_nbtstat_pending = 0
_nbtstat_lock = threading.Lock()

# Background resolution interval
_BG_RESOLVE_INTERVAL = 3   # seconds (reduced from 10 so new-device hostnames appear quickly)

IS_WINDOWS = sys.platform == "win32"

# Source priority for passive hostname learning.
# Higher value = more trustworthy.  mDNS/SSDP names are self-advertised
# by the device and should never be overwritten by generic DHCP names.
_SOURCE_PRIORITY = {
    'MDNS': 10,
    'NETBIOS-NS': 8,
    'SSDP': 6,
    'LLMNR': 4,
    'DHCP': 2,
    'DNS': 1,
}
_DEFAULT_SOURCE_PRIORITY = 0

# Try to import MAC vendor lookup libraries
_mac_lookup = None
VENDOR_AVAILABLE = False

# Prefer mac_vendor_lookup (in requirements.txt)
try:
    from mac_vendor_lookup import MacLookup  # type: ignore[import-untyped]
    _mac_lookup = MacLookup()
    VENDOR_AVAILABLE = True
    logger.debug("Using mac_vendor_lookup for vendor resolution")
except (ImportError, Exception):
    pass

# Fallback: try manuf
_mac_parser = None
if not VENDOR_AVAILABLE:
    try:
        from manuf import manuf as manuf_mod  # type: ignore[import-not-found]
        _mac_parser = manuf_mod.MacParser(update=False)
        VENDOR_AVAILABLE = True
        logger.debug("Using manuf for vendor resolution")
    except (ImportError, Exception):
        logger.debug("No MAC vendor library available — vendor lookup disabled")

# Try to import zeroconf for robust mDNS resolution
_zeroconf_available = False
try:
    from zeroconf import Zeroconf, ServiceBrowser, IPVersion  # type: ignore[import-untyped]
    _zeroconf_available = True
    logger.debug("zeroconf library available for mDNS resolution")
except ImportError:
    logger.debug("zeroconf not available — using fallback mDNS")


class HostnameResolver:
    """
    Resolve device hostnames using multiple methods.

    Priority:
    1. Passive hostname cache (learned from mDNS/NetBIOS/DHCP/DNS/SSDP packets) — 1h TTL
    2. TTL-bounded active cache (max ``_CACHE_MAX_SIZE`` entries, 5 min TTL)
    3. mDNS ``.local`` query (via zeroconf or raw UDP)
    4. Reverse DNS (with ``_DNS_TIMEOUT_SECONDS`` timeout)
    5. NetBIOS name on Windows (``nbtstat -A``, rate-limited to 8 concurrent)
    6. MAC vendor + last IP octet
    """

    def __init__(self):
        # cache_key -> (hostname, expiry_timestamp)
        self._cache: Dict[str, Tuple[str, float]] = {}
        # Passive hostname store: ip -> (hostname, expiry_timestamp, source_priority)
        self._passive_hostnames: Dict[str, Tuple[str, float, int]] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="DNS")

        # Background resolution queue: set of (ip, mac) tuples to resolve
        self._resolve_queue: deque = deque(maxlen=500)
        self._resolve_queue_set: Set[str] = set()  # for O(1) dedup
        self._queue_lock = threading.Lock()

        # Background resolution thread
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_shutdown = threading.Event()

        # Zeroconf instance (lazy init)
        self._zeroconf = None
        self._zeroconf_lock = threading.Lock()

    def close(self):
        """Shut down the background DNS executor and resolution thread."""
        self._bg_shutdown.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=5)
        # Wait for pending DNS queries to complete, cancel any remaining
        try:
            self._executor.shutdown(wait=True, cancel_futures=True)
        except Exception:
            self._executor.shutdown(wait=False)
        # Shut down zeroconf
        with self._zeroconf_lock:
            if self._zeroconf is not None:
                try:
                    self._zeroconf.close()
                except Exception:
                    pass
                self._zeroconf = None

    def start_background_resolver(self):
        """
        Start the background resolution thread that periodically resolves
        devices with hostname IS NULL in the database.
        """
        if self._bg_thread and self._bg_thread.is_alive():
            return
        self._bg_shutdown.clear()
        self._bg_thread = threading.Thread(
            target=self._background_resolve_loop,
            name="HostnameResolver-BG",
            daemon=True,
        )
        self._bg_thread.start()
        logger.info("Background hostname resolver started (interval=%ds)", _BG_RESOLVE_INTERVAL)

    def start_mdns_browser(self, periodic: bool = False):
        """
        Start mDNS service browsing for common service types to
        proactively discover named devices on the network.

        Args:
            periodic: If True, re-browse every 10 minutes (for port_mirror mode).
                      If False, browse once for 10 seconds then exit.
        """
        if not _zeroconf_available:
            logger.debug("zeroconf not available — skipping mDNS browser startup")
            return

        def _do_browse():
            """Run a single 10-second mDNS browse cycle."""
            try:
                zc = self._get_zeroconf()
                if not zc:
                    return

                class _Listener:
                    """Collect discovered service names into the passive cache."""
                    def __init__(self, resolver_ref):
                        self._resolver = resolver_ref

                    def add_service(self, zc_inst, type_, name):
                        try:
                            info = zc_inst.get_service_info(type_, name)
                            if info and info.server:
                                server = info.server.rstrip('.')
                                if server.endswith('.local'):
                                    server = server[:-6]
                                # Get IP addresses from the service info
                                for addr in info.parsed_addresses(IPVersion.V4Only):
                                    if addr and server:
                                        self._resolver.learn_hostname(addr, server, source='MDNS')
                        except Exception:
                            pass

                    def remove_service(self, zc_inst, type_, name):
                        pass

                    def update_service(self, zc_inst, type_, name):
                        pass

                listener = _Listener(self)
                service_types = [
                    "_http._tcp.local.",
                    "_smb._tcp.local.",
                    "_workstation._tcp.local.",
                    "_device-info._tcp.local.",
                    "_googlecast._tcp.local.",
                    "_airplay._tcp.local.",
                    "_raop._tcp.local.",
                    "_ipp._tcp.local.",
                ]
                browsers = []
                for stype in service_types:
                    try:
                        browser = ServiceBrowser(zc, stype, listener)
                        browsers.append(browser)
                    except Exception:
                        pass

                # Let it run for 10 seconds to discover devices
                time.sleep(10)

                # Cancel browsers (but keep zeroconf alive for later queries)
                for b in browsers:
                    try:
                        b.cancel()
                    except Exception:
                        pass

                logger.info("mDNS browse complete — discovered services on network")
            except Exception as e:
                logger.debug("mDNS browse error: %s", e)

        def _browse_loop():
            """Periodic mDNS browsing — re-discovers new devices every 10 min."""
            while not self._bg_shutdown.is_set():
                _do_browse()
                # Wait 10 minutes between browse cycles
                self._bg_shutdown.wait(600)

        if periodic:
            t = threading.Thread(target=_browse_loop, name="mDNS-Browse", daemon=True)
        else:
            t = threading.Thread(target=_do_browse, name="mDNS-Browse", daemon=True)
        t.start()

    def enqueue_for_resolution(self, ip: str, mac: Optional[str] = None):
        """
        Enqueue a device for background hostname resolution.

        Called when a new device MAC is first seen (e.g. from ARP scan
        or packet capture). Resolution happens in the background thread,
        not in the API path.
        """
        if not ip:
            return
        key = f"{ip}:{mac or ''}"
        with self._queue_lock:
            if key not in self._resolve_queue_set:
                self._resolve_queue.append((ip, mac))
                self._resolve_queue_set.add(key)

    def learn_hostname(self, ip: str, hostname: str,
                       source: Optional[str] = None) -> None:
        """
        Passively learn a hostname from captured network traffic
        (mDNS responses, NetBIOS-NS, DHCP, DNS answers, SSDP, etc.).

        Uses a source-priority system so that high-quality names
        (mDNS device self-advertisement) are never overwritten by
        lower-quality sources (DHCP Option 12 generic names).

        Also persists the hostname to the DB immediately with
        ``from_passive=True`` so it overwrites any stale active-resolution
        hostname (e.g. "Android_35VI4FNN" replaced by "Galaxy-Tab-A9").
        """
        if not ip or not hostname:
            return
        # Ignore bare IPs or boilerplate
        if hostname == ip or hostname.lower() in ("unknown", "n/a", ""):
            return
        # Filter out IPv6 link-local addresses being used as hostnames
        if hostname.startswith("fe80::") or hostname.startswith("::"):
            return

        new_priority = _SOURCE_PRIORITY.get(
            (source or '').upper(), _DEFAULT_SOURCE_PRIORITY)

        with self._lock:
            now = time.monotonic()

            # Check existing entry — protect higher-priority names even
            # after expiry.  A high-priority name (e.g. mDNS) that expired
            # must NOT be overwritten by a lower-priority source (e.g. DHCP
            # or DNS).  Only same-or-higher priority sources may replace it.
            existing = self._passive_hostnames.get(ip)
            if existing:
                existing_priority = existing[2] if len(existing) > 2 else _DEFAULT_SOURCE_PRIORITY
                if new_priority < existing_priority:
                    # Lower priority — reject regardless of TTL expiry.
                    # Just refresh the TTL of the existing entry so it stays
                    # cached for lookups.
                    if now >= existing[1]:
                        self._passive_hostnames[ip] = (existing[0], now + _PASSIVE_CACHE_TTL_SECONDS, existing_priority)
                    return
                # Same hostname from same-or-higher priority — just refresh TTL
                if existing[0] == hostname:
                    self._passive_hostnames[ip] = (hostname, now + _PASSIVE_CACHE_TTL_SECONDS, max(new_priority, existing_priority))
                    return

            self._passive_hostnames[ip] = (hostname, now + _PASSIVE_CACHE_TTL_SECONDS, new_priority)
            # Also update the active TTL cache immediately so subsequent lookups hit instantly
            cache_key_prefix = f"{ip}:"
            for key in list(self._cache.keys()):
                if key.startswith(cache_key_prefix):
                    self._cache[key] = (hostname, now + _PASSIVE_CACHE_TTL_SECONDS)
            # Enforce size cap — evict oldest 10% when at capacity
            if len(self._passive_hostnames) > _PASSIVE_CACHE_MAX_SIZE:
                sorted_ips = sorted(
                    self._passive_hostnames,
                    key=lambda k: self._passive_hostnames[k][1],
                )
                evict_count = max(1, _PASSIVE_CACHE_MAX_SIZE // 10)
                for k in sorted_ips[:evict_count]:
                    del self._passive_hostnames[k]

        # Persist to DB immediately — passive names are authoritative and
        # should overwrite any stale active-resolution hostname.
        try:
            self._persist_hostname_to_db(ip, None, hostname, from_passive=True)
        except Exception:
            pass

        # Enqueue for background retry: if the device row doesn't exist yet
        # (e.g. mDNS browse fires before first packet arrives), _persist_hostname_to_db
        # silently updates 0 rows.  Enqueueing ensures the background resolver
        # will re-persist the hostname once the device appears in the DB.
        with self._queue_lock:
            if ip not in self._resolve_queue_set:
                self._resolve_queue_set.add(ip)
                self._resolve_queue.append((ip, None))

    def resolve(self, ip: str, mac: Optional[str] = None) -> str:
        """
        Resolve hostname for a device.

        Returns a human-readable name like "DESKTOP-ABC" or "Apple (114)"
        or the reverse DNS name.  Falls back to the IP address if nothing found.
        """
        # Fast-path: if the IP is our own machine, return the local hostname
        # immediately without DNS lookup.  Check ALL local adapter IPs
        # (not just the primary one) so that hotspot/VPN/secondary IPs
        # also resolve to our hostname.
        try:
            local_hostname = socket.gethostname()
            # Collect all IPs for our hostname (may resolve to multiple)
            _local_ips = set()
            try:
                _local_ips.add(socket.gethostbyname(local_hostname))
            except (socket.error, OSError):
                pass
            # Also check all adapter IPs via psutil for cross-adapter coverage
            try:
                import psutil
                for _iname, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family.name == 'AF_INET':
                            a = addr.address
                            if a and a not in ('0.0.0.0', '127.0.0.1'):
                                _local_ips.add(a)
            except (ImportError, Exception):
                pass
            if ip in _local_ips:
                return local_hostname
        except (socket.error, OSError):
            pass

        cache_key = f"{ip}:{mac or ''}"
        now = time.monotonic()

        # 1. Check passive hostname cache FIRST (most reliable, longer TTL)
        with self._lock:
            passive = self._passive_hostnames.get(ip)
        if passive:
            hostname, expiry = passive[0], passive[1]
            if now < expiry:
                # Also update active cache
                self._put_cache(cache_key, hostname, now, ttl=_PASSIVE_CACHE_TTL_SECONDS)
                return hostname
            else:
                # Expired — still return the cached name but refresh TTL.
                # Don't remove the entry; the priority protection in
                # learn_hostname() depends on it persisting so lower-priority
                # sources can't overwrite a good name.
                priority = passive[2] if len(passive) > 2 else _DEFAULT_SOURCE_PRIORITY
                with self._lock:
                    self._passive_hostnames[ip] = (hostname, now + _PASSIVE_CACHE_TTL_SECONDS, priority)
                self._put_cache(cache_key, hostname, now, ttl=_PASSIVE_CACHE_TTL_SECONDS)
                return hostname

        # 2. Check active cache (with TTL)
        with self._lock:
            entry = self._cache.get(cache_key)
            if entry is not None:
                hostname, expiry = entry
                if now < expiry:
                    return hostname
                # Expired — remove stale entry
                del self._cache[cache_key]

        hostname = None

        # 3. mDNS .local query (before DNS — works for Apple/Linux/IoT)
        mdns_name = self._mdns_lookup(ip)
        if mdns_name:
            self._put_cache(cache_key, mdns_name, now)
            return mdns_name

        # 4. Reverse DNS (with timeout)
        hostname = self._reverse_dns(ip)
        if hostname and hostname != ip:
            # Filter out fe80:: style hostnames
            if not hostname.startswith("fe80::") and not hostname.startswith("::"):
                # Reject if reverse DNS returned our own machine's hostname.
                # On Windows Mobile Hotspot, the built-in DNS often resolves
                # client IPs back to the host's name — giving every connected
                # device the host's hostname instead of its own.
                _is_own_name = False
                try:
                    _local_name = socket.gethostname().lower()
                    if hostname.lower() == _local_name:
                        _is_own_name = True
                    # Also check short name vs FQDN variants
                    if hostname.lower().split('.')[0] == _local_name.split('.')[0]:
                        _is_own_name = True
                except Exception:
                    pass
                if not _is_own_name:
                    self._put_cache(cache_key, hostname, now)
                    return hostname

        # 5. NetBIOS name resolution (Windows — nbtstat -A)
        if IS_WINDOWS:
            nb_name = self._netbios_lookup(ip)
            if nb_name:
                self._put_cache(cache_key, nb_name, now)
                return nb_name

        # 6. MAC vendor lookup
        if mac:
            vendor = self._get_vendor(mac)
            if vendor and vendor != "Unknown":
                last_octet = ip.split('.')[-1] if ip else '?'
                hostname = f"{vendor} ({last_octet})"
                self._put_cache(cache_key, hostname, now)
                return hostname

        # 6b. Gateway-aware fallback: if this IP is the known gateway,
        # label it as "Gateway" (with vendor prefix if available)
        try:
            from database.queries.device_queries import _get_gateway_ip
            gw_ip = _get_gateway_ip()
            if gw_ip and ip == gw_ip:
                gw_label = "Gateway / Router"
                if mac:
                    vendor = self._get_vendor(mac)
                    if vendor and vendor != "Unknown":
                        gw_label = f"{vendor} Gateway"
                self._put_cache(cache_key, gw_label, now)
                return gw_label
        except Exception:
            pass

        # 7. Fallback — cache the miss too (avoid repeated lookups)
        self._put_cache(cache_key, ip, now)
        return ip

    def _put_cache(self, key: str, value: str, now: float,
                   ttl: int = _CACHE_TTL_SECONDS) -> None:
        """Store a value in the cache, evicting oldest entries if at capacity."""
        with self._lock:
            # Evict ~10% when at capacity
            if len(self._cache) >= _CACHE_MAX_SIZE:
                sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][1])
                for k in sorted_keys[:max(1, _CACHE_MAX_SIZE // 10)]:
                    del self._cache[k]
            self._cache[key] = (value, now + ttl)

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Attempt reverse DNS lookup with a short timeout.

        Uses the class-level thread-pool executor so we never create
        a new executor per call and never mutate the process-global
        socket.setdefaulttimeout().
        """
        def _blocking_lookup():
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname

        try:
            future = self._executor.submit(_blocking_lookup)
            result = future.result(timeout=_DNS_TIMEOUT_SECONDS)
            # Strip domain suffix for cleaner display (e.g. "DESKTOP-ABC.lan" → "DESKTOP-ABC")
            if result and '.' in result:
                short = result.split('.')[0]
                # Only use short name if original looks like hostname.domain
                # (not for pure IP-based PTR like "114.196.16.172.in-addr.arpa")
                if not short.replace('-', '').isdigit():
                    return short
            return result
        except (FuturesTimeout, socket.herror, socket.gaierror,
                socket.timeout, OSError):
            return None

    def _netbios_lookup(self, ip: str) -> Optional[str]:
        """
        Resolve hostname via Windows NetBIOS (nbtstat -A).

        Rate-limited to prevent fork-bombing (max 8 concurrent).
        Results are cached through the main cache mechanism, so nbtstat
        is only called once per IP per TTL period.
        """
        global _nbtstat_pending

        with _nbtstat_lock:
            if _nbtstat_pending >= _NBTSTAT_MAX_PENDING:
                return None
            _nbtstat_pending += 1

        try:
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True,
                text=True,
                timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if '<00>' in line and 'UNIQUE' in line:
                        parts = line.split()
                        if parts:
                            name = parts[0].strip()
                            if name and name != '__MSBROWSE__':
                                return name
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        except Exception:
            logger.debug("NetBIOS lookup failed for %s", ip, exc_info=True)
        finally:
            with _nbtstat_lock:
                _nbtstat_pending = max(0, _nbtstat_pending - 1)

        return None

    def _get_zeroconf(self):
        """Lazily initialize and return the shared Zeroconf instance."""
        if not _zeroconf_available:
            return None
        with self._zeroconf_lock:
            if self._zeroconf is None:
                try:
                    self._zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
                except Exception as e:
                    logger.debug("Failed to init Zeroconf: %s", e)
                    return None
            return self._zeroconf

    def _mdns_lookup(self, ip: str) -> Optional[str]:
        """
        Attempt to discover a device's mDNS (.local) hostname.

        Uses the zeroconf library when available for robust resolution.
        Falls back to a hand-crafted UDP PTR query otherwise.
        """
        # Try zeroconf first (check cache for known records)
        if _zeroconf_available:
            result = self._mdns_lookup_zeroconf(ip)
            if result:
                return result

        # Fallback: raw UDP mDNS query
        return self._mdns_lookup_raw(ip)

    def _mdns_lookup_zeroconf(self, ip: str) -> Optional[str]:
        """mDNS resolution using the zeroconf library's cache."""
        try:
            # Build reverse lookup name for mDNS
            parts = ip.split('.')
            if len(parts) != 4:
                return None

            ptr_name = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa."

            zc = self._get_zeroconf()
            if not zc:
                return None

            # Use zeroconf's cache to check for known PTR records
            try:
                from zeroconf import DNSPointer
                records = zc.cache.entries_with_name(ptr_name)
                for entry in records:
                    if isinstance(entry, DNSPointer):
                        alias = entry.alias.rstrip('.')
                        if alias.endswith('.local'):
                            alias = alias[:-6]
                        if alias and not alias.startswith('_'):
                            return alias
            except (ImportError, AttributeError):
                pass

            return None
        except Exception:
            return None

    def _mdns_lookup_raw(self, ip: str) -> Optional[str]:
        """
        Raw UDP mDNS PTR query (fallback when zeroconf is not available
        or has no cached result).
        """
        try:
            # Build the PTR name for the IP (reverse lookup)
            parts = ip.split('.')
            if len(parts) != 4:
                return None
            ptr_name = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"

            # Send mDNS query to 224.0.0.251:5353
            import struct
            # Build a minimal DNS PTR query
            transaction_id = 0x0000
            flags = 0x0000  # standard query
            questions = 1
            header = struct.pack('!HHHHHH', transaction_id, flags, questions, 0, 0, 0)

            # Encode the PTR name
            qname = b''
            for label in ptr_name.split('.'):
                qname += bytes([len(label)]) + label.encode('ascii')
            qname += b'\x00'
            qtype_qclass = struct.pack('!HH', 12, 1)  # PTR, IN class

            packet = header + qname + qtype_qclass

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            try:
                sock.sendto(packet, ('224.0.0.251', 5353))
                data, _ = sock.recvfrom(1024)

                # Parse the response — extract answer section
                if len(data) < 12:
                    return None
                ans_count = struct.unpack('!H', data[6:8])[0]
                if ans_count == 0:
                    return None

                # Skip the question section
                offset = 12
                # Skip QNAME
                while offset < len(data) and data[offset] != 0:
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                        break
                    offset += data[offset] + 1
                else:
                    offset += 1
                offset += 4  # QTYPE + QCLASS

                # Parse first answer
                hostname = self._parse_dns_name(data, offset)
                if hostname:
                    # Skip name + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
                    # Jump to RDATA
                    name_end = offset
                    while name_end < len(data) and data[name_end] != 0:
                        if data[name_end] & 0xC0 == 0xC0:
                            name_end += 2
                            break
                        name_end += data[name_end] + 1
                    else:
                        name_end += 1
                    rdata_offset = name_end + 10  # TYPE + CLASS + TTL + RDLENGTH

                    ptr_name_result = self._parse_dns_name(data, rdata_offset)
                    if ptr_name_result:
                        # Strip ".local" suffix
                        clean = ptr_name_result.rstrip('.')
                        if clean.lower().endswith('.local'):
                            clean = clean[:-6]
                        return clean
            finally:
                sock.close()
        except (socket.timeout, OSError):
            pass
        except Exception:
            logger.debug("mDNS lookup failed for %s", ip, exc_info=True)

        return None

    @staticmethod
    def _parse_dns_name(data: bytes, offset: int) -> Optional[str]:
        """Parse a DNS name from a packet, handling compression pointers."""
        labels = []
        seen_offsets = set()
        while offset < len(data):
            if offset in seen_offsets:
                break  # prevent infinite loops
            seen_offsets.add(offset)

            length = data[offset]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                # Compression pointer
                if offset + 1 >= len(data):
                    break
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                # Follow the pointer to read the rest of the name
                rest = HostnameResolver._parse_dns_name(data, pointer)
                if rest:
                    labels.append(rest)
                break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                labels.append(data[offset:offset + length].decode('ascii', errors='replace'))
                offset += length

        return '.'.join(labels) if labels else None

    def _get_vendor(self, mac: str) -> str:
        """Get vendor name from MAC address."""
        if not VENDOR_AVAILABLE:
            return "Unknown"
        try:
            if _mac_lookup is not None:
                result = _mac_lookup.lookup(mac)
                # Some versions of mac_vendor_lookup return a coroutine
                # from .lookup() — run it synchronously if needed.
                import inspect
                if inspect.isawaitable(result):
                    import asyncio
                    try:
                        result = asyncio.run(result)
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        try:
                            result = loop.run_until_complete(result)
                        finally:
                            loop.close()
                return result if result else "Unknown"
            elif _mac_parser is not None:
                vendor = _mac_parser.get_manuf(mac)
                return vendor if vendor else "Unknown"
            return "Unknown"
        except Exception:
            return "Unknown"

    def clear_cache(self):
        """Clear the hostname cache."""
        with self._lock:
            self._cache.clear()
            self._passive_hostnames.clear()

    # -----------------------------------------------------------------
    # Background resolution
    # -----------------------------------------------------------------

    def _background_resolve_loop(self):
        """
        Periodically resolve hostnames for:
        1. Devices enqueued via enqueue_for_resolution()
        2. Devices in DB with hostname IS NULL
        3. Evict expired passive cache entries (prevents unbounded growth)

        Runs every _BG_RESOLVE_INTERVAL seconds. Persists resolved names
        to DB immediately so subsequent API queries see them.
        """
        logger.info("Background hostname resolution loop started")
        _last_passive_eviction = time.monotonic()
        while not self._bg_shutdown.wait(timeout=_BG_RESOLVE_INTERVAL):
            try:
                self._process_resolution_queue()
                self._resolve_null_hostnames_in_db()

                # Every 5 minutes: evict expired entries from passive cache
                now = time.monotonic()
                if now - _last_passive_eviction >= 300:
                    self._evict_expired_passive_entries()
                    _last_passive_eviction = now
            except Exception as e:
                logger.debug("Background resolve error: %s", e)

    def _evict_expired_passive_entries(self):
        """Remove expired entries from the passive hostname cache."""
        now = time.monotonic()
        with self._lock:
            expired = [ip for ip, entry in self._passive_hostnames.items() if now >= entry[1]]
            for ip in expired:
                del self._passive_hostnames[ip]
        if expired:
            logger.debug("Evicted %d expired passive hostname entries", len(expired))

    def _process_resolution_queue(self):
        """Process devices enqueued for background resolution.

        When restrict mode is active, only resolves entries matching
        the restricted IP.
        """
        batch = []
        restrict_ip = _restrict_to_own_ip  # snapshot
        with self._queue_lock:
            while self._resolve_queue and len(batch) < 20:
                item = self._resolve_queue.popleft()
                key = f"{item[0]}:{item[1] or ''}"
                self._resolve_queue_set.discard(key)
                # In restrict mode, skip entries that aren't our IP
                if restrict_ip and item[0] != restrict_ip:
                    continue
                batch.append(item)

        for ip, mac in batch:
            try:
                # Check if we have a passive (mDNS/DHCP) name — use from_passive flag
                _is_passive = False
                with self._lock:
                    passive = self._passive_hostnames.get(ip)
                    if passive and time.monotonic() < passive[1]:
                        _is_passive = True
                resolved = self.resolve(ip, mac)
                if resolved and resolved != ip:
                    self._persist_hostname_to_db(ip, mac, resolved,
                                                 from_passive=_is_passive)
            except Exception:
                pass

    def _resolve_null_hostnames_in_db(self):
        """
        Find devices in the DB with hostname IS NULL and attempt resolution.
        This runs in the background, NOT in the API path.

        When ``_restrict_to_own_ip`` is set (public_network mode), only
        the host's own device is resolved — no DNS/mDNS/NetBIOS probes
        are made for other devices on the network.

        Also re-resolves devices whose hostname matches the local machine
        name (caused by Windows hotspot DNS returning the host name for
        client IPs).
        """
        try:
            from database.connection import get_connection

            restrict_ip = _restrict_to_own_ip  # snapshot module-level flag

            # Detect local hostname for stale-name cleanup
            _local_hn = ""
            try:
                _local_hn = socket.gethostname()
            except Exception:
                pass

            with get_connection() as conn:
                cursor = conn.cursor()
                if restrict_ip:
                    # Only resolve our own device
                    cursor.execute("""
                        SELECT ip_address, ipv4_address, mac_address
                        FROM devices
                        WHERE (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                          AND (ip_address = ? OR ipv4_address = ?)
                        LIMIT 1
                    """, (restrict_ip, restrict_ip))
                else:
                    # Include devices whose hostname matches the local machine
                    # name — these are hotspot clients that got the host's name
                    # from Windows' built-in DNS and need re-resolution.
                    params = []
                    host_name_clause = ""
                    if _local_hn:
                        host_name_clause = "OR hostname = ?"
                        params.append(_local_hn)
                    cursor.execute(f"""
                        SELECT ip_address, ipv4_address, mac_address
                        FROM devices
                        WHERE (hostname IS NULL OR hostname = '' OR hostname = ip_address
                               {host_name_clause})
                        LIMIT 20
                    """, params)
                rows = cursor.fetchall()

            for row in rows:
                if self._bg_shutdown.is_set():
                    break
                ip = row["ipv4_address"] or row["ip_address"] or ""
                mac = row["mac_address"] or ""
                if not ip:
                    continue
                try:
                    # Check if resolved from passive cache
                    _is_passive = False
                    with self._lock:
                        passive = self._passive_hostnames.get(ip)
                        if passive and time.monotonic() < passive[1]:
                            _is_passive = True
                    resolved = self.resolve(ip, mac)
                    if resolved and resolved != ip:
                        self._persist_hostname_to_db(ip, mac, resolved,
                                                     from_passive=_is_passive)
                except Exception:
                    pass

        except Exception as e:
            logger.debug("DB hostname resolve error: %s", e)

    @staticmethod
    def _persist_hostname_to_db(ip: str, mac: Optional[str], hostname: str,
                                from_passive: bool = False):
        """Persist a resolved hostname to the devices table.

        Overwrites existing hostname if it is NULL, empty, equal to the IP,
        or equal to the local machine's hostname (hotspot DNS leak cleanup).

        When *from_passive* is True (mDNS/NetBIOS/DHCP/SSDP passive learning),
        the hostname is unconditionally written because passive names are
        self-advertised by the device and therefore the most reliable source.
        """
        try:
            from database.connection import get_connection

            # Detect local hostname so we can overwrite leaked host names
            _local_hn = ""
            try:
                _local_hn = socket.gethostname()
            except Exception:
                pass

            with get_connection() as conn:
                cursor = conn.cursor()
                # Build WHERE clause — only include MAC condition when
                # a real MAC is provided.  Passing mac=None (e.g. from
                # learn_hostname) must NOT match mac_address='' which
                # would update unrelated rows.
                if mac:
                    where = "ip_address = ? OR ipv4_address = ? OR mac_address = ?"
                    where_params = (ip, ip, mac)
                else:
                    where = "ip_address = ? OR ipv4_address = ?"
                    where_params = (ip, ip)

                if from_passive:
                    # Passive names (mDNS, NetBIOS-NS, DHCP, SSDP) are the
                    # most reliable — always overwrite.
                    cursor.execute(f"""
                        UPDATE devices
                        SET hostname = ?
                        WHERE {where}
                    """, (hostname, *where_params))
                elif _local_hn:
                    cursor.execute(f"""
                        UPDATE devices
                        SET hostname = CASE
                                WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address
                                      OR hostname = ?)
                                THEN ? ELSE hostname END
                        WHERE {where}
                    """, (_local_hn, hostname, *where_params))
                else:
                    cursor.execute(f"""
                        UPDATE devices
                        SET hostname = CASE
                                WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                                THEN ? ELSE hostname END
                        WHERE {where}
                    """, (hostname, *where_params))
                conn.commit()

            # Also update the in-memory dashboard state so the SSE device
            # list reflects the hostname immediately (without page reload).
            try:
                from utils.realtime_state import dashboard_state
                dashboard_state.update_device_hostname(ip, hostname)
            except Exception:
                pass
        except Exception:
            pass  # Don't fail the resolution pipeline


# Singleton instance
_resolver = HostnameResolver()

# ── Restrict mode (public_network) ─────────────────────────────────
# When set, the background resolver only resolves the specified IP
# and the mDNS browser is suppressed.  This prevents DNS/mDNS/NetBIOS
# queries to the network when on an untrusted / public WiFi.
_restrict_to_own_ip: Optional[str] = None


def set_restrict_mode(own_ip: Optional[str]) -> None:
    """Restrict background resolution to *own_ip* only.

    Call with ``None`` to lift the restriction (permissive modes).
    Call with the capture interface IP for restrictive modes
    (public_network) so the resolver never probes other devices.
    """
    global _restrict_to_own_ip
    _restrict_to_own_ip = own_ip
    if own_ip:
        logger.info("Hostname resolver restricted to own IP: %s", own_ip)
    else:
        logger.info("Hostname resolver restriction lifted (all devices)")


def resolve_hostname(ip: str, mac: Optional[str] = None) -> str:
    """Module-level convenience function."""
    return _resolver.resolve(ip, mac)


def learn_hostname(ip: str, hostname: str, source: Optional[str] = None) -> None:
    """Module-level convenience: passively learn a hostname from captured traffic."""
    _resolver.learn_hostname(ip, hostname, source=source)


def enqueue_for_resolution(ip: str, mac: Optional[str] = None) -> None:
    """Module-level convenience: enqueue a device for background hostname resolution."""
    _resolver.enqueue_for_resolution(ip, mac)


def get_passive_hostname(ip: str) -> Optional[str]:
    """Return the passively-learned hostname for *ip*, or ``None``.

    Only checks the passive cache (DHCP Option 12, mDNS, NetBIOS-NS,
    SSDP, LLMNR).  Does **not** trigger any active resolution (rDNS,
    NetBIOS query, etc.).  Safe to call from hot paths like ARP
    discovery where blocking DNS lookups would slow the scan and
    return unreliable results (e.g. Windows hotspot rDNS).
    """
    now = time.monotonic()
    with _resolver._lock:
        passive = _resolver._passive_hostnames.get(ip)
    if passive:
        hostname, expiry = passive[0], passive[1]
        if now < expiry:
            return hostname
    return None


def start_background_resolver() -> None:
    """Module-level convenience: start the background resolution thread."""
    _resolver.start_background_resolver()


def start_mdns_browser(periodic: bool = False) -> None:
    """Module-level convenience: start mDNS service browsing.

    Suppressed when restrict mode is active (public_network) because
    mDNS browsing sends multicast queries that probe the network.

    Args:
        periodic: If True, re-browse every 10 minutes (for port_mirror mode).
    """
    if _restrict_to_own_ip:
        logger.info("mDNS browser suppressed — restrict mode active (own IP: %s)",
                     _restrict_to_own_ip)
        return
    _resolver.start_mdns_browser(periodic=periodic)


def close_resolver() -> None:
    """Module-level convenience: shut down the resolver cleanly."""
    _resolver.close()
