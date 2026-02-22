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
_DNS_TIMEOUT_SECONDS = 1.5          # Per-resolve timeout

# NetBIOS rate limiting (increased from 3 → 8 for better concurrency)
_NBTSTAT_MAX_PENDING = 8
_nbtstat_pending = 0
_nbtstat_lock = threading.Lock()

# Background resolution interval
_BG_RESOLVE_INTERVAL = 10  # seconds

IS_WINDOWS = sys.platform == "win32"

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
        # Passive hostname store: ip -> (hostname, expiry_timestamp)
        self._passive_hostnames: Dict[str, Tuple[str, float]] = {}
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

    def start_mdns_browser(self):
        """
        Start mDNS service browsing for common service types to
        proactively discover named devices on the network.
        """
        if not _zeroconf_available:
            logger.debug("zeroconf not available — skipping mDNS browser startup")
            return

        def _browse():
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
                                        self._resolver.learn_hostname(addr, server)
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

        t = threading.Thread(target=_browse, name="mDNS-Browse", daemon=True)
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

    def learn_hostname(self, ip: str, hostname: str) -> None:
        """
        Passively learn a hostname from captured network traffic
        (mDNS responses, NetBIOS-NS, DHCP, DNS answers, SSDP, etc.).

        This is the most reliable source since the device itself
        advertises its name. Uses a longer TTL (1 hour) than active
        resolution (5 minutes).
        """
        if not ip or not hostname:
            return
        # Ignore bare IPs or boilerplate
        if hostname == ip or hostname.lower() in ("unknown", "n/a", ""):
            return
        # Filter out IPv6 link-local addresses being used as hostnames
        if hostname.startswith("fe80::") or hostname.startswith("::"):
            return
        with self._lock:
            now = time.monotonic()
            self._passive_hostnames[ip] = (hostname, now + _PASSIVE_CACHE_TTL_SECONDS)
            # Also update the active TTL cache immediately so subsequent lookups hit instantly
            cache_key_prefix = f"{ip}:"
            for key in list(self._cache.keys()):
                if key.startswith(cache_key_prefix):
                    self._cache[key] = (hostname, now + _PASSIVE_CACHE_TTL_SECONDS)

    def resolve(self, ip: str, mac: Optional[str] = None) -> str:
        """
        Resolve hostname for a device.

        Returns a human-readable name like "DESKTOP-ABC" or "Apple (114)"
        or the reverse DNS name.  Falls back to the IP address if nothing found.
        """
        # Fast-path: if the IP is our own machine, return the local hostname
        # immediately without DNS lookup.
        try:
            local_hostname = socket.gethostname()
            local_ip = socket.gethostbyname(local_hostname)
            if ip == local_ip:
                return local_hostname
        except (socket.error, OSError):
            pass

        cache_key = f"{ip}:{mac or ''}"
        now = time.monotonic()

        # 1. Check passive hostname cache FIRST (most reliable, longer TTL)
        with self._lock:
            passive = self._passive_hostnames.get(ip)
        if passive:
            hostname, expiry = passive
            if now < expiry:
                # Also update active cache
                self._put_cache(cache_key, hostname, now, ttl=_PASSIVE_CACHE_TTL_SECONDS)
                return hostname
            else:
                # Expired passive entry — remove it
                with self._lock:
                    self._passive_hostnames.pop(ip, None)

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

        Runs every _BG_RESOLVE_INTERVAL seconds. Persists resolved names
        to DB immediately so subsequent API queries see them.
        """
        logger.info("Background hostname resolution loop started")
        while not self._bg_shutdown.wait(timeout=_BG_RESOLVE_INTERVAL):
            try:
                self._process_resolution_queue()
                self._resolve_null_hostnames_in_db()
            except Exception as e:
                logger.debug("Background resolve error: %s", e)

    def _process_resolution_queue(self):
        """Process devices enqueued for background resolution."""
        batch = []
        with self._queue_lock:
            while self._resolve_queue and len(batch) < 20:
                item = self._resolve_queue.popleft()
                key = f"{item[0]}:{item[1] or ''}"
                self._resolve_queue_set.discard(key)
                batch.append(item)

        for ip, mac in batch:
            try:
                resolved = self.resolve(ip, mac)
                if resolved and resolved != ip:
                    self._persist_hostname_to_db(ip, mac, resolved)
            except Exception:
                pass

    def _resolve_null_hostnames_in_db(self):
        """
        Find devices in the DB with hostname IS NULL and attempt resolution.
        This runs in the background, NOT in the API path.
        """
        try:
            from database.connection import get_connection
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ip_address, ipv4_address, mac_address
                    FROM devices
                    WHERE (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                    LIMIT 20
                """)
                rows = cursor.fetchall()

            for row in rows:
                if self._bg_shutdown.is_set():
                    break
                ip = row["ipv4_address"] or row["ip_address"] or ""
                mac = row["mac_address"] or ""
                if not ip:
                    continue
                try:
                    resolved = self.resolve(ip, mac)
                    if resolved and resolved != ip:
                        self._persist_hostname_to_db(ip, mac, resolved)
                except Exception:
                    pass

        except Exception as e:
            logger.debug("DB hostname resolve error: %s", e)

    @staticmethod
    def _persist_hostname_to_db(ip: str, mac: Optional[str], hostname: str):
        """Persist a resolved hostname to the devices table."""
        try:
            from database.connection import get_connection
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE devices
                    SET hostname = CASE
                            WHEN (hostname IS NULL OR hostname = '' OR hostname = ip_address)
                            THEN ? ELSE hostname END
                    WHERE ip_address = ? OR ipv4_address = ? OR mac_address = ?
                """, (hostname, ip, ip, mac or ""))
                conn.commit()
        except Exception:
            pass  # Don't fail the resolution pipeline


# Singleton instance
_resolver = HostnameResolver()


def resolve_hostname(ip: str, mac: Optional[str] = None) -> str:
    """Module-level convenience function."""
    return _resolver.resolve(ip, mac)


def learn_hostname(ip: str, hostname: str) -> None:
    """Module-level convenience: passively learn a hostname from captured traffic."""
    _resolver.learn_hostname(ip, hostname)


def enqueue_for_resolution(ip: str, mac: Optional[str] = None) -> None:
    """Module-level convenience: enqueue a device for background hostname resolution."""
    _resolver.enqueue_for_resolution(ip, mac)


def start_background_resolver() -> None:
    """Module-level convenience: start the background resolution thread."""
    _resolver.start_background_resolver()


def start_mdns_browser() -> None:
    """Module-level convenience: start mDNS service browsing."""
    _resolver.start_mdns_browser()


def close_resolver() -> None:
    """Module-level convenience: shut down the resolver cleanly."""
    _resolver.close()
