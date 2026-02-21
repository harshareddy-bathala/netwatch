"""
hostname_resolver.py - Device Hostname Resolution
====================================================

Resolves device hostnames using multiple methods:
1. Cache with TTL (instant, bounded size)
2. Reverse DNS lookup (short timeout)
3. MAC vendor lookup (via manuf library)
4. Fallback to "Vendor (last_octet)" format

Thread-safe with a lock around the shared cache.
"""

import socket
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache Configuration
# ---------------------------------------------------------------------------
_CACHE_MAX_SIZE = 1024        # Maximum cached entries
_CACHE_TTL_SECONDS = 300      # 5 minutes
_DNS_TIMEOUT_SECONDS = 1.5    # Per-resolve timeout

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


class HostnameResolver:
    """
    Resolve device hostnames using multiple methods.

    Priority:
    1. TTL-bounded cache (max ``_CACHE_MAX_SIZE`` entries, ``_CACHE_TTL_SECONDS`` TTL)
    2. Reverse DNS (with ``_DNS_TIMEOUT_SECONDS`` timeout)
    3. MAC vendor + last IP octet
    """

    def __init__(self):
        # cache_key -> (hostname, expiry_timestamp)
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="DNS")

    def close(self):
        """Shut down the background DNS executor."""
        self._executor.shutdown(wait=False)

    def resolve(self, ip: str, mac: Optional[str] = None) -> str:
        """
        Resolve hostname for a device.

        Returns a human-readable name like "Apple (114)" or the reverse DNS name.
        Falls back to the IP address if nothing found.
        """
        cache_key = f"{ip}:{mac or ''}"
        now = time.monotonic()

        # 1. Check cache (with TTL)
        with self._lock:
            entry = self._cache.get(cache_key)
            if entry is not None:
                hostname, expiry = entry
                if now < expiry:
                    return hostname
                # Expired — remove stale entry
                del self._cache[cache_key]

        hostname = None

        # 2. Reverse DNS (with timeout)
        hostname = self._reverse_dns(ip)
        if hostname and hostname != ip:
            self._put_cache(cache_key, hostname, now)
            return hostname

        # 3. MAC vendor lookup
        if mac:
            vendor = self._get_vendor(mac)
            if vendor and vendor != "Unknown":
                last_octet = ip.split('.')[-1] if ip else '?'
                hostname = f"{vendor} ({last_octet})"
                self._put_cache(cache_key, hostname, now)
                return hostname

        # 4. Fallback — cache the miss too (avoid repeated DNS lookups)
        self._put_cache(cache_key, ip, now)
        return ip

    def _put_cache(self, key: str, value: str, now: float) -> None:
        """Store a value in the cache, evicting oldest entries if at capacity."""
        with self._lock:
            # Evict ~10% when at capacity
            if len(self._cache) >= _CACHE_MAX_SIZE:
                sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][1])
                for k in sorted_keys[:max(1, _CACHE_MAX_SIZE // 10)]:
                    del self._cache[k]
            self._cache[key] = (value, now + _CACHE_TTL_SECONDS)

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
            return future.result(timeout=_DNS_TIMEOUT_SECONDS)
        except (FuturesTimeout, socket.herror, socket.gaierror,
                socket.timeout, OSError):
            return None

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
                    # asyncio.run() is thread-safe: creates and closes its own loop.
                    # Works correctly from background threads (capture/processor).
                    try:
                        result = asyncio.run(result)
                    except RuntimeError:
                        # Last resort: create a fresh loop manually
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


# Singleton instance
_resolver = HostnameResolver()


def resolve_hostname(ip: str, mac: Optional[str] = None) -> str:
    """Module-level convenience function."""
    return _resolver.resolve(ip, mac)
