"""
geoip.py - GeoIP Lookup for External IP Addresses
=====================================================

Uses the free ``ip-api.com`` batch endpoint (no API key needed, 45 req/min)
to resolve country / city / ISP for external (non-private) IPs.

A TTL-bounded in-memory cache avoids repeated queries.

Usage::

    from packet_capture.geoip import lookup_ip, lookup_batch

    info = lookup_ip("8.8.8.8")
    # {'ip': '8.8.8.8', 'country': 'US', 'city': 'Mountain View', 'isp': 'Google LLC', ...}
"""

import logging
import threading
import time
from typing import Optional, Dict, List

from utils.network_utils import is_private_ip

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache config
# ---------------------------------------------------------------------------
_CACHE_MAX = 2048
_CACHE_TTL = 3600  # 1 hour

_cache: Dict[str, tuple] = {}  # ip -> (info_dict, expiry)
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Private-IP fast-reject (delegates to shared utility)
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    """Quick check – also treats empty/None as 'private' (skip lookup)."""
    if not ip:
        return True
    return is_private_ip(ip)


# ---------------------------------------------------------------------------
# Single lookup
# ---------------------------------------------------------------------------

def lookup_ip(ip: str) -> Optional[Dict]:
    """
    Return GeoIP information for a single external IP.

    Returns ``None`` for private IPs or on error.
    """
    if _is_private(ip):
        return None

    now = time.monotonic()

    # Cache check
    with _lock:
        entry = _cache.get(ip)
        if entry and now < entry[1]:
            return entry[0]

    # HTTP request to free API
    try:
        import requests
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,lat,lon"},
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                info = {
                    "ip": ip,
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                }
                _put_cache(ip, info, now)
                return info
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)

    # Cache the miss
    _put_cache(ip, None, now)
    return None


# ---------------------------------------------------------------------------
# Batch lookup (up to 100 IPs per call)
# ---------------------------------------------------------------------------

def lookup_batch(ips: List[str]) -> Dict[str, Optional[Dict]]:
    """
    Look up multiple IPs in one call.

    Returns a dict mapping each IP to its GeoIP info (or ``None``).
    """
    results: Dict[str, Optional[Dict]] = {}
    to_query: List[str] = []
    now = time.monotonic()

    for ip in ips:
        if _is_private(ip):
            results[ip] = None
            continue
        with _lock:
            entry = _cache.get(ip)
            if entry and now < entry[1]:
                results[ip] = entry[0]
                continue
        to_query.append(ip)

    if not to_query:
        return results

    # ip-api batch endpoint (max 100)
    try:
        import requests
        batch = to_query[:100]
        payload = [{"query": ip, "fields": "status,query,country,countryCode,regionName,city,isp,org,lat,lon"}
                   for ip in batch]
        resp = requests.post("http://ip-api.com/batch", json=payload, timeout=5)
        if resp.status_code == 200:
            for item in resp.json():
                ip = item.get("query", "")
                if item.get("status") == "success":
                    info = {
                        "ip": ip,
                        "country": item.get("country", ""),
                        "country_code": item.get("countryCode", ""),
                        "region": item.get("regionName", ""),
                        "city": item.get("city", ""),
                        "isp": item.get("isp", ""),
                        "org": item.get("org", ""),
                        "lat": item.get("lat"),
                        "lon": item.get("lon"),
                    }
                    _put_cache(ip, info, now)
                    results[ip] = info
                else:
                    _put_cache(ip, None, now)
                    results[ip] = None
    except Exception as exc:
        logger.warning("GeoIP batch lookup failed: %s", exc)

    # Fill any remaining with None
    for ip in to_query:
        if ip not in results:
            results[ip] = None

    return results


# ---------------------------------------------------------------------------
# Internal cache helpers
# ---------------------------------------------------------------------------

def _put_cache(ip: str, info: Optional[Dict], now: float) -> None:
    with _lock:
        if len(_cache) >= _CACHE_MAX:
            # Evict oldest 10%
            sorted_keys = sorted(_cache, key=lambda k: _cache[k][1])
            for k in sorted_keys[:max(1, _CACHE_MAX // 10)]:
                del _cache[k]
        _cache[ip] = (info, now + _CACHE_TTL)


def clear_cache() -> None:
    """Clear the GeoIP cache."""
    with _lock:
        _cache.clear()
