"""
ip_org.py - Offline destination IP → owning-organization lookup
================================================================

The fallback name source when a client's DNS is encrypted and its QUIC
SNI is unrecoverable (ECH) or the traffic is a VPN tunnel: even then we
know *which company's servers* a device is talking to, from the
destination IP's owner. "Nothing-Phone → Meta (3.2 MB)" is honest and
useful when the exact site is hidden.

Fully **offline**. Deliberately NOT the online ``packet_capture/geoip.py``
(ip-api.com) — that violates the local-first constraint and is
rate-limited. Sources, in priority order:

1. An offline MaxMind **GeoLite2-ASN** ``.mmdb`` at ``data/GeoLite2-ASN.mmdb``
   if the user supplied one and the ``geoip2`` package is installed
   (neither is required) — full ASN → org coverage.
2. A bundled curated CIDR→org map (``data/ip_org_ranges.json``) covering the
   common consumer services — always present, zero dependencies.

Results are cached; private/loopback IPs return None.
"""

import ipaddress
import json
import logging
import os
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_RANGES_FILE = os.path.join(_DATA_DIR, "ip_org_ranges.json")
_MMDB_FILE = os.path.join(_DATA_DIR, "GeoLite2-ASN.mmdb")

_lock = threading.Lock()
_ranges = None          # list[(ip_network, org)]  sorted longest-prefix-first
_vpn_orgs = set()
_mmdb_reader = "unset"  # None once we've decided there is none
_cache = {}             # ip -> org|None
_CACHE_MAX = 4096


def _load_ranges():
    global _ranges, _vpn_orgs
    if _ranges is not None:
        return
    nets = []
    try:
        with open(_RANGES_FILE, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        for cidr, org in doc.get("ranges", []):
            try:
                nets.append((ipaddress.ip_network(cidr, strict=False), org))
            except ValueError:
                continue
        _vpn_orgs = {o.lower() for o in doc.get("vpn_orgs", [])}
    except (OSError, ValueError) as exc:
        logger.warning("ip_org: could not load ranges (%s) — org lookup limited", exc)
    # Longest prefix first so the most specific allocation wins.
    nets.sort(key=lambda no: no[0].prefixlen, reverse=True)
    _ranges = nets


def _get_mmdb():
    global _mmdb_reader
    if _mmdb_reader != "unset":
        return _mmdb_reader
    reader = None
    try:
        if os.path.exists(_MMDB_FILE):
            import geoip2.database  # optional, user-installed
            reader = geoip2.database.Reader(_MMDB_FILE)
            logger.info("ip_org: using offline GeoLite2-ASN database")
    except Exception as exc:       # missing package / bad file → curated only
        logger.debug("ip_org: no GeoLite2-ASN reader (%s)", exc)
        reader = None
    _mmdb_reader = reader
    return reader


def lookup_org(ip: str) -> Optional[str]:
    """Owning organization for an external IP, or None (private/unknown)."""
    if not ip:
        return None
    with _lock:
        if ip in _cache:
            return _cache[ip]
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_multicast or \
                addr.is_reserved or addr.is_link_local or addr.is_unspecified:
            _store(ip, None)
            return None
    except ValueError:
        _store(ip, None)
        return None

    org = None
    reader = _get_mmdb()
    if reader is not None:
        try:
            org = reader.asn(ip).autonomous_system_organization
        except Exception:
            org = None
    if not org:
        _load_ranges()
        for net, name in _ranges:
            if addr in net:
                org = name
                break
    _store(ip, org)
    return org


def is_vpn_org(org: Optional[str]) -> bool:
    """True if *org* is a known consumer-VPN provider."""
    if not org:
        return False
    _load_ranges()
    o = org.lower()
    return any(v in o for v in _vpn_orgs) or "vpn" in o


def _store(ip: str, org: Optional[str]) -> None:
    with _lock:
        if len(_cache) >= _CACHE_MAX:
            _cache.clear()
        _cache[ip] = org
