"""
domain_blocklist.py - Resolve blocked domains to IPs for packet-level blocking
==============================================================================

Why this exists
---------------
``dns_blocker`` enforces domain rules by forging NXDOMAIN for a client's
plaintext DNS lookup. That stops nothing on a modern phone: Chrome/Brave and
the Instagram/YouTube apps use **DoH/DoT** (the lookup never reaches us) or
reconnect to **cached IPs over QUIC**. Observed live: blocking instagram.com
left the Instagram app fully working.

So we also block at the packet level. We resolve each blocked domain to its
current server IPs and hand them to :mod:`traffic_blocker`, whose WinDivert
filter already drops any packet to/from a listed IP — independent of DNS,
independent of QUIC.

Honest limitations (say these out loud rather than pretending):
* **CDN IPs rotate.** We re-resolve on a TTL so the set stays current, but a
  brand-new edge IP is reachable until the next refresh.
* **Shared infrastructure over-blocks.** Big providers put many services on
  one IP range, so blocking one Meta domain can affect other Meta services.
* **Network-wide.** An IP block applies to every client (and this host), so a
  per-device domain rule is enforced more broadly than its scope implies.

Resolution is pure-stdlib (``socket``) and fully offline-safe: failures return
an empty set, never an exception, so enforcement degrades instead of breaking.
"""

import logging
import socket
import threading
import time
from typing import Dict, Iterable, Set, Tuple

logger = logging.getLogger(__name__)

# Re-resolve a domain at most this often. CDN records commonly carry TTLs of
# 30-300s; 300 keeps the set fresh without hammering the resolver each sweep.
DEFAULT_TTL_SECONDS = 300

# Hard ceiling on IPs pushed into the WinDivert filter. The filter is a single
# expression string, so an unbounded set would build a pathological filter and
# slow the kernel hot path. 256 covers real domains many times over.
MAX_IPS = 256


def resolve_domain_ips(domain: str) -> Set[str]:
    """Return current IPv4 addresses for *domain* (and its ``www.`` form).

    IPv4 only: the WinDivert filter built by ``traffic_blocker`` matches
    ``ip.SrcAddr``/``ip.DstAddr``, which are v4 fields. Never raises.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return set()
    names = {d} if d.startswith("www.") else {d, f"www.{d}"}
    ips: Set[str] = set()
    for name in names:
        try:
            for info in socket.getaddrinfo(name, None, socket.AF_INET):
                addr = info[4][0]
                if addr and ":" not in addr:
                    ips.add(addr)
        except (socket.gaierror, OSError, UnicodeError):
            continue          # unresolvable / offline — just contributes nothing
    return ips


class DomainBlocklist:
    """Caches domain → IP resolutions behind a TTL.

    ``ips_for(domains)`` is called on every policy sweep, so it must be cheap:
    only domains whose entry has expired are re-resolved.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 resolver=resolve_domain_ips):
        self._ttl = max(1, int(ttl_seconds))
        self._resolve = resolver
        self._lock = threading.Lock()
        # domain -> (expires_at, ips)
        self._cache: Dict[str, Tuple[float, Set[str]]] = {}

    @staticmethod
    def expand(domains: Iterable[str]) -> Set[str]:
        """Grow each blocked domain into its whole app family.

        Blocking ``instagram.com`` must also cover ``cdninstagram.com`` — the
        app never contacts the headline domain, so resolving it alone blocks
        nothing. Unknown domains expand to themselves.
        """
        out: Set[str] = set()
        for d in (domains or []):
            name = (d or "").strip().lower().rstrip(".")
            if not name:
                continue
            try:
                from intelligence.app_catalog import domain_family
                out |= domain_family(name)
            except Exception:
                out.add(name)
        return out

    def ips_for(self, domains: Iterable[str], now: float = None) -> Set[str]:
        """Union of current IPs for *domains* (expanded to app families),
        re-resolving expired entries."""
        now = time.time() if now is None else now
        wanted = self.expand(domains)
        wanted.discard("")

        out: Set[str] = set()
        for d in wanted:
            with self._lock:
                entry = self._cache.get(d)
            if entry is not None and entry[0] > now:
                out |= entry[1]
                continue
            # Resolve outside the lock — getaddrinfo blocks on the network.
            try:
                ips = self._resolve(d)
            except Exception as exc:        # a resolver must never break policy
                logger.debug("resolve %s failed: %s", d, exc)
                ips = set()
            # A failed refresh keeps the previous IPs rather than unblocking the
            # domain: transient DNS failure must not silently open access.
            if not ips and entry is not None:
                ips = entry[1]
            with self._lock:
                self._cache[d] = (now + self._ttl, ips)
                # Drop entries for domains no longer blocked.
                for stale in [k for k in self._cache if k not in wanted]:
                    self._cache.pop(stale, None)
            out |= ips

        if len(out) > MAX_IPS:
            logger.warning("Domain blocklist resolved %d IPs; capping at %d",
                           len(out), MAX_IPS)
            out = set(sorted(out)[:MAX_IPS])
        return out
