"""
sni_ip_learner.py - Learn a blocked app's real server IPs from observed SNI
===========================================================================

Why
---
Resolving a blocked domain ourselves is not enough. ``instagram.com`` resolves
to one address; the Instagram *app* connects to ``i.instagram.com`` and
``scontent.cdninstagram.com``, which resolve to different addresses on a CDN
that rotates them per-client and per-region. Blocking what *our* resolver
returns therefore misses what the *phone* actually talks to — observed live:
the domain rule was armed and the app kept working.

But we already see the truth on the wire. Every TLS/QUIC connection carries an
unencrypted **SNI** naming its destination, and the packet carrying it also
carries the **destination IP**. So instead of guessing addresses, we learn
them: when a connection's SNI belongs to a blocked domain family, we record
that destination IP and hand it to the packet blocker. The app's next
connection to that address is dropped.

Properties
----------
* **Adaptive** — works for any app and any CDN without a hardcoded IP list,
  and follows CDN rotation automatically.
* **Cheap on the hot path** — ``observe()`` returns immediately when nothing is
  blocked (the common case), and match checking is a suffix test over a small
  frozenset.
* **Necessarily reactive** — the connection that *reveals* an IP is not itself
  blocked; blocking begins with the next one. In practice an app opens many
  connections a second, so it stops within seconds rather than instantly.
* **Bounded** — learned IPs are capped and expire, so a long session cannot
  grow memory without limit.
"""

import logging
import threading
import time
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)

# Learned IPs are forgotten after this long without a re-sighting, so a CDN
# address recycled to a different service stops being blocked.
DEFAULT_TTL_SECONDS = 3600

# Hard cap on learned IPs (they feed a WinDivert filter expression).
MAX_LEARNED = 512


class SniIpLearner:
    """Maps blocked domain families → destination IPs observed on the wire."""

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self._ttl = max(1, int(ttl_seconds))
        self._lock = threading.Lock()
        # Suffixes to match SNI against; empty = feature dormant (hot-path fast
        # path returns immediately).
        self._domains: frozenset = frozenset()
        # ip -> (last seen time, matched domain suffix)
        #
        # The matched domain is kept, not just the timestamp, so a learned
        # address can be attributed back to the rule that caused it. Without
        # that, blocking instagram.com on one phone and youtube.com on another
        # would pool every learned IP and each phone would lose both.
        self._learned: Dict[str, tuple] = {}

    # -- configuration -----------------------------------------------------

    def set_blocked_domains(self, domains) -> None:
        """Replace the set of domain suffixes we are learning IPs for."""
        new = frozenset(
            d.strip().lower().rstrip(".")
            for d in (domains or []) if d and d.strip()
        )
        with self._lock:
            if new == self._domains:
                return
            self._domains = new
            if not new:
                self._learned.clear()      # nothing blocked → forget everything
        logger.info("SNI IP learner watching %d domain(s)", len(new))

    @property
    def active(self) -> bool:
        return bool(self._domains)

    # -- hot path ----------------------------------------------------------

    def observe(self, sni: str, dest_ip: Optional[str]) -> bool:
        """Record *dest_ip* if *sni* belongs to a blocked domain family.

        Called from the capture path for every parsed SNI, so the no-rules case
        must cost almost nothing. Returns True when a NEW ip was learned.
        """
        if not self._domains:                 # fast path: nothing is blocked
            return False
        if not sni or not dest_ip or ":" in dest_ip:   # IPv4 filter only
            return False
        name = sni.strip().lower().rstrip(".")
        matched = self._matched_domain(name)
        if matched is None:
            return False
        now = time.time()
        with self._lock:
            is_new = dest_ip not in self._learned
            self._learned[dest_ip] = (now, matched)
            if len(self._learned) > MAX_LEARNED:
                self._prune_locked(now)
        if is_new:
            logger.info("Blocked-domain %s observed at %s — blocking that IP",
                        name, dest_ip)
        return is_new

    def _matched_domain(self, name: str) -> Optional[str]:
        """Return the blocked suffix *name* belongs to, or None."""
        for d in self._domains:
            if name == d or name.endswith("." + d):
                return d
        return None

    def _matches(self, name: str) -> bool:
        return self._matched_domain(name) is not None

    # -- readback ----------------------------------------------------------

    def learned_ips(self, domains=None) -> Set[str]:
        """IPs to block, dropping entries past their TTL.

        With *domains*, only addresses learned for those suffixes are returned
        — that is what lets one rule's addresses be enforced against one device
        without leaking into another rule's scope. Without it, every learned
        address is returned (the network-wide case).
        """
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            if domains is None:
                return set(self._learned)
            wanted = {str(d).strip().lower().rstrip(".") for d in domains if d}
            return {ip for ip, (_t, dom) in self._learned.items()
                    if dom in wanted}

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self._ttl
        self._learned = {ip: v for ip, v in self._learned.items()
                         if v[0] > cutoff}
        if len(self._learned) > MAX_LEARNED:
            # Keep the most recently seen.
            newest = sorted(self._learned.items(), key=lambda kv: kv[1][0],
                            reverse=True)[:MAX_LEARNED]
            self._learned = dict(newest)


# Process-wide instance: the capture path writes to it, the policy enforcer
# reads from it. A singleton keeps the hot path free of plumbing.
sni_ip_learner = SniIpLearner()
