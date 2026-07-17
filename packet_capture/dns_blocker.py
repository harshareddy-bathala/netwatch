"""
dns_blocker.py - Admin Client Blocking (DNS sinkhole)
=====================================================

Enforces the ``blocking_rules`` policy: when a client asks for a blocked
domain, NetWatch answers NXDOMAIN before the real reply gets back, so the
site/app never resolves and the client simply sees it as unreachable.

Why this works here
-------------------
In hotspot mode this host *is* the AP/NAT gateway, so every client's DNS
query crosses the interface we already sniff.  We see the query at the same
instant the ICS DNS proxy does, and we are on the LAN side — our forged
reply reaches the client first.  The client accepts the first well-formed
answer matching the query's transaction ID and source port, and ignores the
real one that arrives a few milliseconds later.

Consequences worth knowing
--------------------------
* Nothing persistent is touched — no firewall rules, no hosts file.  Rules
  stop applying the moment capture stops.
* Only clients are affected.  This host's own lookups leave via the WAN
  interface and are never seen here, so a network-wide rule does not block
  the admin's own machine.
* A client using DoH/DoT, or hardcoded IPs, bypasses this.  It is a policy
  control for normal clients, not a security boundary against a hostile one.

Threading
---------
``handle_packet`` runs inside the Scapy ``prn`` callback on the capture
thread, so it does the *match only* and must stay cheap — the common case
(no rules) is a single truthiness check.  Sending is handed to a small
worker thread so a slow socket write can never stall capture or cause drops.
"""

import logging
import queue
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from scapy.all import DNS, DNSQR, IP, UDP, Ether, sendp  # type: ignore[import-untyped]
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without scapy
    DNS = DNSQR = IP = UDP = Ether = sendp = None
    SCAPY_AVAILABLE = False

# Bounded so a client hammering a blocked domain can't grow memory without
# limit; dropping a spoof just means that one lookup resolves normally.
_SEND_QUEUE_SIZE = 500

# Hit counters are flushed on a timer rather than per packet — a blocked
# client retries aggressively and we won't write to SQLite on every retry.
_HIT_FLUSH_SECONDS = 5.0

_NXDOMAIN = 3


def _suffixes(qname: str) -> List[str]:
    """``www.instagram.com`` -> [``www.instagram.com``, ``instagram.com``].

    The public suffix itself (``com``) is dropped: a rule on a bare TLD is
    not something we let the admin create, and testing it wastes a lookup.
    """
    labels = qname.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


class DNSBlocker:
    """Matches DNS queries against blocking rules and forges NXDOMAIN replies."""

    def __init__(self, iface: Optional[str] = None, sender=None):
        self._iface = iface
        # Injected for tests; defaults to Scapy's L2 send.
        self._sendp = sender if sender is not None else sendp
        # domain -> tuple of (rule_id, device_mac or None)
        self._index: Dict[str, Tuple[Tuple[int, Optional[str]], ...]] = {}
        # W5: whole-device blocks (parental pause / quota / schedule) — every
        # lookup from these MACs is sinkholed regardless of domain.
        self._blocked_macs: frozenset = frozenset()
        # Hot-path guard: skip all work when no rules AND no device blocks.
        self._active = False
        self._lock = threading.Lock()
        self._queue: "queue.Queue" = queue.Queue(maxsize=_SEND_QUEUE_SIZE)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._hits: Dict[int, int] = {}
        self._blocked_count = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self.reload()
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._send_loop, name="DNSBlocker", daemon=True,
        )
        self._thread.start()
        logger.info("DNS blocker started on iface=%s", self._iface)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._flush_hits()
        logger.info("DNS blocker stopped (%d lookups blocked)", self._blocked_count)

    def set_interface(self, iface: Optional[str]) -> None:
        """Follow a capture mode switch onto a new interface."""
        self._iface = iface

    # -- rules -------------------------------------------------------------

    def reload(self) -> int:
        """Re-read enabled rules from the DB into the in-memory index."""
        from database.queries.blocking_queries import get_rules

        index: Dict[str, List[Tuple[int, Optional[str]]]] = {}
        for r in get_rules(enabled_only=True):
            domain = (r.get("domain") or "").lower()
            if not domain:
                continue
            mac = (r.get("device_mac") or "").lower() or None
            index.setdefault(domain, []).append((int(r["id"]), mac))

        frozen = {d: tuple(v) for d, v in index.items()}
        with self._lock:
            self._index = frozen
            self._active = bool(frozen) or bool(self._blocked_macs)
        return len(frozen)

    def set_blocked_macs(self, macs) -> None:
        """Replace the set of fully-blocked device MACs (W5 policy enforcer).

        Called periodically with the MACs currently over quota / paused /
        inside a blocked window. Every DNS lookup from these devices is
        sinkholed until the set changes."""
        normalized = frozenset(
            (m or "").lower().replace("-", ":") for m in (macs or []) if m
        )
        with self._lock:
            self._blocked_macs = normalized
            self._active = bool(self._index) or bool(normalized)

    def match(self, qname: str, src_mac: Optional[str]) -> Optional[int]:
        """Return the id of the rule blocking *qname* for *src_mac*, else None.

        Pure and cheap: a rule on ``instagram.com`` also blocks
        ``www.instagram.com``, so we test the name and each parent domain.
        """
        if not qname:
            return None
        with self._lock:
            index = self._index
        if not index:
            return None
        name = qname.rstrip(".").lower()
        mac = (src_mac or "").lower().replace("-", ":")
        for suffix in _suffixes(name):
            entries = index.get(suffix)
            if not entries:
                continue
            for rule_id, rule_mac in entries:
                if rule_mac is None or rule_mac == mac:
                    return rule_id
        return None

    # -- capture-thread hook ----------------------------------------------

    def handle_packet(self, pkt) -> bool:
        """Called from the Scapy prn callback for every captured packet.

        Returns True if the query matched a rule and a forged reply was
        queued.  Must stay cheap: the no-rules case exits on one check.
        """
        if not self._active:
            return False
        try:
            if not pkt.haslayer(DNS):
                return False
            dns = pkt[DNS]
            # qr==0 is a query; we never touch replies.
            if dns.qr != 0 or not dns.qd:
                return False
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", "ignore")
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
            # W5: whole-device block takes precedence over per-domain rules.
            if src_mac and self._blocked_macs:
                if (src_mac or "").lower().replace("-", ":") in self._blocked_macs:
                    self._queue.put_nowait((pkt, -1))   # -1 = device-level block
                    return True
            rule_id = self.match(qname, src_mac)
            if rule_id is None:
                return False
            self._queue.put_nowait((pkt, rule_id))
            return True
        except queue.Full:
            # Under flood we'd rather let a lookup through than stall capture.
            return False
        except Exception:
            # Never let a malformed packet kill the capture callback.
            return False

    # -- sender thread -----------------------------------------------------

    def _send_loop(self) -> None:
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                pkt, rule_id = self._queue.get(timeout=0.5)
            except queue.Empty:
                pkt = None
            if pkt is not None:
                try:
                    self._send_nxdomain(pkt)
                    self._blocked_count += 1
                    self._hits[rule_id] = self._hits.get(rule_id, 0) + 1
                except Exception as exc:
                    logger.debug("DNS blocker send failed: %s", exc)

            if time.time() - last_flush >= _HIT_FLUSH_SECONDS:
                self._flush_hits()
                last_flush = time.time()

    def _send_nxdomain(self, pkt) -> None:
        """Forge the 'this name does not exist' reply back to the client.

        Built at L2 and sent straight onto the hotspot interface: we already
        know the client's MAC, so this skips ARP and routing and shaves the
        milliseconds that decide whether we beat the real answer.
        """
        reply = (
            Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
            / IP(src=pkt[IP].dst, dst=pkt[IP].src)
            / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            / DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, ra=1,
                rcode=_NXDOMAIN,
                qd=pkt[DNS].qd,
            )
        )
        self._sendp(reply, iface=self._iface, verbose=False)

    def _flush_hits(self) -> None:
        if not self._hits:
            return
        counts, self._hits = self._hits, {}
        # -1 is the device-level (parental) block sentinel — not a
        # blocking_rules row, so it has no hit counter to update.
        counts = {rid: c for rid, c in counts.items() if rid and rid > 0}
        if not counts:
            return
        try:
            from database.queries.blocking_queries import record_hits
            record_hits(counts)
        except Exception as exc:
            logger.debug("DNS blocker hit flush failed: %s", exc)

    # -- diagnostics -------------------------------------------------------

    def get_stats(self) -> dict:
        with self._lock:
            rule_count = len(self._index)
        return {
            "active": self._active,
            "domains": rule_count,
            "blocked_lookups": self._blocked_count,
            "interface": self._iface,
        }
