"""
traffic_blocker.py - Real per-client enforcement (WinDivert packet drop)
=========================================================================

The DNS sinkhole (``dns_blocker.py``) only stops *new plaintext DNS
resolutions*; a phone using DoH/DoT or cached IPs / QUIC sails past it, so a
"paused" device still had internet. This blocker actually drops the client's
**forwarded packets** at the kernel via WinDivert, so pause/quota/bedtime
really cut the device off regardless of DNS.

Enforcement ladder (graceful degradation — NetWatch pattern):
  1. **WinDivert** (``pydivert``) — kernel packet drop. Strongest.
  2. **ARP blackhole** (scapy) — poison the client's gateway ARP so its
     traffic has nowhere to go. Works with no driver.
  3. **DNS sinkhole** — the existing fallback (weakest; wired separately).

Only the enforcement I/O is optional; the blocked-set management and the
WinDivert filter construction are pure and unit-tested. The blocked IP set is
pushed by the ``PolicyEnforcer`` (which resolves blocked MACs → current IPs).
"""

import logging
import threading
import time
from typing import Optional, Set

logger = logging.getLogger(__name__)

try:
    import pydivert          # Windows-only; optional
    _PYDIVERT_OK = True
except Exception:            # ImportError or missing driver at import
    pydivert = None
    _PYDIVERT_OK = False


# Ceiling on filter terms. The WinDivert filter is a single expression string
# compiled by the driver, so an unbounded one is both slow and liable to be
# rejected outright. Truncation is logged rather than silent: an enforcement
# gap the operator cannot see is worse than one they can.
MAX_FILTER_TERMS = 256


def _v4(addrs) -> list:
    """Sorted IPv4-only addresses — the filter matches ip.SrcAddr/ip.DstAddr,
    which are v4 fields."""
    return sorted({a for a in (addrs or []) if a and ":" not in str(a)})


def build_windivert_filter(device_ips: Set[str] = None,
                           pairs=None,
                           server_ips: Set[str] = None) -> Optional[str]:
    """Build the kernel drop filter, or None when nothing is blocked.

    Three deliberately different shapes, because "blocked" means three
    different things and collapsing them is what made blocking collateral:

    ``device_ips``
        Whole-device blocks — pause, quota, bedtime. Every packet to or from
        that client is dropped, which is exactly the intent.
    ``pairs`` — ``(client_ip, server_ip)``
        A domain blocked *for one device*. Only that client's conversation
        with that server dies; the same site keeps working for everyone else,
        including this host.
    ``server_ips``
        A domain blocked network-wide. Everyone loses it, on purpose.

    Previously every case was flattened into bare server-IP terms, so a
    per-device rule silently cut the site off for every other client *and* for
    the machine running NetWatch — while the UI implied per-device scope.
    """
    terms = []
    for ip in _v4(device_ips):
        terms.append(f"ip.SrcAddr == {ip} or ip.DstAddr == {ip}")
    for ip in _v4(server_ips):
        terms.append(f"ip.SrcAddr == {ip} or ip.DstAddr == {ip}")
    for client, server in sorted(pairs or []):
        if not client or not server or ":" in str(client) or ":" in str(server):
            continue        # IPv4 filter only
        terms.append(
            f"(ip.SrcAddr == {client} and ip.DstAddr == {server}) or "
            f"(ip.SrcAddr == {server} and ip.DstAddr == {client})"
        )

    if not terms:
        return None
    if len(terms) > MAX_FILTER_TERMS:
        logger.warning(
            "Blocking filter has %d terms; enforcing the first %d. Some "
            "blocked addresses are NOT being dropped.",
            len(terms), MAX_FILTER_TERMS,
        )
        terms = terms[:MAX_FILTER_TERMS]
    return "ip and (" + " or ".join(terms) + ")"


# Re-opening the WinDivert handle takes the kernel filter down and back up, so
# every re-arm is a brief hole in enforcement and a burst of driver work. The
# SNI learner discovers a blocked app's CDN addresses continuously, which made
# the 5s policy sweep re-arm on almost every pass — sustained handle churn on
# the live NAT path. Growth is therefore batched: a *newly blocked* IP still
# arms immediately (blocking must feel instant), but merely *adding* addresses
# to an already-armed block waits for this interval.
DEFAULT_REARM_INTERVAL_SECONDS = 30.0


class TrafficBlocker:
    """Drops forwarded traffic for a dynamic set of blocked client IPs."""

    def __init__(self, arp_blackhole=None,
                 rearm_interval: float = DEFAULT_REARM_INTERVAL_SECONDS,
                 clock=time.monotonic):
        self._lock = threading.Lock()
        # Whole-device blocks (pause / quota / bedtime): drop everything.
        self._blocked: frozenset = frozenset()
        # Per-device domain blocks: (client_ip, server_ip) conversations only.
        self._pairs: frozenset = frozenset()
        # Network-wide domain blocks: drop the server for everyone.
        self._server_ips: frozenset = frozenset()
        self._thread: Optional[threading.Thread] = None
        self._handle = None
        self._stop = threading.Event()
        self._mode = "off"          # off | windivert | arp | unavailable
        # Injected ARP-blackhole callable(ips) for the no-driver fallback.
        self._arp_blackhole = arp_blackhole
        # Re-arm debounce. Injectable clock keeps the timing testable.
        self._rearm_interval = max(0.0, float(rearm_interval))
        self._clock = clock
        self._last_rearm = 0.0
        self._armed_filter: Optional[str] = None

    # -- public API --------------------------------------------------------

    def set_blocked_ips(self, ips) -> None:
        """Replace the blocked-IP set; (re)arm enforcement to match.

        Only re-arms when the *filter* actually changes, and defers pure
        additions to an existing block until the debounce interval has passed.
        Removals and the first IP of a new block always apply at once — being
        slow to unblock, or slow to block at all, is a correctness problem;
        being slow to widen an existing block is not.
        """
        self.set_policy(device_ips=ips)

    def set_policy(self, device_ips=None, pairs=None, server_ips=None) -> None:
        """Replace the whole enforcement policy; (re)arm to match.

        Only re-arms when the *filter* actually changes, and defers pure
        additions to an existing block until the debounce interval has passed.
        Removals and the first entry of a new block always apply at once —
        being slow to unblock, or slow to block at all, is a correctness
        problem; being slow to widen an existing block is not.
        """
        new_dev = frozenset(str(i) for i in (device_ips or []) if i)
        new_pairs = frozenset(
            (str(c), str(s)) for c, s in (pairs or []) if c and s
        )
        new_srv = frozenset(str(i) for i in (server_ips or []) if i)

        with self._lock:
            if (new_dev, new_pairs, new_srv) == (
                    self._blocked, self._pairs, self._server_ips):
                return
            previous = self._identity_locked()
            self._blocked, self._pairs, self._server_ips = (
                new_dev, new_pairs, new_srv)
            if not self._should_rearm_now(previous, self._identity_locked()):
                return
            self._last_rearm = self._clock()
        self._rearm()

    def _identity_locked(self) -> frozenset:
        """Flat set of everything currently blocked, for change comparison.

        Caller must hold ``self._lock``.
        """
        return frozenset(self._blocked) | frozenset(self._pairs) | frozenset(
            self._server_ips)

    def _current_filter_locked(self) -> Optional[str]:
        """Caller must hold ``self._lock``."""
        return build_windivert_filter(
            self._blocked, self._pairs, self._server_ips)

    def _should_rearm_now(self, previous: frozenset, new: frozenset) -> bool:
        """Decide whether this change warrants re-opening the handle.

        Caller must hold ``self._lock``.
        """
        if not new or not previous:
            return True                      # first block, or full release
        if previous - new:
            return True                      # something was unblocked
        if self._rearm_interval <= 0:
            return True
        return (self._clock() - self._last_rearm) >= self._rearm_interval

    def flush_pending(self) -> bool:
        """Apply a deferred widening of the blocked set, if one is due.

        Called from the policy sweep so IPs learned between re-arms are not
        stranded until the next unrelated change. Returns True if it re-armed.
        """
        with self._lock:
            if not self._identity_locked():
                return False
            if self._current_filter_locked() == self._armed_filter:
                return False
            if (self._clock() - self._last_rearm) < self._rearm_interval:
                return False
            self._last_rearm = self._clock()
        self._rearm()
        return True

    def get_status(self) -> dict:
        return {
            "mode": self._mode,
            "blocked_ips": sorted(self._blocked),
            "blocked_pairs": sorted(self._pairs),
            "blocked_servers": sorted(self._server_ips),
            "windivert_available": _PYDIVERT_OK,
        }

    def stop(self) -> None:
        self._teardown()
        with self._lock:
            # Forget what was armed, so a restart re-opens the handle instead
            # of concluding the (now closed) filter is still in force.
            self._armed_filter = None

    # -- enforcement -------------------------------------------------------

    def _rearm(self) -> None:
        with self._lock:
            filt = self._current_filter_locked()
            anything_blocked = bool(self._identity_locked())
            # The ARP fallback can only blackhole a whole device — it has no
            # way to express "this client, but only towards that server".
            arp_ips = set(self._blocked)
            summary = (len(self._blocked), len(self._pairs),
                       len(self._server_ips))
            if filt == self._armed_filter and self._thread and self._thread.is_alive():
                return          # already enforcing exactly this — leave it alone
            self._armed_filter = filt
        self._teardown()
        if not anything_blocked:
            self._mode = "off"
            return
        if _PYDIVERT_OK and filt:
            self._start_windivert(filt, summary)
        elif self._arp_blackhole is not None and arp_ips:
            try:
                self._arp_blackhole(arp_ips)
                self._mode = "arp"
            except Exception as exc:
                logger.warning("ARP blackhole failed: %s", exc)
                self._mode = "unavailable"
        else:
            # No kernel driver and no ARP fallback wired — DNS sinkhole (set
            # elsewhere) is the only enforcement. Say so honestly via status.
            self._mode = "unavailable"

    def _start_windivert(self, filt: str, summary=(0, 0, 0)) -> None:
        self._stop.clear()
        # Commit the mode synchronously: callers (and get_status) must see
        # "windivert" as soon as _rearm returns, not race the worker thread's
        # first line. If the driver then fails to open (no admin/driver), the
        # worker downgrades this to "unavailable" below.
        self._mode = "windivert"

        def _run():
            try:
                handle = pydivert.WinDivert(filt)
                handle.open()
                self._handle = handle
                logger.info(
                    "TrafficBlocker: WinDivert active — %d device block(s), "
                    "%d per-device domain pair(s), %d network-wide server(s)",
                    *summary,
                )
                while not self._stop.is_set():
                    pkt = handle.recv()      # removes packet from the stack
                    # Never send() it back → dropped. (Loop exits when the
                    # handle is closed from _teardown, which raises here.)
                    del pkt
            except Exception as exc:
                if not self._stop.is_set():
                    # Opening/using the driver failed (commonly: not elevated,
                    # or WinDivert.sys absent) — report honestly rather than
                    # claiming active kernel enforcement.
                    self._mode = "unavailable"
                    logger.warning("TrafficBlocker WinDivert loop ended: %s", exc)
            finally:
                try:
                    if self._handle:
                        self._handle.close()
                except Exception:
                    pass
                self._handle = None

        self._thread = threading.Thread(target=_run, name="TrafficBlocker", daemon=True)
        self._thread.start()

    def _teardown(self) -> None:
        self._stop.set()
        h = self._handle
        if h is not None:
            try:
                h.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        self._handle = None
