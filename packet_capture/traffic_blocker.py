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
from typing import Optional, Set

logger = logging.getLogger(__name__)

try:
    import pydivert          # Windows-only; optional
    _PYDIVERT_OK = True
except Exception:            # ImportError or missing driver at import
    pydivert = None
    _PYDIVERT_OK = False


def build_windivert_filter(ips: Set[str]) -> Optional[str]:
    """WinDivert filter matching any packet to/from a blocked IPv4, or None
    when the set is empty (→ don't open a handle, zero overhead)."""
    v4 = sorted(i for i in ips if i and ":" not in i)
    if not v4:
        return None
    terms = [f"ip.SrcAddr == {i} or ip.DstAddr == {i}" for i in v4]
    return "ip and (" + " or ".join(terms) + ")"


class TrafficBlocker:
    """Drops forwarded traffic for a dynamic set of blocked client IPs."""

    def __init__(self, arp_blackhole=None):
        self._lock = threading.Lock()
        self._blocked: frozenset = frozenset()
        self._thread: Optional[threading.Thread] = None
        self._handle = None
        self._stop = threading.Event()
        self._mode = "off"          # off | windivert | arp | unavailable
        # Injected ARP-blackhole callable(ips) for the no-driver fallback.
        self._arp_blackhole = arp_blackhole

    # -- public API --------------------------------------------------------

    def set_blocked_ips(self, ips) -> None:
        """Replace the blocked-IP set; (re)arm enforcement to match."""
        new = frozenset(str(i) for i in (ips or []) if i)
        with self._lock:
            if new == self._blocked:
                return
            self._blocked = new
        self._rearm()

    def get_status(self) -> dict:
        return {
            "mode": self._mode,
            "blocked_ips": sorted(self._blocked),
            "windivert_available": _PYDIVERT_OK,
        }

    def stop(self) -> None:
        self._teardown()

    # -- enforcement -------------------------------------------------------

    def _rearm(self) -> None:
        self._teardown()
        with self._lock:
            ips = set(self._blocked)
        if not ips:
            self._mode = "off"
            return
        if _PYDIVERT_OK and build_windivert_filter(ips):
            self._start_windivert(ips)
        elif self._arp_blackhole is not None:
            try:
                self._arp_blackhole(ips)
                self._mode = "arp"
            except Exception as exc:
                logger.warning("ARP blackhole failed: %s", exc)
                self._mode = "unavailable"
        else:
            # No kernel driver and no ARP fallback wired — DNS sinkhole (set
            # elsewhere) is the only enforcement. Say so honestly via status.
            self._mode = "unavailable"

    def _start_windivert(self, ips: Set[str]) -> None:
        filt = build_windivert_filter(ips)
        self._stop.clear()

        def _run():
            try:
                handle = pydivert.WinDivert(filt)
                handle.open()
                self._handle = handle
                self._mode = "windivert"
                logger.info("TrafficBlocker: WinDivert dropping %d client IP(s)", len(ips))
                while not self._stop.is_set():
                    pkt = handle.recv()      # removes packet from the stack
                    # Never send() it back → dropped. (Loop exits when the
                    # handle is closed from _teardown, which raises here.)
                    del pkt
            except Exception as exc:
                if not self._stop.is_set():
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
