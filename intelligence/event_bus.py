"""
event_bus.py - In-Process Event Bus (Phase 0)
==============================================

A minimal, thread-safe publish/subscribe bus that turns NetWatch's
point-to-point data flow into a subscribable event stream.  Every AI
feature (digital twin, behavior profiles, detectors, investigations)
consumes events from here instead of polling SQLite.

Design constraints (in priority order):

1. **Publishers never block.**  ``publish()`` is called from the capture
   / writer hot path.  If a subscriber's queue is full, the *oldest*
   event in that queue is dropped and a per-subscription counter is
   incremented.  Slow consumers can never stall capture.
2. **No project imports.**  Like ``orchestration.state``, this module
   sits at the bottom of the dependency graph so anything may import it.
3. **Bounded memory.**  Every subscription has a fixed-size queue.

Topics are dotted strings; subscriptions match exact topics or a
``"prefix.*"`` wildcard (single trailing star only).

Standard topics (Phase 0):

* ``packet.batch``   — payload: list of normalized packet dicts
* ``flow.completed`` — payload: flow record dict
* ``dns.query``      — payload: {timestamp, source_ip, source_mac, qname, qtype}
* ``mode.changed``   — payload: {old_mode, new_mode, timestamp}
* ``device.seen``    — payload: device dict (reserved; wired in Phase 1)

Usage::

    from intelligence.event_bus import event_bus

    # Consumer (own thread):
    sub = event_bus.subscribe(["packet.batch", "mode.*"], name="flow-normalizer")
    while running:
        event = sub.get(timeout=0.5)
        if event is not None:
            handle(event)

    # Producer (hot path):
    event_bus.publish("packet.batch", batch)
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default per-subscription queue capacity (events, not packets)
DEFAULT_SUBSCRIPTION_CAPACITY = 1000


@dataclass(frozen=True)
class Event:
    """A single event on the bus."""
    topic: str
    payload: Any
    timestamp: float = field(default_factory=time.time)


class Subscription:
    """A bounded mailbox for one consumer.

    Obtained via :meth:`EventBus.subscribe`.  Consumers call :meth:`get`
    (blocking with timeout) or :meth:`drain` (non-blocking batch read).
    """

    def __init__(self, name: str, topics: List[str], capacity: int):
        self.name = name
        self._topics = list(topics)
        self._queue: "queue.Queue[Event]" = queue.Queue(maxsize=capacity)
        self._closed = False
        self.dropped = 0          # events dropped because this queue was full
        self.delivered = 0

    # -- matching ------------------------------------------------------
    def matches(self, topic: str) -> bool:
        for pattern in self._topics:
            if pattern == topic:
                return True
            if pattern.endswith(".*") and topic.startswith(pattern[:-1]):
                return True
            if pattern == "*":
                return True
        return False

    # -- producer side (called by the bus) ------------------------------
    def _offer(self, event: Event) -> None:
        """Enqueue without ever blocking; drop-oldest on overflow."""
        if self._closed:
            return
        try:
            self._queue.put_nowait(event)
            self.delivered += 1
        except queue.Full:
            # Drop the oldest event to make room for the newest.
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            self.dropped += 1
            try:
                self._queue.put_nowait(event)
                self.delivered += 1
            except queue.Full:
                # Racing producers filled it again — drop the new event too.
                self.dropped += 1
            if self.dropped % 1000 == 1:
                logger.warning(
                    "Subscription '%s' dropping events (dropped=%d) — "
                    "consumer too slow", self.name, self.dropped,
                )

    # -- consumer side ---------------------------------------------------
    def get(self, timeout: Optional[float] = None) -> Optional[Event]:
        """Return the next event, or None on timeout / closed."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self, max_items: int = 100) -> List[Event]:
        """Return up to *max_items* immediately-available events."""
        items: List[Event] = []
        for _ in range(max_items):
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def close(self) -> None:
        self._closed = True

    @property
    def pending(self) -> int:
        return self._queue.qsize()


class EventBus:
    """Thread-safe in-process pub/sub bus (see module docstring)."""

    def __init__(self):
        self._subs: List[Subscription] = []
        self._lock = threading.Lock()
        self.published = 0

    def subscribe(
        self,
        topics: List[str],
        name: str = "",
        capacity: int = DEFAULT_SUBSCRIPTION_CAPACITY,
    ) -> Subscription:
        """Register a consumer for *topics* and return its Subscription."""
        sub = Subscription(
            name=name or f"sub-{len(self._subs)}",
            topics=topics,
            capacity=capacity,
        )
        with self._lock:
            self._subs.append(sub)
        logger.info("EventBus: subscription '%s' registered for %s", sub.name, topics)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        sub.close()
        with self._lock:
            try:
                self._subs.remove(sub)
            except ValueError:
                pass

    def publish(self, topic: str, payload: Any) -> None:
        """Deliver *payload* to every matching subscription.  Never blocks."""
        # Snapshot under lock; offer outside the lock so a slow list of
        # subscribers can't serialize publishers against subscribe().
        with self._lock:
            subs = list(self._subs)
        self.published += 1
        event = Event(topic=topic, payload=payload)
        for sub in subs:
            if sub.matches(topic):
                sub._offer(event)

    def get_stats(self) -> Dict[str, Any]:
        """Diagnostics for the health/system API."""
        with self._lock:
            subs = list(self._subs)
        return {
            "published": self.published,
            "subscriptions": [
                {
                    "name": s.name,
                    "pending": s.pending,
                    "delivered": s.delivered,
                    "dropped": s.dropped,
                }
                for s in subs
            ],
        }


# Module-level singleton — the application bus.
event_bus = EventBus()
