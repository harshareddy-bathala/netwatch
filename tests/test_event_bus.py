"""
test_event_bus.py - Event Bus Tests (Phase 0, AI-first substrate)
==================================================================

Covers ``intelligence.event_bus``: topic matching, non-blocking
publish with drop-oldest overflow, drain, and diagnostics.
"""

import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.event_bus import EventBus, Event


class TestSubscribePublish:

    def test_exact_topic_delivery(self):
        bus = EventBus()
        sub = bus.subscribe(["flow.completed"], name="t1")
        bus.publish("flow.completed", {"a": 1})
        event = sub.get(timeout=0.1)
        assert event is not None
        assert event.topic == "flow.completed"
        assert event.payload == {"a": 1}

    def test_non_matching_topic_not_delivered(self):
        bus = EventBus()
        sub = bus.subscribe(["flow.completed"], name="t2")
        bus.publish("dns.query", {"q": "example.com"})
        assert sub.get(timeout=0.05) is None

    def test_wildcard_prefix_matching(self):
        bus = EventBus()
        sub = bus.subscribe(["mode.*"], name="t3")
        bus.publish("mode.changed", {"old_mode": "hotspot", "new_mode": "ethernet"})
        event = sub.get(timeout=0.1)
        assert event is not None
        assert event.payload["new_mode"] == "ethernet"

    def test_star_matches_everything(self):
        bus = EventBus()
        sub = bus.subscribe(["*"], name="t4")
        bus.publish("anything.at.all", 42)
        event = sub.get(timeout=0.1)
        assert event is not None and event.payload == 42

    def test_multiple_subscribers_each_get_copy(self):
        bus = EventBus()
        s1 = bus.subscribe(["packet.batch"], name="a")
        s2 = bus.subscribe(["packet.batch"], name="b")
        bus.publish("packet.batch", [1, 2, 3])
        assert s1.get(timeout=0.1).payload == [1, 2, 3]
        assert s2.get(timeout=0.1).payload == [1, 2, 3]


class TestOverflow:

    def test_publish_never_blocks_and_drops_oldest(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="slow", capacity=3)
        for i in range(10):
            bus.publish("x", i)  # must not block
        # Queue holds the 3 newest events; 7 were dropped
        got = [e.payload for e in sub.drain(max_items=10)]
        assert got == [7, 8, 9]
        assert sub.dropped == 7

    def test_drop_counter_in_stats(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="slow", capacity=1)
        bus.publish("x", 1)
        bus.publish("x", 2)
        stats = bus.get_stats()
        entry = next(s for s in stats["subscriptions"] if s["name"] == "slow")
        assert entry["dropped"] == 1
        assert stats["published"] == 2


class TestConsumerAPI:

    def test_drain_respects_max_items(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="d")
        for i in range(5):
            bus.publish("x", i)
        assert len(sub.drain(max_items=2)) == 2
        assert sub.pending == 3

    def test_get_timeout_returns_none(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="empty")
        assert sub.get(timeout=0.05) is None

    def test_unsubscribe_stops_delivery(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="gone")
        bus.unsubscribe(sub)
        bus.publish("x", 1)
        assert sub.get(timeout=0.05) is None

    def test_closed_subscription_ignores_offers(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="closed")
        sub.close()
        bus.publish("x", 1)
        assert sub.pending == 0


class TestThreading:

    def test_concurrent_publishers(self):
        bus = EventBus()
        sub = bus.subscribe(["x"], name="mt", capacity=10_000)
        n_threads, per_thread = 8, 500

        def worker():
            for i in range(per_thread):
                bus.publish("x", i)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        total = sub.delivered
        assert total == n_threads * per_thread
        assert sub.dropped == 0
