"""
intelligence - AI-First Intelligence Substrate (Phase 0)
=========================================================

This package hosts the intelligence layer that the AI-first roadmap
(ROADMAP.md) builds on top of the existing capture + dashboard stack:

* ``event_bus``      — in-process pub/sub event stream (Phase 0)
* ``flow_normalizer``— packet batches → flow / DNS telemetry (Phase 0)

Later phases add the digital twin, behavior profiles, detectors, and the
LLM investigation runtime here.  Nothing in this package may block the
capture hot path: publishers never wait on subscribers.
"""

from intelligence.event_bus import EventBus, Event, event_bus

__all__ = ["EventBus", "Event", "event_bus"]
