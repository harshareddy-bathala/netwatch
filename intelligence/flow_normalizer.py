"""
flow_normalizer.py - Packet Batches → Flow / DNS Telemetry (Phase 0)
=====================================================================

The first event-bus consumer.  Subscribes to ``packet.batch`` events
published by :class:`packet_capture.database_writer.DatabaseWriter`
and maintains a table of *active flows* keyed by::

    (source_ip, dest_ip, source_port, dest_port, protocol, direction)

A flow is flushed to the ``flows`` table (and published as a
``flow.completed`` event) when it has been idle for
``FLOW_IDLE_TIMEOUT_SECONDS`` or alive for ``FLOW_MAX_AGE_SECONDS``.
DNS query packets additionally produce rows in ``dns_queries`` and
``dns.query`` events.

This thread never touches the capture hot path: it consumes from its own
bounded bus subscription (drop-oldest under overload) and does its own
DB writes.  Retention for both tables is handled here as well
(self-contained hourly cleanup).
"""

import logging
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

from intelligence.event_bus import event_bus as _default_bus

logger = logging.getLogger(__name__)

# Config with safe fallbacks (module is importable without project config)
try:
    from config import (
        FLOW_IDLE_TIMEOUT_SECONDS,
        FLOW_MAX_AGE_SECONDS,
        FLOW_FLUSH_INTERVAL_SECONDS,
        FLOW_RETENTION_HOURS,
        FLOW_MAX_ACTIVE,
    )
except ImportError:
    FLOW_IDLE_TIMEOUT_SECONDS = 30
    FLOW_MAX_AGE_SECONDS = 300
    FLOW_FLUSH_INTERVAL_SECONDS = 5.0
    FLOW_RETENTION_HOURS = 72
    FLOW_MAX_ACTIVE = 50000

_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _is_noise_qname(qname: str) -> bool:
    """Resolver plumbing, not user activity: reverse-DNS lookups (the
    capture host's own hostname resolver emits bursts of these), mDNS
    service discovery, and WPAD probes.  They drowned the Activity feed —
    one host card was 67 ``*.in-addr.arpa`` rows and zero real sites."""
    q = qname.lower().rstrip(".")
    return (q.endswith(".arpa") or q.endswith(".local")
            or q in ("wpad", "localhost") or q.startswith("wpad."))


def _ts_str(value) -> str:
    """Normalize datetime/str/epoch to the project's timestamp string."""
    if isinstance(value, datetime):
        return value.strftime(_TS_FMT)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value).strftime(_TS_FMT)
    return str(value) if value else datetime.now().strftime(_TS_FMT)


class _ActiveFlow:
    """Mutable accumulator for one in-progress flow."""

    __slots__ = ("first_seen", "last_seen", "bytes_total", "packets_total",
                 "source_mac", "dest_mac", "is_control")

    def __init__(self, now: float, source_mac: Optional[str],
                 dest_mac: Optional[str], is_control: bool):
        self.first_seen = now
        self.last_seen = now
        self.bytes_total = 0
        self.packets_total = 0
        self.source_mac = source_mac
        self.dest_mac = dest_mac
        self.is_control = 1 if is_control else 0


class FlowNormalizer:
    """Aggregates packet batches into flow records (see module docstring).

    Parameters allow injecting save functions and a bus for tests.
    """

    def __init__(
        self,
        shutdown_event: Optional[threading.Event] = None,
        bus=None,
        save_flows: Optional[Callable[[List[dict]], int]] = None,
        save_dns: Optional[Callable[[List[dict]], int]] = None,
        idle_timeout: float = FLOW_IDLE_TIMEOUT_SECONDS,
        max_age: float = FLOW_MAX_AGE_SECONDS,
        flush_interval: float = FLOW_FLUSH_INTERVAL_SECONDS,
        retention_hours: int = FLOW_RETENTION_HOURS,
        max_active: int = FLOW_MAX_ACTIVE,
    ):
        self._bus = bus or _default_bus
        self._shutdown_event = shutdown_event or threading.Event()
        self._idle_timeout = idle_timeout
        self._max_age = max_age
        self._flush_interval = flush_interval
        self._retention_hours = retention_hours
        self._max_active = max_active

        self._save_flows = save_flows
        self._save_dns = save_dns

        self._flows: Dict[tuple, _ActiveFlow] = {}
        self._dns_buffer: List[dict] = []
        self._thread: Optional[threading.Thread] = None
        self._sub = None

        # Diagnostics
        self.flows_flushed = 0
        self.dns_saved = 0
        self.batches_ingested = 0

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def _resolve_save_fns(self) -> bool:
        if self._save_flows is None or self._save_dns is None:
            try:
                from database.queries.flow_queries import (
                    save_flows_batch, save_dns_queries_batch,
                )
                self._save_flows = self._save_flows or save_flows_batch
                self._save_dns = self._save_dns or save_dns_queries_batch
            except ImportError:
                logger.error("FlowNormalizer: flow_queries unavailable — not starting")
                return False
        return True

    def start(self) -> bool:
        """Subscribe to the bus and launch the consumer thread."""
        if self._thread and self._thread.is_alive():
            return True
        if not self._resolve_save_fns():
            return False
        self._sub = self._bus.subscribe(
            ["packet.batch"], name="flow-normalizer",
        )
        self._thread = threading.Thread(
            target=self._run, name="FlowNormalizer", daemon=True,
        )
        self._thread.start()
        logger.info(
            "FlowNormalizer started (idle=%ss, max_age=%ss, retention=%dh)",
            self._idle_timeout, self._max_age, self._retention_hours,
        )
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Flush everything and stop the thread."""
        self._shutdown_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._sub is not None:
            self._bus.unsubscribe(self._sub)

    def get_stats(self) -> dict:
        return {
            "active_flows": len(self._flows),
            "flows_flushed": self.flows_flushed,
            "dns_saved": self.dns_saved,
            "batches_ingested": self.batches_ingested,
            "running": bool(self._thread and self._thread.is_alive()),
        }

    # ------------------------------------------------------------------ #
    #  Consumer thread
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        last_flush = time.monotonic()
        last_retention = time.monotonic()
        while not self._shutdown_event.is_set():
            event = self._sub.get(timeout=self._flush_interval)
            if event is not None and event.topic == "packet.batch":
                try:
                    self.ingest_batch(event.payload)
                except Exception as exc:
                    logger.error("FlowNormalizer ingest error: %s", exc)

            now = time.monotonic()
            if now - last_flush >= self._flush_interval:
                try:
                    self.flush(force=False)
                except Exception as exc:
                    logger.error("FlowNormalizer flush error: %s", exc)
                last_flush = now

            if now - last_retention >= 3600:
                try:
                    from database.queries.flow_queries import cleanup_old_flow_data
                    result = cleanup_old_flow_data(self._retention_hours)
                    if any(result.values()):
                        logger.info("Flow retention: %s", result)
                except Exception as exc:
                    logger.error("Flow retention error: %s", exc)
                last_retention = now

        # Drain remaining events, then final flush
        try:
            for event in self._sub.drain(max_items=1000):
                if event.topic == "packet.batch":
                    self.ingest_batch(event.payload)
            self.flush(force=True)
        except Exception as exc:
            logger.error("FlowNormalizer final flush error: %s", exc)
        logger.info("FlowNormalizer thread exited")

    # ------------------------------------------------------------------ #
    #  Aggregation
    # ------------------------------------------------------------------ #

    def ingest_batch(self, batch: List[dict]) -> None:
        """Fold a batch of normalized packet dicts into active flows."""
        if not batch:
            return
        self.batches_ingested += 1
        now = time.time()

        for p in batch:
            key = (
                p.get("source_ip") or "",
                p.get("dest_ip") or "",
                p.get("source_port"),
                p.get("dest_port"),
                p.get("protocol") or "UNKNOWN",
                p.get("direction") or "unknown",
            )
            flow = self._flows.get(key)
            if flow is None:
                if len(self._flows) >= self._max_active:
                    # Memory guard: force-flush before accepting new flows.
                    self.flush(force=True)
                flow = _ActiveFlow(
                    now,
                    p.get("source_mac"),
                    p.get("dest_mac"),
                    bool(p.get("is_control_traffic")),
                )
                self._flows[key] = flow
            flow.last_seen = now
            flow.bytes_total += int(p.get("bytes") or 0)
            flow.packets_total += 1

            qname = p.get("dns_qname")
            if qname and not _is_noise_qname(qname):
                dns_row = {
                    "timestamp": _ts_str(p.get("timestamp")),
                    "source_ip": p.get("source_ip"),
                    "source_mac": p.get("source_mac"),
                    "qname": qname,
                    "qtype": p.get("dns_qtype"),
                    "protocol": p.get("protocol") or "DNS",
                }
                self._dns_buffer.append(dns_row)
                self._bus.publish("dns.query", dns_row)

            # TLS SNI names the destination site directly — the only name
            # signal we get from clients whose DNS is encrypted (Private
            # DNS / DoH). Stored beside DNS rows so the Activity feed and
            # the twin see one unified "device → site" stream.
            sni = p.get("tls_sni")
            if sni and not _is_noise_qname(sni):
                sni_row = {
                    "timestamp": _ts_str(p.get("timestamp")),
                    "source_ip": p.get("source_ip"),
                    "source_mac": p.get("source_mac"),
                    "qname": sni,
                    "qtype": None,
                    # "TLS" (TCP ClientHello) or "QUIC" (HTTP/3 Initial) so the
                    # Activity feed can show where the name came from.
                    "protocol": p.get("tls_sni_proto") or "TLS",
                }
                self._dns_buffer.append(sni_row)
                self._bus.publish("dns.query", sni_row)

    def flush(self, force: bool = False) -> int:
        """Persist expired flows (all flows when *force*) and DNS buffer.

        Returns the number of flow rows written.
        """
        now = time.time()
        expired_keys = []
        for key, flow in self._flows.items():
            if (
                force
                or now - flow.last_seen >= self._idle_timeout
                or now - flow.first_seen >= self._max_age
            ):
                expired_keys.append(key)

        rows: List[dict] = []
        for key in expired_keys:
            flow = self._flows.pop(key)
            src_ip, dst_ip, src_port, dst_port, protocol, direction = key
            row = {
                "first_seen": _ts_str(flow.first_seen),
                "last_seen": _ts_str(flow.last_seen),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "source_port": src_port,
                "dest_port": dst_port,
                "protocol": protocol,
                "direction": direction,
                "source_mac": flow.source_mac,
                "dest_mac": flow.dest_mac,
                "bytes_total": flow.bytes_total,
                "packets_total": flow.packets_total,
                "is_control": flow.is_control,
                "duration_seconds": round(max(0.0, flow.last_seen - flow.first_seen), 3),
            }
            rows.append(row)

        written = 0
        if rows and self._save_flows is not None:
            count = self._save_flows(rows)
            if count and count > 0:
                written = count
                self.flows_flushed += count
                for row in rows:
                    self._bus.publish("flow.completed", row)

        if self._dns_buffer and self._save_dns is not None:
            dns_rows, self._dns_buffer = self._dns_buffer, []
            count = self._save_dns(dns_rows)
            if count and count > 0:
                self.dns_saved += count
            elif count is not None and count < 0:
                # Save failed (e.g. DB locked past retries) — re-buffer so
                # the next flush retries, capped to avoid unbounded growth.
                self._dns_buffer = (dns_rows + self._dns_buffer)[:5000]

        return written
