"""
pcap_replay.py - PCAP Replay Source (Phase 2.5)
================================================

Replays a captured ``.pcap`` file through the *real* parser and batches
the results exactly as live capture does — the primary test strategy for
the privilege-separated pipeline, since it needs no root and no live NIC.

Two sinks:

* feed a ``DatabaseWriter``-shaped object directly (``.enqueue(batch)``),
  driving the whole intelligence stack from a fixture file, or
* stream over :class:`~packet_capture.capture_ipc.CaptureServer` so the
  unprivileged side can be exercised end-to-end against recorded traffic.

Because it reuses ``parser.parse_packet``, whatever the live pipeline
would make of a packet is exactly what replay makes of it.
"""

import logging
import time
from typing import Callable, Iterator, List, Optional

logger = logging.getLogger(__name__)


def _load_scapy_reader():
    """Import scapy lazily so the module imports without it (tests that
    only build packets in memory still need scapy, but importing this
    module must never hard-fail)."""
    try:
        from scapy.all import PcapReader, rdpcap  # noqa: F401
        return PcapReader
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "scapy is required for pcap replay but is unavailable"
        ) from exc


def iter_parsed_packets(pcap_path: str) -> Iterator[dict]:
    """Yield parsed packet dicts from *pcap_path*, one per parseable frame.

    Streams via ``PcapReader`` so large captures don't load into memory.
    """
    from packet_capture.parser import parse_packet

    PcapReader = _load_scapy_reader()
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            # resolve_names=False: replay must stay pure and fast — no
            # per-packet reverse-DNS / NetBIOS lookups against the live
            # network for hosts that only exist in the capture file.
            parsed = parse_packet(pkt, resolve_names=False)
            if parsed is not None:
                yield parsed


def batch_packets(packets: Iterator[dict], batch_size: int = 50) -> Iterator[List[dict]]:
    """Group a stream of packet dicts into fixed-size batches."""
    batch: List[dict] = []
    for pkt in packets:
        batch.append(pkt)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def replay_to_sink(
    pcap_path: str,
    sink: Callable[[List[dict]], None],
    *,
    batch_size: int = 50,
    speed: float = 0.0,
    max_packets: Optional[int] = None,
) -> int:
    """Replay *pcap_path* into *sink* (called once per batch).

    Parameters
    ----------
    sink : callable
        Receives each batch — e.g. ``writer.enqueue`` or
        ``server.publish``.
    speed : float
        0 replays as fast as possible.  >0 sleeps ``batch_size / speed``
        seconds between batches to loosely pace a demo.
    max_packets : int, optional
        Stop after this many parsed packets (handy for tests).

    Returns the number of packets replayed.
    """
    total = 0
    packets = iter_parsed_packets(pcap_path)
    if max_packets is not None:
        packets = _limit(packets, max_packets)
    for batch in batch_packets(packets, batch_size=batch_size):
        sink(batch)
        total += len(batch)
        if speed > 0:
            time.sleep(len(batch) / speed)
    logger.info("pcap replay complete: %d packets from %s", total, pcap_path)
    return total


def _limit(it: Iterator[dict], n: int) -> Iterator[dict]:
    for i, item in enumerate(it):
        if i >= n:
            return
        yield item
