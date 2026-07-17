"""
capture_bridge.py - Unprivileged Capture Bridge (Phase 2.5)
============================================================

The unprivileged half of the split.  Connects to the privileged capture
daemon over the loopback transport and feeds every received packet batch
into the existing ``DatabaseWriter`` — so DB writes, realtime-state
updates, and the ``packet.batch`` event all happen exactly as they do
under in-process capture.  Downstream (intelligence, API, UI) cannot tell
the difference.

Runs the client in a background thread with automatic reconnect, so a
daemon restart doesn't take the main process down with it.
"""

import logging
import threading
import time
from typing import Optional

from packet_capture.capture_ipc import CaptureClient

logger = logging.getLogger(__name__)


class CaptureBridge:
    """Streams batches from the capture daemon into a DatabaseWriter."""

    def __init__(self, writer, host: str, port: int, token: str,
                 reconnect_delay: float = 3.0):
        self._writer = writer
        self._host = host
        self._port = port
        self._token = token
        self._reconnect_delay = reconnect_delay
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._client: Optional[CaptureClient] = None
        self.batches_forwarded = 0
        self.reconnects = 0

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="CaptureBridge", daemon=True)
        self._thread.start()
        logger.info("CaptureBridge started (daemon %s:%d)", self._host, self._port)

    def _run(self) -> None:
        while not self._stop.is_set():
            client = CaptureClient(host=self._host, port=self._port,
                                   token=self._token)
            try:
                client.connect()
            except (OSError, ConnectionError) as exc:
                logger.warning("CaptureBridge: connect failed (%s) — retrying", exc)
                if self._stop.wait(self._reconnect_delay):
                    break
                self.reconnects += 1
                continue
            self._client = client
            try:
                for batch in client.batches():
                    if self._stop.is_set():
                        break
                    self._writer.enqueue(batch)
                    self.batches_forwarded += 1
            except Exception:
                logger.exception("CaptureBridge: stream error")
            finally:
                client.stop()
            if self._stop.is_set():
                break
            logger.info("CaptureBridge: daemon stream ended — reconnecting")
            if self._stop.wait(self._reconnect_delay):
                break
            self.reconnects += 1
        logger.info("CaptureBridge stopped (forwarded=%d, reconnects=%d)",
                    self.batches_forwarded, self.reconnects)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._client is not None:
            self._client.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)


def connect_from_endpoint_file(writer, endpoint_file: str,
                               wait_seconds: float = 10.0) -> Optional[CaptureBridge]:
    """Read the daemon's advertised endpoint and start a bridge.

    Polls *endpoint_file* (the daemon writes it on startup) for up to
    *wait_seconds*; returns a started :class:`CaptureBridge`, or None if
    the daemon never advertised.
    """
    from capture_daemon import read_endpoint_file

    deadline = time.time() + wait_seconds
    endpoint = None
    while time.time() < deadline:
        endpoint = read_endpoint_file(endpoint_file)
        if endpoint is not None:
            break
        time.sleep(0.25)
    if endpoint is None:
        logger.error("CaptureBridge: no daemon endpoint at %s after %.0fs",
                     endpoint_file, wait_seconds)
        return None
    host, port, token = endpoint
    bridge = CaptureBridge(writer, host=host, port=port, token=token)
    bridge.start()
    return bridge
