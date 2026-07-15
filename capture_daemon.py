"""
capture_daemon.py - Privileged Capture Daemon (Phase 2.5)
==========================================================

The minimal privileged half of NetWatch.  It does only what needs root /
Administrator — detect the interface mode and sniff packets — then streams
parsed packet batches over a loopback socket to the unprivileged main
process.  No database, no API, no intelligence, no web server run here, so
the attack surface exposed to raw network data is small.

Usage (run elevated)::

    python capture_daemon.py                 # auto-detect mode + port
    python capture_daemon.py --port 51900    # fixed port

It writes ``host:port:token`` to ``CAPTURE_IPC_PORT_FILE`` so the
unprivileged process can connect.  Enable the split by setting
``CAPTURE_IPC_ENABLED=true`` for the main process.

The capture stack (mode detection, CaptureEngine, parser, bandwidth) is
reused unchanged; only the batch sink is redirected — the engine's
``db_writer`` is a :class:`CaptureServerWriter` that publishes to the
socket instead of writing SQLite.
"""

import argparse
import logging
import os
import secrets
import signal
import sys
import threading
import time
from typing import List, Optional

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from packet_capture.capture_ipc import CaptureServer  # noqa: E402

logger = logging.getLogger("capture_daemon")


class CaptureServerWriter:
    """Duck-types the slice of ``DatabaseWriter`` that CaptureEngine uses,
    but publishes each batch to the capture socket instead of the DB."""

    def __init__(self, server: CaptureServer):
        self._server = server
        self.packets_written = 0
        self.batches_written = 0

    def start(self) -> None:  # engine calls this
        pass

    def stop(self, timeout: float = 5.0) -> None:  # engine calls this
        pass

    def enqueue(self, packet_dicts: List[dict]) -> None:
        if not packet_dicts:
            return
        self._server.publish(packet_dicts)
        self.packets_written += len(packet_dicts)
        self.batches_written += 1

    @property
    def pending(self) -> int:
        return 0


def _write_endpoint_file(path: str, host: str, port: int, token: str) -> None:
    """Advertise the chosen endpoint for the main process to read."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"{host}:{port}:{token}")
    os.replace(tmp, path)
    logger.info("Capture endpoint written to %s (%s:%d)", path, host, port)


def read_endpoint_file(path: str):
    """Return (host, port, token) from an endpoint file, or None."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            host, port, token = fh.read().strip().split(":", 2)
        return host, int(port), token
    except (OSError, ValueError):
        return None


def _check_privileges() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def build_capture_engine(server: CaptureServer):
    """Construct a CaptureEngine bound to the detected mode, with its batch
    sink redirected to the capture socket.  Returns (engine, mode) or
    raises on failure."""
    from packet_capture.mode_detector import ModeDetector
    from packet_capture.capture_engine import CaptureEngine

    detector = ModeDetector()
    mode = detector.detect_mode()
    if mode is None:
        raise RuntimeError("no capture mode could be detected")

    writer = CaptureServerWriter(server)
    engine = CaptureEngine(mode=mode, db_writer=writer)
    return engine, mode


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=None, help="bind host (default from config)")
    parser.add_argument("--port", type=int, default=None, help="bind port (0 = auto)")
    parser.add_argument("--token", default=None, help="shared auth token")
    parser.add_argument("--endpoint-file", default=None,
                        help="path to advertise host:port:token")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    from config import (
        CAPTURE_IPC_HOST, CAPTURE_IPC_PORT, CAPTURE_IPC_TOKEN,
        CAPTURE_IPC_PORT_FILE,
    )
    host = args.host or CAPTURE_IPC_HOST
    port = args.port if args.port is not None else CAPTURE_IPC_PORT
    token = args.token or CAPTURE_IPC_TOKEN or secrets.token_hex(16)
    endpoint_file = args.endpoint_file or CAPTURE_IPC_PORT_FILE

    if not _check_privileges():
        logger.error("Capture daemon requires administrator/root privileges.")
        return 1

    server = CaptureServer(host=host, port=port, token=token)
    bound_port = server.start()
    _write_endpoint_file(endpoint_file, host, bound_port, token)

    try:
        engine, mode = build_capture_engine(server)
    except Exception as exc:
        logger.error("Failed to start capture: %s", exc)
        server.stop()
        return 1

    stop = threading.Event()

    def _sig(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    engine.start()
    logger.info("Capture daemon running (mode=%s). Ctrl+C to stop.",
                mode.get_mode_name().value)
    try:
        while not stop.is_set():
            time.sleep(0.5)
    finally:
        engine.stop()
        server.stop()
        try:
            os.remove(endpoint_file)
        except OSError:
            pass
    logger.info("Capture daemon stopped (batches sent=%d, dropped=%d)",
                server.batches_sent, server.batches_dropped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
