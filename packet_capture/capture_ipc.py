"""
capture_ipc.py - Capture Privilege-Separation Transport (Phase 2.5)
===================================================================

Moves packet capture behind a local socket so the sniffing process can
run privileged and *minimal* while the API / intelligence / UI run
unprivileged.  The seam is the same batch-of-packet-dicts that already
flows into ``DatabaseWriter.enqueue`` and onto the ``packet.batch`` event
— nothing downstream changes.

    ┌──────────────────────────┐        ┌───────────────────────────┐
    │  privileged capture proc │        │   unprivileged main proc  │
    │  sniff → parse → batch   │─socket→│  enqueue → DB / bus / UI  │
    │  CaptureServer.publish() │ frames │  CaptureClient.run(cb)    │
    └──────────────────────────┘        └───────────────────────────┘

Design constraints:

* **Zero new dependencies.**  Loopback TCP (127.0.0.1) + stdlib ``socket``
  works identically on Windows/Linux/macOS; a shared token gates the
  connection so other local processes cannot inject packets.
* **Framing is explicit.**  Each frame is a 4-byte big-endian length
  prefix followed by a JSON batch, so partial reads on the stream never
  corrupt a batch.
* **Faithful payloads.**  ``parse_packet`` stamps a ``datetime``
  timestamp; the codec serialises it to ISO-8601 and revives it on the
  far side, so the receiver sees the exact dicts in-process capture
  produced.

This module is transport only — it never imports capture or DB code, so
either side can use it in isolation and tests can drive it over a real
loopback socket without root.
"""

import json
import logging
import socket
import struct
import threading
from datetime import datetime
from typing import Callable, Iterable, List, Optional

logger = logging.getLogger(__name__)

# Protocol handshake: magic + version, then a length-prefixed token.
_MAGIC = b"NWCAP1\n"
_LEN = struct.Struct(">I")          # 4-byte big-endian frame length
_MAX_FRAME = 32 * 1024 * 1024       # 32 MiB hard ceiling — refuse larger
_TS_KEY = "timestamp"


# ---------------------------------------------------------------------------
# Codec
# ---------------------------------------------------------------------------

def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def encode_batch(batch: List[dict]) -> bytes:
    """Serialise a packet batch to a length-prefixed frame."""
    payload = json.dumps(batch, default=_json_default,
                         separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_FRAME:
        raise ValueError(f"batch frame too large: {len(payload)} bytes")
    return _LEN.pack(len(payload)) + payload


def _revive_timestamps(batch: List[dict]) -> List[dict]:
    """Convert ISO ``timestamp`` strings back to datetime, matching what
    ``parse_packet`` produces in-process.  Leaves unparseable values as-is."""
    for pkt in batch:
        ts = pkt.get(_TS_KEY)
        if isinstance(ts, str):
            try:
                pkt[_TS_KEY] = datetime.fromisoformat(ts)
            except ValueError:
                pass
    return batch


def decode_batch(payload: bytes) -> List[dict]:
    """Inverse of :func:`encode_batch` for one frame's payload bytes."""
    batch = json.loads(payload.decode("utf-8"))
    if not isinstance(batch, list):
        raise ValueError("decoded frame is not a batch list")
    return _revive_timestamps(batch)


# ---------------------------------------------------------------------------
# Stream framing helpers
# ---------------------------------------------------------------------------

def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
    """Read exactly *n* bytes, or None if the peer closed mid-read."""
    chunks = bytearray()
    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def _read_frame(sock: socket.socket) -> Optional[bytes]:
    """Read one length-prefixed frame's payload bytes, or None on close."""
    header = _recv_exactly(sock, _LEN.size)
    if header is None:
        return None
    (length,) = _LEN.unpack(header)
    if length > _MAX_FRAME:
        raise ValueError(f"declared frame length {length} exceeds cap")
    return _recv_exactly(sock, length)


def _send_length_prefixed(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(_LEN.pack(len(payload)) + payload)


# ---------------------------------------------------------------------------
# Server (privileged capture side)
# ---------------------------------------------------------------------------

class CaptureServer:
    """Accepts one authenticated client and streams packet batches to it.

    The capture process calls :meth:`publish` with each batch; the server
    forwards it to the connected client.  When no client is connected
    batches are dropped (the capture path must never block).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 token: str = ""):
        self._host = host
        self._port = port
        self._token = token.encode("utf-8")
        self._srv: Optional[socket.socket] = None
        self._client: Optional[socket.socket] = None
        self._client_lock = threading.Lock()
        self._accept_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.batches_sent = 0
        self.batches_dropped = 0

    def start(self) -> int:
        """Bind, listen, and accept clients in the background.  Returns the
        bound port (useful when constructed with port=0)."""
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self._host, self._port))
        self._srv.listen(1)
        self._port = self._srv.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="CaptureServer", daemon=True)
        self._accept_thread.start()
        logger.info("CaptureServer listening on %s:%d", self._host, self._port)
        return self._port

    @property
    def port(self) -> int:
        return self._port

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._srv.settimeout(0.5)
                try:
                    conn, addr = self._srv.accept()
                except socket.timeout:
                    continue
            except OSError:
                break
            if not self._authenticate(conn):
                logger.warning("CaptureServer: rejected client %s (bad token)", addr)
                conn.close()
                continue
            logger.info("CaptureServer: client connected from %s", addr)
            with self._client_lock:
                if self._client is not None:
                    try:
                        self._client.close()
                    except OSError:
                        pass
                self._client = conn

    def _authenticate(self, conn: socket.socket) -> bool:
        try:
            conn.settimeout(5.0)
            conn.sendall(_MAGIC)
            token = _read_frame(conn)
            conn.settimeout(None)
            return token is not None and token == self._token
        except (OSError, ValueError):
            return False

    def publish(self, batch: List[dict]) -> None:
        """Forward a batch to the connected client; drop if none / on error."""
        if not batch:
            return
        with self._client_lock:
            client = self._client
        if client is None:
            self.batches_dropped += 1
            return
        try:
            frame = encode_batch(batch)
            client.sendall(frame)
            self.batches_sent += 1
        except (OSError, ValueError) as exc:
            logger.warning("CaptureServer: client send failed (%s) — dropping", exc)
            with self._client_lock:
                if self._client is client:
                    try:
                        client.close()
                    except OSError:
                        pass
                    self._client = None
            self.batches_dropped += 1

    def stop(self) -> None:
        self._stop.set()
        with self._client_lock:
            if self._client is not None:
                try:
                    self._client.close()
                except OSError:
                    pass
                self._client = None
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# Client (unprivileged main side)
# ---------------------------------------------------------------------------

class CaptureClient:
    """Connects to a :class:`CaptureServer` and delivers batches to a
    callback until stopped or the connection drops."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 token: str = "", connect_timeout: float = 5.0):
        self._host = host
        self._port = port
        self._token = token.encode("utf-8")
        self._connect_timeout = connect_timeout
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self.batches_received = 0

    def connect(self) -> None:
        sock = socket.create_connection((self._host, self._port),
                                        timeout=self._connect_timeout)
        magic = _recv_exactly(sock, len(_MAGIC))
        if magic != _MAGIC:
            sock.close()
            raise ConnectionError("capture server handshake failed (bad magic)")
        _send_length_prefixed(sock, self._token)
        sock.settimeout(None)
        self._sock = sock
        logger.info("CaptureClient connected to %s:%d", self._host, self._port)

    def batches(self) -> Iterable[List[dict]]:
        """Yield decoded batches until the connection closes or stop()."""
        if self._sock is None:
            self.connect()
        while not self._stop.is_set():
            try:
                payload = _read_frame(self._sock)
            except (OSError, ValueError) as exc:
                logger.warning("CaptureClient: read error (%s)", exc)
                break
            if payload is None:
                break
            self.batches_received += 1
            yield decode_batch(payload)

    def run(self, callback: Callable[[List[dict]], None]) -> None:
        """Deliver every received batch to *callback* until the stream ends."""
        for batch in self.batches():
            try:
                callback(batch)
            except Exception:
                logger.exception("CaptureClient: batch callback error")

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
