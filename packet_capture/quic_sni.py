"""
quic_sni.py - Passive SNI recovery from QUIC Initial packets (RFC 9001)
=======================================================================

Modern phones defeat NetWatch's name capture two ways at once: encrypted
DNS (Private DNS / DoH → no port-53 packet) and HTTP/3 = **QUIC over
UDP/443** for the actual apps (Instagram, YouTube, TikTok…). The TCP-based
TLS-SNI hook never sees those.

But a QUIC **Initial** packet is *not* opaque. Its payload is encrypted
with keys **derived from the client's Destination Connection ID** using a
published salt (RFC 9001 §5.2), so anyone on-path — including a passive
monitor — can decrypt it and read the TLS ClientHello inside, which names
the site (SNI). This module does exactly that, using only the ClientHello
that is already sent in the clear-after-derivation Initial packet. No
payload beyond the handshake is touched; this stays metadata-only.

Limits (documented, not bugs): TLS 1.3 **Encrypted ClientHello (ECH)**
hides the real SNI even here; QUIC versions other than v1 are skipped; and
only the ClientHello (offset-0 CRYPTO) is parsed, which is the normal case.
"""

import hashlib
import hmac
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_OK = True
except ImportError:          # degrade quietly — QUIC SNI just stays off
    _CRYPTO_OK = False

# QUIC v1 initial salt (RFC 9001 §5.2)
_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
_QUIC_V1 = 0x00000001
_SAMPLE_LEN = 16
_MAX_QUIC_INITIAL = 1600     # ignore anything larger than a plausible Initial


# --------------------------------------------------------------------------- #
#  HKDF (TLS 1.3 / QUIC label form) — stdlib only
# --------------------------------------------------------------------------- #

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full_label = b"tls13 " + label.encode()
    # HkdfLabel: uint16 length, opaque label<1..255>, opaque context<0..255>
    info = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# --------------------------------------------------------------------------- #
#  Varint (RFC 9000 §16)
# --------------------------------------------------------------------------- #

def _read_varint(buf: bytes, off: int):
    """Return (value, new_offset) for a QUIC variable-length integer."""
    if off >= len(buf):
        raise ValueError("varint past end")
    prefix = buf[off] >> 6
    length = 1 << prefix
    if off + length > len(buf):
        raise ValueError("varint truncated")
    val = buf[off] & 0x3F
    for k in range(1, length):
        val = (val << 8) | buf[off + k]
    return val, off + length


# --------------------------------------------------------------------------- #
#  TLS ClientHello → SNI  (shared with the TCP-TLS path)
# --------------------------------------------------------------------------- #

def sni_from_client_hello(hs: bytes) -> Optional[str]:
    """Extract SNI from a TLS ClientHello **handshake message** (starts at
    the 0x01 handshake type — no record header). Bounds-checked."""
    try:
        if len(hs) < 39 or hs[0] != 0x01:
            return None
        i = 4                                  # type(1) + length(3)
        i += 2 + 32                            # client version + random
        i += 1 + hs[i]                         # session id
        i += 2 + int.from_bytes(hs[i:i + 2], "big")   # cipher suites
        i += 1 + hs[i]                         # compression methods
        if i + 2 > len(hs):
            return None
        ext_end = i + 2 + int.from_bytes(hs[i:i + 2], "big")
        i += 2
        while i + 4 <= min(ext_end, len(hs)):
            ext_type = int.from_bytes(hs[i:i + 2], "big")
            ext_len = int.from_bytes(hs[i + 2:i + 4], "big")
            i += 4
            if ext_type == 0:                  # server_name
                name_len = int.from_bytes(hs[i + 3:i + 5], "big")
                raw = hs[i + 5:i + 5 + name_len]
                try:
                    name = raw.decode("ascii")   # strict: junk → not a hostname
                except UnicodeDecodeError:
                    return None
                name = name.rstrip(".").lower()
                return name if _is_valid_hostname(name) else None
            i += ext_len
    except (IndexError, ValueError):
        pass
    return None


# A misparsed / partial ClientHello (e.g. QUIC CRYPTO spanning packets, or a
# non-Initial UDP-443 payload that happens to AEAD-verify) can walk into
# garbage and yield mojibake SNI. Only accept a syntactically valid hostname.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def _is_valid_hostname(name: str) -> bool:
    """True for a plausible DNS hostname (has a dot, valid labels, sane TLD)."""
    if not name or "." not in name:
        return False
    if not _HOSTNAME_RE.match(name):
        return False
    tld = name.rsplit(".", 1)[-1]
    return len(tld) >= 2 and tld.isalpha()   # reject numeric/garbage TLDs


# --------------------------------------------------------------------------- #
#  QUIC Initial decryption
# --------------------------------------------------------------------------- #

def _decrypt_initial_payload(data: bytes):
    """Decrypt a QUIC v1 Initial UDP payload → cleartext frames, or None."""
    if not _CRYPTO_OK or len(data) < 7 or len(data) > _MAX_QUIC_INITIAL:
        return None
    first = data[0]
    # Long header (0x80), fixed bit (0x40), packet type Initial (bits 5-4 == 00)
    if (first & 0x80) == 0 or (first & 0x30) != 0x00:
        return None
    if int.from_bytes(data[1:5], "big") != _QUIC_V1:
        return None
    off = 5
    try:
        dcid_len = data[off]; off += 1
        dcid = data[off:off + dcid_len]; off += dcid_len
        scid_len = data[off]; off += 1
        off += scid_len                        # skip SCID
        token_len, off = _read_varint(data, off)
        off += token_len                       # skip token
        length, off = _read_varint(data, off)  # length of pn + payload
        pn_offset = off
        if pn_offset + length > len(data) or length < 20:
            return None
    except (IndexError, ValueError):
        return None

    # Derive client initial secrets from the DCID.
    initial_secret = _hkdf_extract(_INITIAL_SALT, dcid)
    client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
    key = _hkdf_expand_label(client_secret, "quic key", 16)
    iv = _hkdf_expand_label(client_secret, "quic iv", 12)
    hp = _hkdf_expand_label(client_secret, "quic hp", 16)

    # Header protection: sample starts 4 bytes into the (still-protected) pn.
    sample_off = pn_offset + 4
    sample = data[sample_off:sample_off + _SAMPLE_LEN]
    if len(sample) < _SAMPLE_LEN:
        return None
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    first_unmasked = first ^ (mask[0] & 0x0F)
    pn_len = (first_unmasked & 0x03) + 1
    pn_bytes = bytes(data[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
    packet_number = int.from_bytes(pn_bytes, "big")

    # AEAD: nonce = iv XOR left-padded packet number; AAD = header w/ unmasked
    # first byte and unmasked pn; ciphertext = remainder after the pn.
    header = bytearray(data[:pn_offset + pn_len])
    header[0] = first_unmasked
    for i in range(pn_len):
        header[pn_offset + i] = pn_bytes[i]
    payload_off = pn_offset + pn_len
    ciphertext = data[payload_off:pn_offset + length]

    pn_full = packet_number.to_bytes(12, "big")
    nonce = bytes(iv[i] ^ pn_full[i] for i in range(12))
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, bytes(header))
    except Exception:
        return None


def _reassemble_crypto(frames: bytes) -> bytes:
    """Concatenate CRYPTO-frame data (offset-ordered) from decrypted frames."""
    chunks = {}
    off = 0
    n = len(frames)
    while off < n:
        try:
            ftype, off = _read_varint(frames, off)
        except ValueError:
            break
        if ftype == 0x00:                      # PADDING
            continue
        if ftype == 0x01:                      # PING
            continue
        if ftype in (0x02, 0x03):              # ACK — skip (not fully parsed)
            break
        if ftype == 0x06:                      # CRYPTO
            try:
                c_off, off = _read_varint(frames, off)
                c_len, off = _read_varint(frames, off)
            except ValueError:
                break
            chunks[c_off] = frames[off:off + c_len]
            off += c_len
        else:
            break                              # unknown frame — stop
    return b"".join(chunks[o] for o in sorted(chunks))


def extract_quic_sni(udp_payload: bytes) -> Optional[str]:
    """SNI from a QUIC Initial UDP payload, or None. Safe on any bytes."""
    if not _CRYPTO_OK:
        return None
    try:
        plaintext = _decrypt_initial_payload(udp_payload)
        if not plaintext:
            return None
        crypto = _reassemble_crypto(plaintext)
        if not crypto:
            return None
        return sni_from_client_hello(crypto)
    except Exception:
        return None


def crypto_available() -> bool:
    return _CRYPTO_OK
