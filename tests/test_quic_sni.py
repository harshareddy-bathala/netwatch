"""
test_quic_sni.py - Passive QUIC Initial SNI recovery (W2)
=========================================================

Builds a real, encrypted QUIC v1 Initial packet carrying a TLS
ClientHello with a chosen SNI, then asserts the passive parser decrypts
and recovers it — the mechanism that makes Instagram/YouTube (QUIC) show
up for a phone using encrypted DNS.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from packet_capture.quic_sni import (
    extract_quic_sni, sni_from_client_hello,
    _hkdf_extract, _hkdf_expand_label, _INITIAL_SALT,
)
from packet_capture.packet_processor import extract_tls_sni


def _client_hello(server_name: str) -> bytes:
    """A minimal TLS ClientHello *handshake message* (no record header)."""
    name = server_name.encode()
    sni_entry = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = b"\xff\x01\x00\x01\x00" + sni_ext          # padding ext then SNI
    extensions = len(exts).to_bytes(2, "big") + exts
    body = (b"\x03\x03" + bytes(32) + b"\x00" +
            b"\x00\x02\x13\x01" + b"\x01\x00" + extensions)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _build_quic_initial(server_name: str, dcid: bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08") -> bytes:
    """Construct an encrypted QUIC v1 client Initial for *server_name*."""
    crypto = _client_hello(server_name)
    # CRYPTO frame: type 0x06, offset 0, length, data
    frame = b"\x06\x00" + len(crypto).to_bytes(2, "big")[1:] if len(crypto) < 64 else None
    # use varint-correct encoding: offset=0 (1 byte), length as varint
    def varint(n):
        if n < 64:
            return bytes([n])
        return (0x40 << 8 | n).to_bytes(2, "big")
    frames = b"\x06" + varint(0) + varint(len(crypto)) + crypto
    # pad so the sample (16B, 4 into the pn) has room
    frames = frames + b"\x00" * max(0, 64 - len(frames))

    initial_secret = _hkdf_extract(_INITIAL_SALT, dcid)
    client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
    key = _hkdf_expand_label(client_secret, "quic key", 16)
    iv = _hkdf_expand_label(client_secret, "quic iv", 12)
    hp = _hkdf_expand_label(client_secret, "quic hp", 16)

    pn = 0
    pn_len = 1
    pn_bytes = pn.to_bytes(pn_len, "big")
    first = 0xC0 | (pn_len - 1)          # long header, Initial, pn_len=1

    header_wo_len = (bytes([first]) + (1).to_bytes(4, "big") +
                     bytes([len(dcid)]) + dcid + b"\x00" + b"\x00")  # scid len 0, token len 0
    length_field = pn_len + len(frames) + 16   # pn + payload + GCM tag
    def varint_len(n):
        if n < 64:
            return bytes([n])
        return ((0x40 << 8) | n).to_bytes(2, "big")
    header = header_wo_len + varint_len(length_field)
    pn_offset = len(header)
    header_full = header + pn_bytes

    nonce = bytes(iv[i] ^ (pn.to_bytes(12, "big"))[i] for i in range(12))
    ct = AESGCM(key).encrypt(nonce, frames, header_full)

    packet = bytearray(header_full + ct)
    # Apply header protection using a sample 4 bytes into the pn field.
    sample_off = pn_offset + 4
    sample = bytes(packet[sample_off:sample_off + 16])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


class TestClientHelloWalk:
    def test_handshake_sni(self):
        assert sni_from_client_hello(_client_hello("www.instagram.com")) == "www.instagram.com"

    def test_tcp_record_still_works(self):
        record = b"\x16\x03\x01" + len(_client_hello("youtube.com")).to_bytes(2, "big") + _client_hello("youtube.com")
        assert extract_tls_sni(record) == "youtube.com"


class TestQuicInitial:
    def test_recovers_sni_from_encrypted_initial(self):
        pkt = _build_quic_initial("i.instagram.com")
        assert extract_quic_sni(pkt) == "i.instagram.com"

    def test_recovers_youtube(self):
        pkt = _build_quic_initial("rr4---sn-quic.googlevideo.com")
        assert extract_quic_sni(pkt) == "rr4---sn-quic.googlevideo.com"

    def test_non_quic_bytes_safe(self):
        assert extract_quic_sni(b"") is None
        assert extract_quic_sni(b"\x00" * 40) is None
        assert extract_quic_sni(bytes(range(60))) is None

    def test_short_header_ignored(self):
        # 0x40 = short header (1-RTT), never an Initial
        assert extract_quic_sni(b"\x40" + bytes(60)) is None


class TestIpOrg:
    def test_meta_and_google_ranges(self):
        from intelligence.ip_org import lookup_org
        assert lookup_org("57.144.168.192") == "Meta"
        assert lookup_org("142.250.67.46") == "Google"

    def test_private_ip_is_none(self):
        from intelligence.ip_org import lookup_org
        assert lookup_org("192.168.137.1") is None
        assert lookup_org("10.0.0.5") is None

    def test_unknown_ip_is_none(self):
        from intelligence.ip_org import lookup_org
        assert lookup_org("203.0.113.7") is None
