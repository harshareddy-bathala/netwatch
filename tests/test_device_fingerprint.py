"""
test_device_fingerprint.py - Auto device identification (W4)
=============================================================

The classifier turns passive signals (vendor OUI, hostname, DHCP-55 param
list) into a device-type guess + friendly label. Deterministic → unit
tests assert the common consumer devices land in the right bucket and that
weak/unknown signals stay honest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.device_fingerprint import (
    classify_device, is_known_consumer_vendor,
    PHONE, TABLET, LAPTOP, TV, IOT, ROUTER, UNKNOWN,
)


class TestHostnameHints:

    def test_phone_hostnames(self):
        for hn in ("Nothing-Phone-2a", "iPhone-Harsha", "Pixel-7",
                   "Galaxy-S23", "OnePlus-11", "redmi-note"):
            assert classify_device(hostname=hn)["device_type"] == PHONE, hn

    def test_tablet_hostnames(self):
        assert classify_device(hostname="Galaxy-Tab-A9")["device_type"] == TABLET
        assert classify_device(hostname="iPad-Pro")["device_type"] == TABLET

    def test_laptop_hostnames(self):
        assert classify_device(hostname="MacBook-Air")["device_type"] == LAPTOP
        assert classify_device(hostname="DESKTOP-thinkpad")["device_type"] == LAPTOP

    def test_tv_and_iot(self):
        assert classify_device(hostname="living-room-tv")["device_type"] == TV
        assert classify_device(hostname="chromecast-hall")["device_type"] == TV
        assert classify_device(hostname="esp32-sensor")["device_type"] == IOT
        assert classify_device(hostname="Amazon-Echo")["device_type"] == IOT

    def test_label_is_friendly_hostname(self):
        r = classify_device(hostname="Nothing-Phone-2a.local")
        assert r["label"] == "Nothing-Phone-2a"
        assert r["confidence"] >= 0.8


class TestVendorFallback:

    def test_vendor_only_when_no_hostname(self):
        assert classify_device(vendor="Nothing Technology Limited")["device_type"] == PHONE
        assert classify_device(vendor="Ubiquiti Inc")["device_type"] == ROUTER

    def test_hostname_beats_vendor(self):
        # Apple vendor but a laptop hostname → laptop, not phone.
        r = classify_device(vendor="Apple, Inc.", hostname="MacBook-Pro")
        assert r["device_type"] == LAPTOP

    def test_label_from_vendor_when_no_hostname(self):
        r = classify_device(vendor="Espressif Inc.")
        assert r["device_type"] == IOT
        assert "Espressif" in r["label"]


class TestUnknownAndHonesty:

    def test_no_signals_is_unknown(self):
        r = classify_device()
        assert r["device_type"] == UNKNOWN
        assert r["confidence"] == 0.0
        assert r["label"] == ""

    def test_unrecognized_vendor_unknown(self):
        r = classify_device(vendor="Totally Made Up Co")
        assert r["device_type"] == UNKNOWN


class TestDhcpFingerprint:

    def test_dhcp55_windows(self):
        fp = (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 252)
        assert classify_device(dhcp_fingerprint=fp)["device_type"] == "desktop"


class TestKnownConsumerVendor:

    def test_known(self):
        assert is_known_consumer_vendor("Apple, Inc.")
        assert is_known_consumer_vendor("Samsung Electronics")
        assert is_known_consumer_vendor("Nothing Technology Limited")

    def test_unknown(self):
        assert not is_known_consumer_vendor("")
        assert not is_known_consumer_vendor("Obscure Router Vendor XYZ")
