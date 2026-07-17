"""
device_fingerprint.py - Passive device identification (W4)
===========================================================

Turns the passive signals NetWatch already collects (OUI vendor, DHCP
Option-12 hostname, mDNS/SSDP names, and — when present — the DHCP
Option-55 parameter-request-list fingerprint) into a **device type** guess
and a **friendly label**, so the UI shows "Nothing-Phone" or
"Galaxy-Tab (tablet)" instead of a raw MAC, and "unknown device" means
something.

Pure and deterministic: ``classify_device(...)`` takes the signals and
returns ``{device_type, confidence, label}``. No I/O — trivially testable,
and the caller decides when/whether to persist.
"""

import re
from typing import Optional

# Device types we classify into (stored in devices.device_type).
PHONE, TABLET, LAPTOP, DESKTOP = "phone", "tablet", "laptop", "desktop"
TV, CONSOLE, IOT, PRINTER = "tv", "console", "iot", "printer"
WEARABLE, ROUTER, UNKNOWN = "wearable", "router", "unknown"

# Hostname substrings → device type. Most reliable signal when present.
_HOSTNAME_HINTS = [
    (PHONE, ("iphone", "galaxy-a", "galaxy-s", "galaxy-note", "pixel", "oneplus",
             "nothing-phone", "redmi", "poco", "moto-", "motog", "realme",
             "vivo", "oppo", "-phone", "mi-phone", "infinix")),
    (TABLET, ("ipad", "galaxy-tab", "-tab", "tablet", "mediapad", "surface-pro")),
    (LAPTOP, ("macbook", "laptop", "thinkpad", "-book", "ideapad", "zenbook",
              "inspiron", "latitude", "elitebook", "probook", "vivobook")),
    (DESKTOP, ("desktop", "-pc", "imac", "workstation", "optiplex")),
    (TV, ("tv", "firestick", "fire-stick", "chromecast", "shield", "roku",
          "bravia", "aquos", "vizio", "androidtv", "appletv", "-atv")),
    (CONSOLE, ("playstation", "ps4", "ps5", "xbox", "nintendo", "switch")),
    (WEARABLE, ("watch", "band", "-fit", "gizmo")),
    (PRINTER, ("printer", "officejet", "deskjet", "laserjet", "ecotank",
               "pixma", "-print")),
    (ROUTER, ("router", "gateway", "-ap", "access-point", "eero", "orbi",
              "deco", "unifi")),
    (IOT, ("echo", "alexa", "nest", "ring-", "esp-", "esp_", "esp32", "esp8266",
           "tuya", "smartplug", "smart-plug", "bulb", "camera", "cam-",
           "thermostat", "doorbell", "-iot", "shelly", "sonos", "hue")),
]

# OUI vendor substrings → (device type, confidence) when hostname is silent.
_VENDOR_HINTS = [
    (("nothing technology",), PHONE, 0.75),
    (("oneplus", "xiaomi", "vivo", "oppo", "realme", "motorola mobility",
      "guangdong oppo", "infinix"), PHONE, 0.6),
    (("samsung",), PHONE, 0.4),            # could be phone/tablet/TV — weak
    (("apple",), PHONE, 0.35),            # disambiguated by hostname usually
    (("intel", "dell", "lenovo", "asustek", "micro-star", "hewlett",
      "wistron", "compal", "quanta"), LAPTOP, 0.55),
    (("raspberry", "espressif", "tuya", "shenzhen", "sonos", "amazon techn",
      "google, inc", "nest labs", "ring llc"), IOT, 0.5),
    (("roku", "sony interactive", "vizio", "tcl"), TV, 0.55),
    (("nintendo", "microsoft"), CONSOLE, 0.4),
    (("ubiquiti", "tp-link", "netgear", "cisco", "d-link", "aruba",
      "mikrotik", "zyxel", "eero"), ROUTER, 0.55),
    (("hewlett-packard", "canon", "seiko epson", "brother"), PRINTER, 0.45),
]

# DHCP Option-55 parameter-request-list fingerprints (subset; the ordered
# option list is fairly OS-distinctive). Values are tuples of option numbers.
_DHCP55_FINGERPRINTS = {
    (1, 121, 3, 6, 15, 119, 252): (LAPTOP, 0.6),          # common Linux/macOS
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 252): (DESKTOP, 0.6),  # Windows
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43): (PHONE, 0.55),  # Android-ish
    (1, 121, 3, 6, 15, 114, 119, 252): (PHONE, 0.5),       # iOS-ish
}


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _label_from_hostname(hostname: str) -> str:
    """A clean display label from a raw hostname (strip domain, tidy dashes)."""
    h = hostname.split(".")[0].strip()
    return h or hostname


def classify_device(vendor: Optional[str] = None,
                    hostname: Optional[str] = None,
                    mac: Optional[str] = None,
                    dhcp_fingerprint: Optional[tuple] = None) -> dict:
    """Best-effort device identity from passive signals.

    Returns ``{"device_type", "confidence", "label"}``. ``confidence`` is
    0..1; ``label`` is a friendly name (hostname when available, else
    "<Vendor> <type>"), or "" when nothing is known.
    """
    v = _norm(vendor)
    h = _norm(hostname)

    dtype, confidence = UNKNOWN, 0.0

    # 1. Hostname hints (strongest).
    if h:
        for candidate, needles in _HOSTNAME_HINTS:
            if any(n in h for n in needles):
                dtype, confidence = candidate, 0.85
                break

    # 2. DHCP-55 fingerprint (only refines an unknown type).
    if dtype == UNKNOWN and dhcp_fingerprint:
        fp = _DHCP55_FINGERPRINTS.get(tuple(dhcp_fingerprint))
        if fp:
            dtype, confidence = fp

    # 3. Vendor hints (weakest; don't override a hostname/DHCP verdict).
    if dtype == UNKNOWN and v:
        for needles, candidate, conf in _VENDOR_HINTS:
            if any(n in v for n in needles):
                dtype, confidence = candidate, conf
                break

    # Friendly label.
    if h:
        label = _label_from_hostname(hostname)
    elif vendor:
        label = f"{vendor.split(',')[0].strip()}{' ' + dtype if dtype != UNKNOWN else ''}"
    else:
        label = ""

    return {"device_type": dtype, "confidence": round(confidence, 2), "label": label}


def is_known_consumer_vendor(vendor: Optional[str]) -> bool:
    """True when the OUI belongs to a mainstream consumer-device maker — so a
    'rogue device' alert for it can be softened (it's a phone joining, not an
    attacker planting hardware)."""
    v = _norm(vendor)
    if not v:
        return False
    for needles, _dtype, _conf in _VENDOR_HINTS:
        if any(n in v for n in needles):
            return True
    return "samsung" in v or "apple" in v or "google" in v
