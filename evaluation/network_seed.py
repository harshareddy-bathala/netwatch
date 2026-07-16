"""
network_seed.py - Realistic Network State for Evaluation (Phase 4)
===================================================================

Seeds the database with a **deterministic, realistic** network so the
citation-faithfulness evaluation has something to actually make claims
about.

Why this exists
---------------
Run against an idle database the investigator answers "the network is
not active, 0 devices, 0 bandwidth" — truthful, but containing almost no
*checkable facts*.  ``claim_support`` is 1.0 by definition for an answer
with nothing to check, so the metric scored a perfect 1.000 while
measuring 2 facts across 5 questions.  A populated network forces the
model to state device counts, bandwidth figures, IPs and protocol names
— facts the metric can verify against the tool results, and facts an
ungrounded model must hallucinate.

Design
------
* **Deterministic** — fixed seed, so the seeded network (and therefore
  the evaluation numbers) reproduces exactly.
* **Subnet-aware** — devices are placed in the host's detected subnet
  because ``get_active_device_count`` filters to the current subnet; a
  hard-coded 10.x network would count as 0 active devices on most hosts.
* **Realistic shape** — a household/office mix (laptops, phone, TV, NAS,
  printer) with plausible vendors, protocol mix and byte volumes, not
  uniform noise.

The seed writes only to ``devices`` and ``traffic_summary``.  It is
additive and clearly branded (``EVAL-SEED`` session ids), so
:func:`clear_seed` can remove exactly what it inserted.
"""

import logging
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SEED = 20260716
SESSION_TAG = "EVAL-SEED"

# Realistic device fleet. IPs are host suffixes — the subnet prefix is
# taken from the live host so the active-device query counts them.
_FLEET = [
    # (suffix, mac, hostname, vendor, device_type)
    (11, "3c:22:fb:1a:2b:01", "harsh-laptop",    "Apple, Inc.",           "laptop"),
    (12, "a4:83:e7:44:19:02", "pixel-7",         "Google, Inc.",          "phone"),
    (13, "d8:3a:dd:90:71:03", "living-room-tv",  "Samsung Electronics",   "tv"),
    (14, "00:11:32:aa:bc:04", "nas-vault",       "Synology Incorporated", "nas"),
    (15, "b8:27:eb:5c:9d:05", "rpi-sensor",      "Raspberry Pi Foundation", "iot"),
    (16, "30:05:5c:77:e1:06", "office-printer",  "Hewlett Packard",       "printer"),
    (17, "f0:9f:c2:31:44:07", "work-desktop",    "Ubiquiti Inc.",         "desktop"),
]

# External endpoints the fleet talks to, with a plausible protocol mix.
_EXTERNAL = [
    ("142.250.196.68", 443, "HTTPS"),   # google
    ("104.244.42.129", 443, "HTTPS"),   # twitter
    ("13.107.42.14",   443, "HTTPS"),   # microsoft
    ("151.101.1.140",   80, "HTTP"),    # fastly
    ("8.8.8.8",         53, "DNS"),
    ("1.1.1.1",         53, "DNS"),
    ("52.94.236.248",  443, "HTTPS"),   # aws
]


def _invalidate_caches() -> None:
    """Drop cached query results so reads reflect the seed.

    Both device and traffic queries memoise; a process that read metrics
    before seeding would otherwise keep serving the pre-seed (usually
    empty) answer.
    """
    for module, cache in (("database.queries.device_queries", "_device_cache"),
                          ("database.queries.traffic_queries", "_traffic_cache"),
                          ("database.queries.stats_queries", "_stats_cache")):
        try:
            mod = __import__(module, fromlist=[cache])
            getattr(mod, cache).clear()
        except Exception:      # cache is optional / named differently
            pass


def _subnet_prefix() -> str:
    """The host's /24 prefix (e.g. '192.168.40.'), so seeded devices land
    in the subnet the active-device query filters on."""
    try:
        from database.queries.device_queries import _detect_subnet_cidr
        cidr = _detect_subnet_cidr()
        if cidr:
            return cidr.rsplit(".", 1)[0] + "."
    except Exception as exc:
        logger.warning("subnet detection failed (%s) — falling back", exc)
    return "192.168.1."


def seed_network(conn=None, minutes: int = 60) -> Dict[str, object]:
    """Populate devices + traffic for the last *minutes*.

    Returns a summary of what was written (device count, row count, and
    the facts an answer about this network should contain).
    """
    from database.connection import get_connection

    rng = random.Random(SEED)
    prefix = _subnet_prefix()
    now = datetime.now()

    devices = [
        {"ip": f"{prefix}{suffix}", "mac": mac, "hostname": host,
         "vendor": vendor, "device_type": dtype}
        for suffix, mac, host, vendor, dtype in _FLEET
    ]

    def _write(cursor):
        # -- devices -------------------------------------------------
        for d in devices:
            # last_seen must be UTC-recent: get_active_device_count
            # compares against utcnow().
            cursor.execute("""
                INSERT INTO devices (mac_address, ip_address, ipv4_address,
                                     hostname, device_name, vendor,
                                     first_seen, last_seen, is_local,
                                     device_type, total_bytes_sent,
                                     total_bytes_received, total_packets)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address    = excluded.ip_address,
                    ipv4_address  = excluded.ipv4_address,
                    hostname      = excluded.hostname,
                    last_seen     = excluded.last_seen
            """, (d["mac"], d["ip"], d["ip"], d["hostname"], d["hostname"],
                  d["vendor"],
                  (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"),
                  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                  d["device_type"],
                  rng.randint(2_000_000, 90_000_000),
                  rng.randint(5_000_000, 400_000_000),
                  rng.randint(5_000, 90_000)))

        # -- traffic history ----------------------------------------
        rows = 0
        total_bytes = 0
        # One row per device per minute, plus a dense burst in the last
        # 10 seconds (get_realtime_stats derives live bandwidth from a
        # 10-second window).
        for minute in range(minutes):
            ts = now - timedelta(minutes=minute)
            for d in devices:
                if rng.random() < 0.25:      # not every device every minute
                    continue
                dst_ip, dst_port, proto = rng.choice(_EXTERNAL)
                for direction, lo, hi in (("download", 40_000, 3_000_000),
                                          ("upload", 5_000, 250_000)):
                    nbytes = rng.randint(lo, hi)
                    total_bytes += nbytes
                    rows += 1
                    cursor.execute("""
                        INSERT INTO traffic_summary
                            (timestamp, source_ip, dest_ip, source_mac,
                             source_port, dest_port, protocol,
                             bytes_transferred, packets_count, direction,
                             is_control, session_id, device_name, vendor)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                    """, (ts.strftime("%Y-%m-%d %H:%M:%S"),
                          d["ip"] if direction == "upload" else dst_ip,
                          dst_ip if direction == "upload" else d["ip"],
                          d["mac"], rng.randint(40000, 65000), dst_port,
                          proto, nbytes, max(1, nbytes // 1400), direction,
                          SESSION_TAG, d["hostname"], d["vendor"]))

        # -- live 10-second window ----------------------------------
        # get_realtime_stats derives live bandwidth from the trailing 10
        # seconds; without this burst the seeded network reads as idle.
        recent_bytes = 0
        for sec in range(10):
            ts = now - timedelta(seconds=sec)
            for d in devices[:4]:
                nbytes = rng.randint(60_000, 200_000)
                recent_bytes += nbytes
                rows += 1
                cursor.execute("""
                    INSERT INTO traffic_summary
                        (timestamp, source_ip, dest_ip, source_mac,
                         source_port, dest_port, protocol,
                         bytes_transferred, packets_count, direction,
                         is_control, session_id, device_name, vendor)
                    VALUES (?, ?, ?, ?, ?, ?, 'HTTPS', ?, ?, 'download', 0, ?, ?, ?)
                """, (ts.strftime("%Y-%m-%d %H:%M:%S"), "142.250.196.68",
                      d["ip"], d["mac"], 443, rng.randint(40000, 65000),
                      nbytes, max(1, nbytes // 1400), SESSION_TAG,
                      d["hostname"], d["vendor"]))

        return rows, total_bytes, recent_bytes

    if conn is not None:
        cursor = conn.cursor()
        rows, total_bytes, recent_bytes = _write(cursor)
        conn.commit()
    else:
        with get_connection() as c:
            cursor = c.cursor()
            rows, total_bytes, recent_bytes = _write(cursor)
            c.commit()

    _invalidate_caches()

    return {
        "devices": len(devices),
        "traffic_rows": rows,
        "subnet": prefix + "0/24",
        "device_ips": [d["ip"] for d in devices],
    }


def clear_seed(conn=None) -> int:
    """Remove only the rows this module inserted."""
    from database.connection import get_connection

    macs = [m for _, m, _, _, _ in _FLEET]
    placeholders = ",".join("?" * len(macs))

    def _clear(cursor):
        cursor.execute("DELETE FROM traffic_summary WHERE session_id = ?",
                       (SESSION_TAG,))
        n = cursor.rowcount
        cursor.execute(f"DELETE FROM devices WHERE mac_address IN ({placeholders})",
                       macs)
        return n + cursor.rowcount

    if conn is not None:
        cursor = conn.cursor()
        n = _clear(cursor)
        conn.commit()
    else:
        with get_connection() as c:
            n = _clear(c.cursor())
            c.commit()
    _invalidate_caches()
    return n
