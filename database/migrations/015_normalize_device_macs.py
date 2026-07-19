"""
015_normalize_device_macs.py
=============================
Normalise device MAC addresses to lower-case and remove non-device rows.

Two defects left junk in the ``devices`` table:

1. **Mixed-case duplicates.** Scapy reports upper-case MACs while the
   discovery path stores lower-case, and ``mac_address`` is the primary key —
   so one phone occupied two rows (``22:5E:3E:1A:D0:F3`` and
   ``22:5e:3e:1a:d0:f3``), and the dashboard counted it twice.
2. **Broadcast / multicast rows.** ``ff:ff:ff:ff:ff:ff`` at the subnet
   broadcast address is not a device.

The write paths are fixed; this cleans up rows already persisted. Duplicates
are merged into the lower-case row, keeping the most recent ``last_seen`` and
summing byte counters so history isn't lost.
"""

import logging

from database.connection import get_connection

logger = logging.getLogger(__name__)

# Prefixes that are never a real unicast device.
_BAD_EXACT = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
_BAD_PREFIX = ("01:00:5e:", "33:33:", "01:80:c2:")


def run():
    with get_connection() as conn:
        cursor = conn.cursor()

        # --- 1. drop broadcast / multicast rows -------------------------
        cursor.execute("SELECT mac_address FROM devices")
        removed = 0
        for row in cursor.fetchall():
            mac = (row[0] or "").lower()
            if mac in _BAD_EXACT or any(mac.startswith(p) for p in _BAD_PREFIX):
                cursor.execute("DELETE FROM devices WHERE mac_address = ?", (row[0],))
                removed += 1

        # --- 2. merge mixed-case duplicates -----------------------------
        cursor.execute("SELECT mac_address FROM devices")
        by_lower: dict = {}
        for row in cursor.fetchall():
            raw = row[0]
            if raw is None:
                continue
            by_lower.setdefault(raw.lower(), []).append(raw)

        merged = 0
        for lower, variants in by_lower.items():
            if len(variants) == 1 and variants[0] == lower:
                continue        # already canonical, nothing to do

            # Winner = most recently seen row among the variants.
            placeholders = ",".join("?" for _ in variants)
            cursor.execute(
                f"""SELECT mac_address, hostname, device_name, ip_address,
                           ipv4_address, ipv6_address, vendor,
                           COALESCE(total_bytes_sent, 0),
                           COALESCE(total_bytes_received, 0),
                           COALESCE(total_packets, 0), last_seen, first_seen
                    FROM devices WHERE mac_address IN ({placeholders})
                    ORDER BY last_seen DESC""",
                tuple(variants),
            )
            rows = cursor.fetchall()
            if not rows:
                continue
            best = rows[0]
            sent = sum(r[7] for r in rows)
            recv = sum(r[8] for r in rows)
            pkts = sum(r[9] for r in rows)
            first_seen = min((r[11] for r in rows if r[11]), default=best[11])
            # Prefer any non-empty identity field across the variants.
            def pick(idx):
                for r in rows:
                    if r[idx]:
                        return r[idx]
                return None

            cursor.execute(
                f"DELETE FROM devices WHERE mac_address IN ({placeholders})",
                tuple(variants),
            )
            cursor.execute(
                """INSERT INTO devices
                       (mac_address, hostname, device_name, ip_address,
                        ipv4_address, ipv6_address, vendor,
                        total_bytes_sent, total_bytes_received, total_packets,
                        first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (lower, pick(1), pick(2), pick(3), pick(4), pick(5), pick(6),
                 sent, recv, pkts, first_seen, best[10]),
            )
            if len(variants) > 1:
                merged += 1

        conn.commit()

    if removed or merged:
        logger.info("015: removed %d non-device row(s), merged %d duplicate "
                    "MAC group(s)", removed, merged)
    else:
        logger.info("015: device MACs already normalised")
