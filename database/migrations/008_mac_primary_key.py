"""
008_mac_primary_key.py
=======================

Migrates the ``devices`` table from ``UNIQUE(ip_address)`` to
``UNIQUE(mac_address)`` keying.  Adds new columns:

- ``ipv4_address`` – device's IPv4 address (may change over time)
- ``ipv6_address`` – device's IPv6 address (if known)
- ``detected_mode`` – the capture mode that first discovered this device
- ``active_mode``   – the mode where this device is currently visible

Existing data is grouped by ``mac_address``: traffic totals are summed,
the newest ``last_seen`` wins, and user-set hostnames are preserved.

The old ``ip_address`` column is kept as an alias for backward
compatibility (populated with the IPv4 if available, else IPv6).
"""

import sqlite3
import logging
import os

logger = logging.getLogger(__name__)

DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    os.pardir,
    "netwatch.db",
)


def run():
    """Recreate devices table with MAC-primary keying."""
    try:
        from config import DATABASE_PATH as _db_path
        db_path = _db_path
    except Exception:
        db_path = DATABASE_PATH

    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Check if devices table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='devices'"
        )
        if not cursor.fetchone():
            logger.info("008: devices table does not exist yet – skipping migration")
            return

        # Check if migration already applied (active_mode column exists)
        cursor.execute("PRAGMA table_info(devices)")
        columns = {row[1] for row in cursor.fetchall()}
        if "active_mode" in columns:
            logger.info("008: devices table already has active_mode – skipping")
            return

        logger.info("008: Migrating devices table to MAC-primary keying")

        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("BEGIN TRANSACTION")

        # Create new table with MAC-primary keying
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL UNIQUE,
                ip_address TEXT DEFAULT NULL,
                ipv4_address TEXT DEFAULT NULL,
                ipv6_address TEXT DEFAULT NULL,
                hostname TEXT DEFAULT NULL,
                device_name TEXT DEFAULT NULL,
                vendor TEXT DEFAULT NULL,
                first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                total_bytes_sent INTEGER DEFAULT 0,
                total_bytes_received INTEGER DEFAULT 0,
                total_packets INTEGER DEFAULT 0,
                is_local INTEGER DEFAULT 0,
                device_type TEXT DEFAULT 'unknown',
                notes TEXT DEFAULT NULL,
                detected_mode TEXT DEFAULT NULL,
                active_mode TEXT DEFAULT NULL
            )
        """)

        # Migrate data: group by mac_address, merge totals, keep newest
        # last_seen, preserve user-set hostname/device_name.
        # Devices without a valid MAC are dropped (they were noise).
        cursor.execute("""
            INSERT INTO devices_v2 (
                mac_address, ip_address, ipv4_address, ipv6_address,
                hostname, device_name, vendor,
                first_seen, last_seen,
                total_bytes_sent, total_bytes_received, total_packets,
                is_local, device_type, notes
            )
            SELECT
                mac_address,
                -- ip_address: prefer IPv4 for backward compat
                MAX(CASE WHEN ip_address NOT LIKE '%:%' THEN ip_address END),
                -- ipv4_address
                MAX(CASE WHEN ip_address NOT LIKE '%:%' THEN ip_address END),
                -- ipv6_address
                MAX(CASE WHEN ip_address LIKE '%:%' THEN ip_address END),
                -- hostname: prefer non-null, non-IP values
                MAX(CASE
                    WHEN hostname IS NOT NULL AND hostname != ''
                         AND hostname != ip_address
                    THEN hostname END),
                -- device_name: prefer non-null, non-IP values
                MAX(CASE
                    WHEN device_name IS NOT NULL AND device_name != ''
                         AND device_name != ip_address
                    THEN device_name END),
                MAX(vendor),
                MIN(first_seen),
                MAX(last_seen),
                SUM(total_bytes_sent),
                SUM(total_bytes_received),
                SUM(total_packets),
                MAX(is_local),
                MAX(device_type),
                MAX(notes)
            FROM devices
            WHERE mac_address IS NOT NULL
              AND mac_address != ''
              AND mac_address != '00:00:00:00:00:00'
              AND mac_address != 'ff:ff:ff:ff:ff:ff'
            GROUP BY LOWER(mac_address)
        """)

        migrated = cursor.rowcount
        logger.info("008: Migrated %d unique MAC devices", migrated)

        # Drop old table and rename
        cursor.execute("DROP TABLE devices")
        cursor.execute("ALTER TABLE devices_v2 RENAME TO devices")

        # Recreate indexes
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_mac
            ON devices(mac_address)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_ip
            ON devices(ip_address)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_ipv4
            ON devices(ipv4_address)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_last_seen
            ON devices(last_seen)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_devices_active_mode
            ON devices(active_mode)
        """)

        conn.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
        logger.info("008: MAC-primary migration complete (%d devices)", migrated)

    except Exception as e:
        logger.error("008: Migration failed: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()
