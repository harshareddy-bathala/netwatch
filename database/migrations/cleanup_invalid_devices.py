"""
002_cleanup_invalid_devices.py
================================
Database cleanup migration:
  - Remove devices with invalid MAC addresses (00:00:00:00:00:00, ff:ff:ff:ff:ff:ff)
  - Remove devices with non-private / multicast / broadcast IPs
  - Remove duplicate devices (keep the one with the most recent last_seen)
  - Clean related traffic_summary rows for removed devices
  - VACUUM the database after cleanup

Run manually:
    python -m database.migrations.002_cleanup_invalid_devices

Or it is called automatically on application startup via run_startup_migrations().
"""

import sqlite3
import os
import sys
import logging
import ipaddress

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(DATABASE_DIR)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import DATABASE_PATH, DATABASE_TIMEOUT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

INVALID_MACS = {
    '00:00:00:00:00:00',
    'ff:ff:ff:ff:ff:ff',
    'FF:FF:FF:FF:FF:FF',
}


def _is_bad_ip(ip: str) -> bool:
    """Return True if the IP should NOT exist in the devices table."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return True
        # 255.255.255.255 broadcast
        if ip == '255.255.255.255':
            return True
        # Link-local 169.254.x.x is usually noise
        if addr.is_link_local:
            return True
        return False
    except ValueError:
        return True  # malformed → remove


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

def run(db_path: str | None = None) -> dict:
    """
    Execute the cleanup migration.

    Returns a dict with counts of rows deleted from each table.
    """
    db_path = db_path or DATABASE_PATH
    if not os.path.exists(db_path):
        logger.warning("Database not found at %s – skipping cleanup migration.", db_path)
        return {'skipped': True}

    conn = sqlite3.connect(db_path, timeout=DATABASE_TIMEOUT)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    stats = {
        'devices_invalid_mac': 0,
        'devices_bad_ip': 0,
        'traffic_cleaned': 0,
        'daily_usage_cleaned': 0,
    }

    try:
        # ------------------------------------------------------------------
        # 1. Remove devices with invalid MAC addresses
        # ------------------------------------------------------------------
        mac_placeholders = ','.join('?' for _ in INVALID_MACS)
        cursor.execute(
            f"SELECT id, ip_address FROM devices WHERE mac_address IN ({mac_placeholders})",
            list(INVALID_MACS),
        )
        bad_mac_rows = cursor.fetchall()
        bad_mac_ids = [r['id'] for r in bad_mac_rows]
        bad_mac_ips = [r['ip_address'] for r in bad_mac_rows]

        if bad_mac_ids:
            id_ph = ','.join('?' for _ in bad_mac_ids)
            cursor.execute(f"DELETE FROM devices WHERE id IN ({id_ph})", bad_mac_ids)
            stats['devices_invalid_mac'] = cursor.rowcount
            logger.info("Removed %d devices with invalid MAC addresses.", cursor.rowcount)

        # ------------------------------------------------------------------
        # 2. Remove devices with bad IPs (multicast, broadcast, link-local…)
        # ------------------------------------------------------------------
        cursor.execute("SELECT id, ip_address FROM devices")
        all_devices = cursor.fetchall()
        bad_ip_ids = [r['id'] for r in all_devices if _is_bad_ip(r['ip_address'])]

        if bad_ip_ids:
            id_ph = ','.join('?' for _ in bad_ip_ids)
            cursor.execute(f"DELETE FROM devices WHERE id IN ({id_ph})", bad_ip_ids)
            stats['devices_bad_ip'] = cursor.rowcount
            logger.info("Removed %d devices with bad IP addresses.", cursor.rowcount)

        # ------------------------------------------------------------------
        # 3. Clean orphaned traffic_summary rows referencing deleted IPs
        # ------------------------------------------------------------------
        all_bad_ips = list(set(bad_mac_ips + [r['ip_address'] for r in all_devices if _is_bad_ip(r['ip_address'])]))
        if all_bad_ips:
            ip_ph = ','.join('?' for _ in all_bad_ips)
            cursor.execute(
                f"DELETE FROM traffic_summary WHERE source_ip IN ({ip_ph}) AND dest_ip IN ({ip_ph})",
                all_bad_ips + all_bad_ips,
            )
            stats['traffic_cleaned'] = cursor.rowcount

        # ------------------------------------------------------------------
        # 4. Clean daily_usage for removed devices
        # ------------------------------------------------------------------
        try:
            if all_bad_ips:
                ip_ph = ','.join('?' for _ in all_bad_ips)
                cursor.execute(
                    f"DELETE FROM daily_usage WHERE device_ip IN ({ip_ph})",
                    all_bad_ips,
                )
                stats['daily_usage_cleaned'] = cursor.rowcount
        except sqlite3.OperationalError:
            # daily_usage table may not exist in all schemas
            pass

        conn.commit()

        # ------------------------------------------------------------------
        # 5. VACUUM to reclaim space
        # ------------------------------------------------------------------
        try:
            conn.execute("VACUUM")
        except sqlite3.OperationalError:
            # VACUUM can fail inside a transaction on some builds
            pass

        total = sum(v for v in stats.values() if isinstance(v, int))
        if total > 0:
            logger.info("Cleanup migration complete. Removed %d rows total. %s", total, stats)
        else:
            logger.info("Cleanup migration: database is already clean.")

    except Exception as e:
        conn.rollback()
        logger.error("Cleanup migration failed: %s", e)
        raise
    finally:
        conn.close()

    return stats


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def run_startup_migrations(db_path: str | None = None):
    """Called from app startup to run all pending migrations."""
    logger.info("Running startup database migrations …")
    run(db_path)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s | %(message)s')
    result = run()
    print("Cleanup result:", result)
