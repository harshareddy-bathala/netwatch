"""
Migration 002: Clean up devices from wrong subnets.

Run once to remove historical bad data. This script detects the current
subnet automatically and removes any devices that don't belong.

Usage:
    python database/migrations/002_cleanup_wrong_subnet.py
"""

import os
import sys
import sqlite3

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import DATABASE_PATH


def detect_current_subnet() -> str:
    """Detect current subnet prefix from the active network interface."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}"
    except Exception:
        pass
    return ""


def run_cleanup():
    """Remove devices not in current subnet."""
    current_subnet = detect_current_subnet()

    if not current_subnet:
        print("ERROR: Could not detect current subnet. Aborting.")
        return

    if not os.path.exists(DATABASE_PATH):
        print(f"ERROR: Database not found at {DATABASE_PATH}")
        return

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    print(f"Database: {DATABASE_PATH}")
    print(f"Current subnet: {current_subnet}.x")
    print()

    # Find wrong subnet devices
    cursor.execute("""
        SELECT ip_address, mac_address, device_name
        FROM devices
        WHERE ip_address NOT LIKE ?
    """, (f"{current_subnet}.%",))
    wrong_devices = cursor.fetchall()

    if not wrong_devices:
        print("No wrong-subnet devices found. Database is clean.")
        conn.close()
        return

    print(f"Found {len(wrong_devices)} device(s) in wrong subnet:")
    for ip, mac, name in wrong_devices:
        print(f"  - {ip} ({mac}) {name or ''}")

    # Delete wrong-subnet devices
    cursor.execute("""
        DELETE FROM devices
        WHERE ip_address NOT LIKE ?
    """, (f"{current_subnet}.%",))
    deleted = cursor.rowcount

    # Also clean up daily_usage for removed devices
    cursor.execute("""
        DELETE FROM daily_usage
        WHERE ip_address NOT LIKE ?
    """, (f"{current_subnet}.%",))
    daily_deleted = cursor.rowcount

    conn.commit()

    # Get remaining device count
    cursor.execute("SELECT COUNT(*) FROM devices")
    remaining = cursor.fetchone()[0]

    conn.close()

    print()
    print(f"Deleted {deleted} device(s) from wrong subnets")
    print(f"Deleted {daily_deleted} daily_usage record(s) for wrong subnets")
    print(f"Remaining devices: {remaining} (all in {current_subnet}.x)")


if __name__ == "__main__":
    run_cleanup()
