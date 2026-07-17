"""
013_add_blocking_rules.py
=========================

Adds ``blocking_rules`` — admin-defined policy for which domains a client
may resolve.  Enforced by ``packet_capture.dns_blocker``, which answers a
matching DNS query with NXDOMAIN before the real reply arrives.

A rule with ``device_mac`` NULL applies network-wide; otherwise it applies
to that one client.  ``domain`` matches the domain itself and any subdomain
(``instagram.com`` also blocks ``www.instagram.com``).

Safe to run multiple times.
"""

import logging

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def run():
    """Create the blocking_rules table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocking_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                domain TEXT NOT NULL,
                device_mac TEXT DEFAULT NULL,    -- NULL = every client
                enabled INTEGER NOT NULL DEFAULT 1,
                hit_count INTEGER NOT NULL DEFAULT 0,
                last_hit TIMESTAMP DEFAULT NULL,
                note TEXT DEFAULT NULL
            )
        """)
        # One rule per (domain, scope). COALESCE keeps the network-wide rule
        # distinct from per-device ones, since NULLs never compare equal in a
        # UNIQUE index.
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_blocking_rules_unique "
            "ON blocking_rules(domain, COALESCE(device_mac, ''))"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocking_rules_enabled "
            "ON blocking_rules(enabled)"
        )
        conn.commit()

    logger.info("013: blocking_rules table ready")


if __name__ == "__main__":
    run()
