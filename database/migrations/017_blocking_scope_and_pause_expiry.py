"""
017_blocking_scope_and_pause_expiry.py
=======================================
Two columns that make enforcement say what it means.

``blocking_rules.scope`` ('device' | 'network')
    A rule already carried a ``device_mac``, but packet-level enforcement
    ignored it: every blocked domain was dropped by bare server IP, so
    "block Instagram on the kid's phone" also cut Instagram off for every
    other client and for the machine running NetWatch. Scope makes the
    distinction explicit and enforceable — and lets an admin still choose
    network-wide deliberately.

    Existing rows default to 'device', which is the narrower, safer reading of
    what their ``device_mac`` was always supposed to mean. Rules with no MAC
    are network-wide by definition and ignore this column.

``device_policies.pause_expires_at``
    A manual pause had no expiry, so it outlived the session that created it.
    The live database carried a pause set at 10:12 that was still dropping
    that phone's traffic hours later, across restarts, with nothing in the UI
    to explain it. Existing pauses are left as-is (NULL = until resumed)
    rather than silently expired.

Both use ALTER TABLE ADD COLUMN, which SQLite applies without rewriting the
table. Adding a column twice raises, so each is guarded by a column check —
migrations must be safe to re-run.
"""

import logging

from database.connection import get_connection

logger = logging.getLogger(__name__)


def _has_column(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def run():
    added = []
    with get_connection() as conn:
        cursor = conn.cursor()

        if not _has_column(cursor, "blocking_rules", "scope"):
            cursor.execute(
                "ALTER TABLE blocking_rules "
                "ADD COLUMN scope TEXT NOT NULL DEFAULT 'device'"
            )
            added.append("blocking_rules.scope")

        if not _has_column(cursor, "device_policies", "pause_expires_at"):
            cursor.execute(
                "ALTER TABLE device_policies "
                "ADD COLUMN pause_expires_at TIMESTAMP DEFAULT NULL"
            )
            added.append("device_policies.pause_expires_at")

        conn.commit()

    if added:
        logger.info("017: added %s", ", ".join(added))
    else:
        logger.info("017: columns already present")
