"""
014_add_device_policies.py
==========================

Adds ``device_policies`` — per-client parental controls / quotas (W5),
enforced (in hotspot mode) by the DNS blocker:

* ``paused``          — manual "pause internet for this device" toggle.
* ``daily_quota_mb``  — block the device once its usage-today crosses this.
* ``blocked_windows`` — JSON list of daily time ranges to block (bedtime),
  e.g. ``[{"start": "22:00", "end": "07:00"}]``.

Enforcement is the same DNS-sinkhole mechanism as ``blocking_rules`` but at
the whole-device level; a periodic evaluator computes which MACs are
currently blocked and pushes the set to the blocker.

Safe to run multiple times.
"""

import logging

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def run():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT NOT NULL UNIQUE,
                paused INTEGER NOT NULL DEFAULT 0,
                daily_quota_mb INTEGER DEFAULT NULL,
                blocked_windows TEXT DEFAULT NULL,
                note TEXT DEFAULT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    logger.info("014: device_policies table ready")


if __name__ == "__main__":
    run()
