"""
011_add_behavior_profiles.py
============================

Phase 1 (AI-first roadmap) migration:
- Adds ``behavior_profiles`` — per-device learned baselines keyed by
  (mac_address, hour_of_week, metric), stored as Welford running
  statistics (count / mean / m2) so profiles update online without
  keeping raw history.

Consumed by ``intelligence.behavior.BehaviorAnalyzer``.

Safe to run multiple times.
"""

import logging

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def run():
    """Create the behavior_profiles table."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS behavior_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                hour_of_week INTEGER NOT NULL,   -- 0-167 (weekday*24 + hour)
                metric TEXT NOT NULL,            -- bytes / flows / unique_dests / dns_queries
                count INTEGER NOT NULL DEFAULT 0,
                mean REAL NOT NULL DEFAULT 0,
                m2 REAL NOT NULL DEFAULT 0,      -- Welford sum of squared deltas
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(mac_address, hour_of_week, metric)
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_behavior_profiles_mac "
            "ON behavior_profiles(mac_address)"
        )
        conn.commit()

    logger.info("011: behavior_profiles table ready")


if __name__ == "__main__":
    run()
