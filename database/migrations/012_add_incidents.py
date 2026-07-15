"""
012_add_incidents.py
====================

Phase 2 (AI-first roadmap) migration:
- Adds ``incidents`` — fused groups of related alerts.  Alerts that hit
  the same device (or the network at large) inside a rolling window
  belong to one incident instead of scrolling past as disconnected rows,
  fixing the dedup-by-type weakness called out in the roadmap.
- Adds ``alerts.incident_id`` so member alerts point at their incident.

Consumed by ``intelligence.incidents.IncidentManager``.

Safe to run multiple times.
"""

import logging

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def run():
    """Create the incidents table and link column on alerts."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN ('open', 'resolved')),
                severity TEXT NOT NULL DEFAULT 'info'
                    CHECK(severity IN ('info', 'low', 'medium', 'warning',
                                       'high', 'critical')),
                title TEXT NOT NULL,
                device_mac TEXT DEFAULT NULL,    -- NULL = network-wide
                alert_count INTEGER NOT NULL DEFAULT 0,
                categories TEXT DEFAULT NULL,    -- JSON array of alert types
                summary TEXT DEFAULT NULL
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_status_updated "
            "ON incidents(status, updated_at)"
        )

        # alerts.incident_id — ALTER TABLE ADD COLUMN is not idempotent,
        # so check the schema first.
        cursor.execute("PRAGMA table_info(alerts)")
        columns = {row[1] for row in cursor.fetchall()}
        if "incident_id" not in columns:
            cursor.execute(
                "ALTER TABLE alerts ADD COLUMN incident_id INTEGER "
                "REFERENCES incidents(id)"
            )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_incident "
            "ON alerts(incident_id)"
        )
        conn.commit()

    logger.info("012: incidents table + alerts.incident_id ready")


if __name__ == "__main__":
    run()
