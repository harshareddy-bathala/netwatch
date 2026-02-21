"""
007_extend_alert_type_check.py
===============================

Extends the alerts table CHECK constraint on ``alert_type`` to include
'custom' (for user-created alerts via POST /api/alerts).

SQLite does not support ALTER TABLE … ALTER COLUMN, so we recreate the
table with the new constraint and copy existing data across.

Also adds forward-compatible fine-grained health types
('health_cpu', 'health_memory', 'health_db') so that future versions
can use them without another migration.
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
    """Recreate alerts table with extended alert_type CHECK constraint."""
    try:
        from config import DATABASE_PATH as _db_path
        db_path = _db_path
    except Exception:
        db_path = DATABASE_PATH

    conn = sqlite3.connect(db_path, timeout=30)
    cursor = conn.cursor()

    try:
        # Check if alerts table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
        )
        if not cursor.fetchone():
            logger.info("007: alerts table does not exist yet – skipping migration")
            return

        logger.info("007: Extending alert_type CHECK constraint to include 'custom' and health subtypes")

        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("BEGIN TRANSACTION")

        # Create new table with extended CHECK constraint
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL CHECK(alert_type IN (
                    'bandwidth', 'anomaly', 'device_count', 'health',
                    'protocol', 'connection', 'security', 'new_device',
                    'custom',
                    'health_cpu', 'health_memory', 'health_db'
                )),
                severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'warning', 'high', 'critical')),
                message TEXT NOT NULL,
                details TEXT DEFAULT NULL,
                source_ip TEXT DEFAULT NULL,
                dest_ip TEXT DEFAULT NULL,
                resolved INTEGER DEFAULT 0,
                resolved_at TIMESTAMP DEFAULT NULL,
                resolved_by TEXT DEFAULT NULL,
                acknowledged INTEGER DEFAULT 0,
                acknowledged_at TIMESTAMP DEFAULT NULL
            )
        """)

        # Copy data
        cursor.execute("""
            INSERT INTO alerts_new (
                id, timestamp, alert_type, severity, message, details,
                source_ip, dest_ip, resolved, resolved_at, resolved_by,
                acknowledged, acknowledged_at
            )
            SELECT
                id, timestamp, alert_type, severity, message, details,
                source_ip, dest_ip, resolved, resolved_at, resolved_by,
                acknowledged, acknowledged_at
            FROM alerts
        """)

        # Swap tables
        cursor.execute("DROP TABLE alerts")
        cursor.execute("ALTER TABLE alerts_new RENAME TO alerts")

        # Recreate indexes that existed on the old table
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp DESC)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_resolved
            ON alerts(resolved)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_type_sev_ts
            ON alerts(alert_type, severity, timestamp DESC)
        """)

        conn.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
        logger.info("007: alert_type CHECK constraint extended successfully")

    except Exception as e:
        conn.rollback()
        logger.warning("007: Migration failed (non-fatal): %s", e)
    finally:
        conn.close()
