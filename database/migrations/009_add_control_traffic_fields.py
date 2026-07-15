"""
009_add_control_traffic_fields.py
=================================

Phase 1 migration:
- Adds control-traffic marker on traffic_summary rows.
- Adds control byte counters on devices.
- Creates control/timestamp index for mixed analytics queries.

Safe to run multiple times.
"""

import logging

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def _column_names(cursor, table_name: str) -> set:
    """Return current column names for a table."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    cols = set()
    for row in cursor.fetchall():
        try:
            cols.add(row["name"])
        except Exception:
            cols.add(row[1])
    return cols


def run():
    """Apply control-traffic schema updates."""
    with get_connection() as conn:
        cursor = conn.cursor()

        traffic_cols = _column_names(cursor, "traffic_summary")
        if "is_control" not in traffic_cols:
            cursor.execute(
                "ALTER TABLE traffic_summary ADD COLUMN is_control INTEGER DEFAULT 0"
            )
            logger.info("009: added traffic_summary.is_control")

        device_cols = _column_names(cursor, "devices")
        if "control_bytes_sent" not in device_cols:
            cursor.execute(
                "ALTER TABLE devices ADD COLUMN control_bytes_sent INTEGER DEFAULT 0"
            )
            logger.info("009: added devices.control_bytes_sent")
        if "control_bytes_received" not in device_cols:
            cursor.execute(
                "ALTER TABLE devices ADD COLUMN control_bytes_received INTEGER DEFAULT 0"
            )
            logger.info("009: added devices.control_bytes_received")

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_control_timestamp "
            "ON traffic_summary(is_control, timestamp)"
        )

        # Optional backfill for existing control-protocol history.
        backfill_names = (
            "ARP",
            "DHCP",
            "DHCPV6",
            "IGMP",
            "MDNS",
            "LLMNR",
            "SSDP",
            "UPNPSSDP",
            "IPV6ND",
            "ICMPV6ND",
            "IPV6SLAAC",
            "SLAAC",
            "NDP",
        )
        placeholders = ",".join("?" for _ in backfill_names)
        cursor.execute(
            f"""
            UPDATE traffic_summary
            SET is_control = 1
            WHERE COALESCE(is_control, 0) = 0
              AND UPPER(REPLACE(COALESCE(protocol, ''), '-', '')) IN ({placeholders})
            """,
            backfill_names,
        )

        conn.commit()

    logger.info("009: control-traffic migration complete")


if __name__ == "__main__":
    run()
