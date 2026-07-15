"""
010_add_flow_tables.py
======================

Phase 0 (AI-first roadmap) migration:
- Adds the ``flows`` table (flow-level telemetry aggregated from packet
  batches by ``intelligence.flow_normalizer``).
- Adds the ``dns_queries`` table (per-device queried names).

These tables are the substrate for device-behavior learning, threat
detection, and the digital twin (ROADMAP.md, Phase 0 → Phase 1).

Safe to run multiple times.
"""

import logging

from database.db_handler import get_connection

logger = logging.getLogger(__name__)


def run():
    """Create flow-telemetry tables and their (minimal) indexes."""
    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                source_ip TEXT NOT NULL,
                dest_ip TEXT NOT NULL,
                source_port INTEGER DEFAULT NULL,
                dest_port INTEGER DEFAULT NULL,
                protocol TEXT NOT NULL DEFAULT 'UNKNOWN',
                direction TEXT DEFAULT 'unknown',
                source_mac TEXT DEFAULT NULL,
                dest_mac TEXT DEFAULT NULL,
                bytes_total INTEGER DEFAULT 0,
                packets_total INTEGER DEFAULT 0,
                is_control INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_flows_src_mac_seen "
            "ON flows(source_mac, last_seen)"
        )

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                source_ip TEXT DEFAULT NULL,
                source_mac TEXT DEFAULT NULL,
                qname TEXT NOT NULL,
                qtype INTEGER DEFAULT NULL,
                protocol TEXT DEFAULT 'DNS'
            )
        """)
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp "
            "ON dns_queries(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_dns_queries_qname "
            "ON dns_queries(qname)"
        )

        conn.commit()

    logger.info("010: flow-telemetry tables ready (flows, dns_queries)")


if __name__ == "__main__":
    run()
