"""
flow_queries.py - Flow & DNS Telemetry Queries (Phase 0, AI-first)
===================================================================

Persistence for the ``flows`` and ``dns_queries`` tables (migration 010).
Written by ``intelligence.flow_normalizer``; read by Phase 1+ consumers
(behavior profiles, threat detectors, investigations).

All writes are batched ``executemany`` calls, mirroring
``save_packets_batch`` conventions.
"""

import logging
import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional

from database.connection import get_connection

logger = logging.getLogger(__name__)


def save_flows_batch(flows: List[dict]) -> int:
    """Bulk-insert completed flow records.  Returns rows written (-1 on error)."""
    if not flows:
        return 0
    try:
        with get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO flows (
                    first_seen, last_seen, source_ip, dest_ip,
                    source_port, dest_port, protocol, direction,
                    source_mac, dest_mac, bytes_total, packets_total,
                    is_control, duration_seconds
                ) VALUES (
                    :first_seen, :last_seen, :source_ip, :dest_ip,
                    :source_port, :dest_port, :protocol, :direction,
                    :source_mac, :dest_mac, :bytes_total, :packets_total,
                    :is_control, :duration_seconds
                )
                """,
                flows,
            )
            conn.commit()
        return len(flows)
    except sqlite3.Error as e:
        logger.error("save_flows_batch error: %s", e)
        return -1


def save_dns_queries_batch(rows: List[dict]) -> int:
    """Bulk-insert DNS query events.  Returns rows written (-1 on error)."""
    if not rows:
        return 0
    try:
        with get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO dns_queries (timestamp, source_ip, source_mac,
                                         qname, qtype, protocol)
                VALUES (:timestamp, :source_ip, :source_mac,
                        :qname, :qtype, :protocol)
                """,
                rows,
            )
            conn.commit()
        return len(rows)
    except sqlite3.Error as e:
        logger.error("save_dns_queries_batch error: %s", e)
        return -1


def get_recent_flows(limit: int = 100, since: Optional[str] = None,
                     mac: Optional[str] = None) -> List[dict]:
    """Return recent flow records, newest first."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            clauses, params = [], []
            if since:
                clauses.append("last_seen >= ?")
                params.append(since)
            if mac:
                clauses.append("(source_mac = ? OR dest_mac = ?)")
                params.extend([mac, mac])
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            cursor.execute(
                f"""
                SELECT * FROM flows {where}
                ORDER BY last_seen DESC LIMIT ?
                """,
                (*params, int(limit)),
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_recent_flows error: %s", e)
        return []


def get_recent_dns_queries(limit: int = 100, since: Optional[str] = None,
                           mac: Optional[str] = None) -> List[dict]:
    """Return recent DNS query events, newest first."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            clauses, params = [], []
            if since:
                clauses.append("timestamp >= ?")
                params.append(since)
            if mac:
                clauses.append("source_mac = ?")
                params.append(mac)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            cursor.execute(
                f"""
                SELECT * FROM dns_queries {where}
                ORDER BY timestamp DESC LIMIT ?
                """,
                (*params, int(limit)),
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_recent_dns_queries error: %s", e)
        return []


def cleanup_old_flow_data(retention_hours: int = 72) -> dict:
    """Delete flow/DNS rows older than *retention_hours*.

    Called periodically by the flow normalizer thread (self-contained
    retention — no coupling to the maintenance module).
    """
    cutoff = (datetime.now() - timedelta(hours=retention_hours)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    result = {"flows_deleted": 0, "dns_deleted": 0}
    try:
        with get_connection() as conn:
            cur = conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
            result["flows_deleted"] = cur.rowcount or 0
            cur = conn.execute("DELETE FROM dns_queries WHERE timestamp < ?", (cutoff,))
            result["dns_deleted"] = cur.rowcount or 0
            conn.commit()
    except sqlite3.Error as e:
        logger.error("cleanup_old_flow_data error: %s", e)
    return result
