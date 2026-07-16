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
import time
from datetime import datetime, timedelta
from typing import List, Optional

from database.connection import get_connection

logger = logging.getLogger(__name__)

# Lock-retry policy — mirrors alert_queries/packet_store: SQLite allows one
# writer, and flow flushes race the packet-batch writer during busy periods.
_MAX_RETRIES = 3
_BASE_DELAY = 0.15  # seconds, doubled per attempt


def _executemany_with_retry(label: str, sql: str, rows: List[dict]) -> int:
    """Run a batched INSERT with retry on 'database is locked'.

    Returns rows written, or -1 after exhausting retries / on error.
    """
    for attempt in range(_MAX_RETRIES):
        try:
            with get_connection() as conn:
                conn.executemany(sql, rows)
                conn.commit()
            return len(rows)
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if ("locked" in msg or "busy" in msg) and attempt < _MAX_RETRIES - 1:
                delay = _BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "%s: DB locked (attempt %d/%d), retrying in %.2fs",
                    label, attempt + 1, _MAX_RETRIES, delay,
                )
                time.sleep(delay)
                continue
            logger.error("%s error: %s", label, e)
            return -1
        except sqlite3.Error as e:
            logger.error("%s error: %s", label, e)
            return -1
    return -1


def save_flows_batch(flows: List[dict]) -> int:
    """Bulk-insert completed flow records.  Returns rows written (-1 on error)."""
    if not flows:
        return 0
    return _executemany_with_retry(
        "save_flows_batch",
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


def save_dns_queries_batch(rows: List[dict]) -> int:
    """Bulk-insert DNS query events.  Returns rows written (-1 on error)."""
    if not rows:
        return 0
    return _executemany_with_retry(
        "save_dns_queries_batch",
        """
        INSERT INTO dns_queries (timestamp, source_ip, source_mac,
                                 qname, qtype, protocol)
        VALUES (:timestamp, :source_ip, :source_mac,
                :qname, :qtype, :protocol)
        """,
        rows,
    )


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


def get_recent_activity(minutes: int = 5, limit: int = 300,
                        mac: Optional[str] = None) -> List[dict]:
    """Recent DNS resolutions enriched with the client's friendly name.

    Powers the live "Activity" feed: each row is one domain a client
    looked up (a good proxy for the site/app it is using), joined to the
    ``devices`` table so the UI can show "moto-g34-5G → instagram.com"
    instead of a bare MAC. Newest first, within the last *minutes*.
    """
    # dns_queries timestamps are written in *local* time
    # (packet_processor uses datetime.fromtimestamp), so the cutoff must be
    # local too — using UTC here would offset the window by the local tz.
    since = (datetime.now() - timedelta(minutes=max(1, minutes))).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    clauses = ["q.timestamp >= ?"]
    params: list = [since]
    if mac:
        clauses.append("LOWER(q.source_mac) = LOWER(?)")
        params.append(mac)
    where = "WHERE " + " AND ".join(clauses)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT
                    q.timestamp                            AS timestamp,
                    q.source_ip                            AS source_ip,
                    q.source_mac                           AS source_mac,
                    q.qname                                AS qname,
                    q.qtype                                AS qtype,
                    COALESCE(NULLIF(d.hostname, ''),
                             NULLIF(d.device_name, ''))    AS device_name
                FROM dns_queries q
                LEFT JOIN devices d
                    ON LOWER(d.mac_address) = LOWER(q.source_mac)
                {where}
                ORDER BY q.timestamp DESC
                LIMIT ?
                """,
                (*params, int(limit)),
            )
            cols = [c[0] for c in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_recent_activity error: %s", e)
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
