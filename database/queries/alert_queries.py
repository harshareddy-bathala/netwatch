"""
alert_queries.py - Alert CRUD Operations
==========================================

Create, query, acknowledge, and resolve alerts.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict

from database.connection import get_connection, dict_from_row

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_alert(alert_type: str, severity: str, message: str,
                 details: str = None, source_ip: str = None,
                 dest_ip: str = None, metadata: str = None) -> Optional[int]:
    """
    Insert a new alert.  Returns the alert id or *None* on failure.

    *metadata* is stored in the ``details`` column when *details* is not
    provided (keeps backward compatibility with callers that pass
    ``metadata`` instead of ``details``).
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts
                    (timestamp, alert_type, severity, message, details, source_ip, dest_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                alert_type, severity, message,
                details or metadata,
                source_ip, dest_ip,
            ))
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logger.error("create_alert error: %s", e)
        return None


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_alerts(limit: int = 50, severity: str = None,
               include_resolved: bool = False,
               acknowledged: bool = None) -> List[dict]:
    """Query alerts with optional filters, ordered by newest first."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts WHERE 1=1"
            params: list = []

            if not include_resolved:
                query += " AND resolved = 0"
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if acknowledged is not None:
                query += " AND acknowledged = ?"
                params.append(1 if acknowledged else 0)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict_from_row(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        logger.error("get_alerts error: %s", e)
        return []


def get_alert_by_id(alert_id: int) -> Optional[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            return dict_from_row(cursor.fetchone())
    except sqlite3.Error as e:
        logger.error("get_alert_by_id error: %s", e)
        return None


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

def acknowledge_alert(alert_id: int) -> bool:
    """Mark alert as seen (but not resolved)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alerts SET acknowledged = 1, acknowledged_at = ?
                WHERE id = ?
            """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), alert_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error("acknowledge_alert error: %s", e)
        return False


def resolve_alert(alert_id: int, resolved_by: str = None) -> bool:
    """Mark alert as fully resolved."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alerts SET resolved = 1, resolved_at = ?, resolved_by = ?
                WHERE id = ?
            """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), resolved_by, alert_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error("resolve_alert error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------

def count_alerts(resolved: bool = False, severity: str = None,
                 acknowledged: bool = None) -> int:
    """Count alerts matching the given filters (for badge counts).

    Parameters
    ----------
    resolved : bool
        Filter by resolved state (default False = unresolved).
    severity : str, optional
        Filter by severity level.
    acknowledged : bool, optional
        If provided, filter by acknowledged state.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT COUNT(*) AS cnt FROM alerts WHERE resolved = ?"
            params: list = [1 if resolved else 0]
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if acknowledged is not None:
                query += " AND acknowledged = ?"
                params.append(1 if acknowledged else 0)
            cursor.execute(query, params)
            row = cursor.fetchone()
            return row["cnt"] if row else 0
    except sqlite3.Error as e:
        logger.error("count_alerts error: %s", e)
        return 0


def get_alert_counts() -> dict:
    """Counts of **unresolved** alerts grouped by severity."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity, COUNT(*) AS count
                FROM alerts WHERE resolved = 0 GROUP BY severity
            """)
            counts = {"info": 0, "low": 0, "medium": 0, "warning": 0,
                       "high": 0, "critical": 0, "total": 0}
            for row in cursor.fetchall():
                counts[row["severity"]] = row["count"]
                counts["total"] += row["count"]
            return counts
    except sqlite3.Error as e:
        logger.error("get_alert_counts error: %s", e)
        return {"total": 0, "error": str(e)}


def get_alert_summary() -> dict:
    """Summary including unacknowledged counts (for dashboard)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity,
                       COUNT(*) AS count,
                       SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) AS unacknowledged
                FROM alerts WHERE resolved = 0 GROUP BY severity
            """)
            summary = {"critical": 0, "high": 0, "warning": 0, "medium": 0,
                        "info": 0, "low": 0, "total": 0, "unacknowledged": 0}
            for row in cursor.fetchall():
                sev = row["severity"] or "info"
                cnt = row["count"] or 0
                unack = row["unacknowledged"] or 0
                summary[sev] = cnt
                summary["total"] += cnt
                summary["unacknowledged"] += unack
            return summary
    except sqlite3.Error as e:
        logger.error("get_alert_summary error: %s", e)
        return {"total": 0, "error": str(e)}


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def delete_old_alerts(days: int = 7) -> int:
    """Delete resolved alerts older than *days* days."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("DELETE FROM alerts WHERE resolved = 1 AND resolved_at < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount
    except sqlite3.Error as e:
        logger.error("delete_old_alerts error: %s", e)
        return 0
