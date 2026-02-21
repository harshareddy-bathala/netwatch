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

    Retries up to 3 times with exponential backoff when the database is
    locked (common during startup when ARP scans cause heavy writes).
    """
    import time as _time

    max_retries = 3
    base_delay = 0.15  # 150 ms

    for attempt in range(max_retries):
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
        except sqlite3.OperationalError as e:
            # Retry on "database is locked" or "database is busy"
            if "locked" in str(e).lower() or "busy" in str(e).lower():
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        "create_alert: DB locked (attempt %d/%d), retrying in %.2fs",
                        attempt + 1, max_retries, delay,
                    )
                    _time.sleep(delay)
                    continue
            logger.error("create_alert error: %s", e)
            return None
        except sqlite3.Error as e:
            logger.error("create_alert error: %s", e)
            return None

    logger.error("create_alert: exhausted %d retries", max_retries)
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
# Aggregated stats (used by dashboard — replaces raw SQL in routes)
# ---------------------------------------------------------------------------

def get_alert_stats_aggregated() -> dict:
    """
    Return aggregated alert statistics for badge counts.

    Single query that returns total_unresolved, unacknowledged, and
    per-severity breakdowns.  Replaces the raw SQL that was in routes.py.
    """
    result = {
        'total_unresolved': 0,
        'unacknowledged': 0,
        'by_severity': {'critical': 0, 'warning': 0, 'info': 0},
    }
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity, COUNT(*) AS cnt,
                       SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) AS unack
                FROM alerts WHERE resolved = 0 GROUP BY severity
            """)
            for row in cursor.fetchall():
                sev = row['severity'] if isinstance(row, dict) else row[0]
                cnt = row['cnt'] if isinstance(row, dict) else row[1]
                unack = row['unack'] if isinstance(row, dict) else row[2]
                result['total_unresolved'] += cnt
                result['unacknowledged'] += (unack or 0)
                if sev in result['by_severity']:
                    result['by_severity'][sev] = cnt
    except sqlite3.Error as e:
        logger.error("get_alert_stats_aggregated error: %s", e)
    return result


# ---------------------------------------------------------------------------
# Alert rules CRUD (moved from routes.py — #29)
# ---------------------------------------------------------------------------

_VALID_METRICS = {'bandwidth_bps', 'device_count', 'packet_rate', 'protocol_bytes'}
_VALID_OPS = {'>', '<', '>=', '<=', '=='}
_VALID_SEV = {'info', 'warning', 'critical'}


def list_alert_rules() -> list:
    """List all custom alert rules."""
    try:
        with get_connection() as conn:
            cursor = conn.execute("SELECT * FROM alert_rules ORDER BY created_at DESC")
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("list_alert_rules error: %s", e)
        return []


def create_alert_rule(name: str, description: str, metric: str,
                      operator: str, threshold: float, severity: str,
                      cooldown_seconds: int = 300) -> Optional[int]:
    """Create a custom alert rule. Returns rule ID or None."""
    try:
        with get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO alert_rules (name, description, metric, operator, threshold, severity, cooldown_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, description, metric, operator, threshold, severity, cooldown_seconds))
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logger.error("create_alert_rule error: %s", e)
        return None


def update_alert_rule(rule_id: int, fields: dict) -> bool:
    """Update an alert rule. *fields* is a dict of column→value."""
    try:
        fields['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        set_clause = ', '.join(f'{k} = ?' for k in fields)
        values = list(fields.values()) + [rule_id]
        with get_connection() as conn:
            conn.execute(f"UPDATE alert_rules SET {set_clause} WHERE id = ?", values)
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error("update_alert_rule error: %s", e)
        return False


def delete_alert_rule(rule_id: int) -> bool:
    """Delete an alert rule."""
    try:
        with get_connection() as conn:
            conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.error("delete_alert_rule error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def delete_old_alerts(days: int = 7) -> int:
    """Delete resolved alerts older than *days* days based on creation timestamp."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("DELETE FROM alerts WHERE resolved = 1 AND timestamp < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount
    except sqlite3.Error as e:
        logger.error("delete_old_alerts error: %s", e)
        return 0
