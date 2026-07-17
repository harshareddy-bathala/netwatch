"""
incident_queries.py - Incident CRUD Operations (Phase 2)
=========================================================

Persistence for alert→incident fusion.  An incident groups related
alerts (same device or network-wide) that arrive inside a rolling
window; see ``intelligence.incidents.IncidentManager`` for the fusion
rules.
"""

import json
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

from database.connection import get_connection, dict_from_row

logger = logging.getLogger(__name__)

_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _now() -> str:
    return datetime.now().strftime(_TS_FMT)


# ---------------------------------------------------------------------------
# Create / attach
# ---------------------------------------------------------------------------

def create_incident(title: str, severity: str,
                    device_mac: Optional[str] = None,
                    categories: Optional[List[str]] = None,
                    summary: Optional[str] = None) -> Optional[int]:
    """Insert a new open incident; returns its id or None on failure."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = _now()
            cursor.execute("""
                INSERT INTO incidents
                    (created_at, updated_at, status, severity, title,
                     device_mac, alert_count, categories, summary)
                VALUES (?, ?, 'open', ?, ?, ?, 0, ?, ?)
            """, (now, now, severity, title, device_mac,
                  json.dumps(categories or []), summary))
            conn.commit()
            return cursor.lastrowid
    except sqlite3.Error as e:
        logger.error("create_incident error: %s", e)
        return None


def attach_alert(incident_id: int, alert_id: int, severity: str,
                 categories: List[str], summary: Optional[str] = None) -> bool:
    """Link *alert_id* to *incident_id* and refresh incident rollups.

    When *summary* is given it replaces the incident summary so the
    headline reflects the fused total (e.g. "3 alerts…") rather than a
    stale copy of the first alert's message.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET incident_id = ? WHERE id = ?",
                (incident_id, alert_id),
            )
            if summary is not None:
                cursor.execute("""
                    UPDATE incidents
                    SET updated_at = ?,
                        alert_count = alert_count + 1,
                        severity = ?,
                        categories = ?,
                        summary = ?
                    WHERE id = ?
                """, (_now(), severity, json.dumps(categories), summary,
                      incident_id))
            else:
                cursor.execute("""
                    UPDATE incidents
                    SET updated_at = ?,
                        alert_count = alert_count + 1,
                        severity = ?,
                        categories = ?
                    WHERE id = ?
                """, (_now(), severity, json.dumps(categories), incident_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error("attach_alert error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def find_open_incident(device_mac: Optional[str],
                       updated_since: str,
                       category: Optional[str] = None) -> Optional[dict]:
    """Most recent open incident for *device_mac* touched after
    *updated_since* (``NULL`` mac matches only network-wide incidents).

    Network-wide (NULL-mac) incidents additionally require a *category*
    match when one is given: without a device to anchor on, category is
    the only evidence two alerts tell the same story — a health alert
    must not fuse into an unrelated security incident."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if device_mac:
                cursor.execute("""
                    SELECT * FROM incidents
                    WHERE status = 'open' AND device_mac = ?
                      AND updated_at >= ?
                    ORDER BY updated_at DESC LIMIT 1
                """, (device_mac, updated_since))
            elif category:
                cursor.execute("""
                    SELECT * FROM incidents
                    WHERE status = 'open' AND device_mac IS NULL
                      AND updated_at >= ?
                      AND categories LIKE ?
                    ORDER BY updated_at DESC LIMIT 1
                """, (updated_since, f'%"{category}"%'))
            else:
                cursor.execute("""
                    SELECT * FROM incidents
                    WHERE status = 'open' AND device_mac IS NULL
                      AND updated_at >= ?
                    ORDER BY updated_at DESC LIMIT 1
                """, (updated_since,))
            row = cursor.fetchone()
            return _shape(dict_from_row(row)) if row else None
    except sqlite3.Error as e:
        logger.error("find_open_incident error: %s", e)
        return None


def get_incidents(status: Optional[str] = None, limit: int = 50) -> List[dict]:
    """List incidents, newest activity first."""
    limit = max(1, min(int(limit), 500))
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("""
                    SELECT * FROM incidents WHERE status = ?
                    ORDER BY updated_at DESC LIMIT ?
                """, (status, limit))
            else:
                cursor.execute("""
                    SELECT * FROM incidents
                    ORDER BY updated_at DESC LIMIT ?
                """, (limit,))
            return [_shape(dict_from_row(row)) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_incidents error: %s", e)
        return []


def get_incident(incident_id: int) -> Optional[dict]:
    """One incident with its member alerts, oldest alert first."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            incident = _shape(dict_from_row(row))
            cursor.execute("""
                SELECT id, timestamp, alert_type, severity, message, details
                FROM alerts WHERE incident_id = ?
                ORDER BY timestamp ASC, id ASC
            """, (incident_id,))
            incident["alerts"] = [dict_from_row(r) for r in cursor.fetchall()]
            return incident
    except sqlite3.Error as e:
        logger.error("get_incident error: %s", e)
        return None


def _shape(incident: dict) -> dict:
    """Decode the categories JSON column in place."""
    try:
        incident["categories"] = json.loads(incident.get("categories") or "[]")
    except (TypeError, ValueError):
        incident["categories"] = []
    return incident


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

def resolve_incident(incident_id: int) -> bool:
    """Mark an incident resolved (member alerts are left untouched)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incidents SET status = 'resolved', updated_at = ?
                WHERE id = ? AND status = 'open'
            """, (_now(), incident_id))
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        logger.error("resolve_incident error: %s", e)
        return False
