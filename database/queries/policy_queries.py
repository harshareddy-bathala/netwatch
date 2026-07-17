"""
policy_queries.py - Device policies (parental controls / quotas, W5)
=====================================================================

CRUD for ``device_policies`` plus the **pure** enforcement decision
(``is_blocked_now`` / ``evaluate_blocked_macs``) that a periodic task
feeds to the DNS blocker. Keeping the decision pure (no DB, no clock)
makes the "should this device be blocked right now?" logic unit-testable.
"""

import json
import logging
import sqlite3
from datetime import datetime, time as dtime
from typing import Dict, List, Optional

from database.connection import get_connection

logger = logging.getLogger(__name__)


def _norm_mac(mac: Optional[str]) -> str:
    return (mac or "").lower().replace("-", ":").strip()


# --------------------------------------------------------------------------- #
#  Pure enforcement decision
# --------------------------------------------------------------------------- #

def _in_window(now: dtime, start: str, end: str) -> bool:
    """True if *now* falls in the daily [start, end) window, honoring windows
    that wrap past midnight (e.g. 22:00→07:00)."""
    try:
        sh, sm = map(int, start.split(":"))
        eh, em = map(int, end.split(":"))
    except (ValueError, AttributeError):
        return False
    s, e = dtime(sh, sm), dtime(eh, em)
    if s <= e:
        return s <= now < e
    return now >= s or now < e          # wraps midnight


def is_blocked_now(policy: dict, usage_bytes_today: int,
                   now: Optional[datetime] = None) -> Optional[str]:
    """Return a reason string if this device should be blocked right now,
    else None. Pure — the caller supplies today's usage and the clock.

    Order: manual pause → quota exceeded → inside a blocked (bedtime) window.
    """
    now = now or datetime.now()
    if policy.get("paused"):
        return "paused"

    quota_mb = policy.get("daily_quota_mb")
    if quota_mb:
        if usage_bytes_today >= int(quota_mb) * 1024 * 1024:
            return "quota_exceeded"

    windows = policy.get("blocked_windows")
    if windows:
        if isinstance(windows, str):
            try:
                windows = json.loads(windows)
            except ValueError:
                windows = []
        for w in windows or []:
            if _in_window(now.time(), w.get("start", ""), w.get("end", "")):
                return "schedule"
    return None


def evaluate_blocked_macs(policies: List[dict],
                          usage_by_mac: Dict[str, int],
                          now: Optional[datetime] = None) -> Dict[str, str]:
    """Map of {mac: reason} for every device currently blocked by policy."""
    out = {}
    for p in policies:
        mac = _norm_mac(p.get("device_mac"))
        if not mac:
            continue
        reason = is_blocked_now(p, usage_by_mac.get(mac, 0), now=now)
        if reason:
            out[mac] = reason
    return out


# --------------------------------------------------------------------------- #
#  CRUD
# --------------------------------------------------------------------------- #

def _row_to_policy(row, cols) -> dict:
    d = dict(zip(cols, row))
    if d.get("blocked_windows"):
        try:
            d["blocked_windows"] = json.loads(d["blocked_windows"])
        except (ValueError, TypeError):
            d["blocked_windows"] = []
    else:
        d["blocked_windows"] = []
    d["paused"] = bool(d.get("paused"))
    return d


def get_policies() -> List[dict]:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM device_policies ORDER BY updated_at DESC")
            cols = [c[0] for c in cur.description]
            return [_row_to_policy(r, cols) for r in cur.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_policies error: %s", e)
        return []


def get_policy(mac: str) -> Optional[dict]:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM device_policies WHERE LOWER(device_mac) = LOWER(?)",
                        (_norm_mac(mac),))
            row = cur.fetchone()
            if not row:
                return None
            return _row_to_policy(row, [c[0] for c in cur.description])
    except sqlite3.Error as e:
        logger.error("get_policy error: %s", e)
        return None


def upsert_policy(mac: str, paused: Optional[bool] = None,
                  daily_quota_mb: Optional[int] = None,
                  blocked_windows: Optional[list] = None,
                  note: Optional[str] = None) -> Optional[int]:
    """Create or update a device's policy. Only provided fields change."""
    mac = _norm_mac(mac)
    if not mac:
        return None
    windows_json = json.dumps(blocked_windows) if blocked_windows is not None else None
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            existing = get_policy(mac)
            if existing is None:
                cur.execute(
                    """INSERT INTO device_policies
                           (device_mac, paused, daily_quota_mb, blocked_windows, note)
                       VALUES (?, ?, ?, ?, ?)""",
                    (mac, 1 if paused else 0, daily_quota_mb, windows_json, note),
                )
            else:
                sets, params = ["updated_at = CURRENT_TIMESTAMP"], []
                if paused is not None:
                    sets.append("paused = ?"); params.append(1 if paused else 0)
                if daily_quota_mb is not None:
                    sets.append("daily_quota_mb = ?"); params.append(daily_quota_mb or None)
                if blocked_windows is not None:
                    sets.append("blocked_windows = ?"); params.append(windows_json)
                if note is not None:
                    sets.append("note = ?"); params.append(note)
                params.append(mac)
                cur.execute(
                    f"UPDATE device_policies SET {', '.join(sets)} "
                    f"WHERE LOWER(device_mac) = LOWER(?)", params)
            conn.commit()
            return cur.lastrowid
    except sqlite3.Error as e:
        logger.error("upsert_policy error: %s", e)
        return None


def delete_policy(mac: str) -> bool:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM device_policies WHERE LOWER(device_mac) = LOWER(?)",
                        (_norm_mac(mac),))
            conn.commit()
            return cur.rowcount > 0
    except sqlite3.Error as e:
        logger.error("delete_policy error: %s", e)
        return False


def get_usage_today_by_mac(since_midnight: Optional[str] = None) -> Dict[str, int]:
    """Per-device byte totals since local midnight, from the flows table."""
    if since_midnight is None:
        since_midnight = datetime.now().strftime("%Y-%m-%d 00:00:00")
    out: Dict[str, int] = {}
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """SELECT LOWER(source_mac) AS mac, SUM(bytes_total) AS b
                   FROM flows
                   WHERE last_seen >= ? AND source_mac IS NOT NULL
                   GROUP BY LOWER(source_mac)""",
                (since_midnight,),
            )
            for row in cur.fetchall():
                mac = row[0]
                if mac:
                    out[mac] = int(row[1] or 0)
    except sqlite3.Error as e:
        logger.error("get_usage_today_by_mac error: %s", e)
    return out
