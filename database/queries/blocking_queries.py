"""
blocking_queries.py - Client Blocking Policy (migration 013)
============================================================

CRUD for ``blocking_rules``: the admin-defined list of domains clients may
not resolve.  Enforced by ``packet_capture.dns_blocker``.

A rule with ``device_mac`` NULL applies to every client; otherwise to that
one client.  Domains are stored normalised (lowercase, no trailing dot, no
scheme/path) so that matching is a plain suffix test at enforcement time.
"""

import logging
import re
import sqlite3
from typing import List, Optional

from database.connection import get_connection

logger = logging.getLogger(__name__)

# Hostnames only (no scheme, port or path) — we are matching DNS QNAMEs, so
# anything that cannot appear in one is rejected. Labels may not start or end
# with a hyphen, and the last one must be alphabetic, which also rejects a
# bare IP address (blocking one is a firewall job, not a DNS one).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z]{2,63}$"
)


def normalize_domain(raw: str) -> Optional[str]:
    """Reduce user input to a bare DNS name, or None if it isn't one.

    Accepts what an admin would realistically paste — ``https://Instagram.com/``,
    ``www.Instagram.com.`` — and returns ``instagram.com`` / ``www.instagram.com``.
    """
    if not raw:
        return None
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)   # strip scheme
    d = d.split("/", 1)[0]             # strip path
    d = d.split("?", 1)[0]
    d = d.split(":", 1)[0]             # strip port
    d = d.rstrip(".")                  # strip root label
    if not d or not _DOMAIN_RE.match(d):
        return None
    return d


def normalize_mac(raw: Optional[str]) -> Optional[str]:
    """Lowercase colon-form MAC, or None for a network-wide rule."""
    if not raw:
        return None
    m = raw.strip().lower().replace("-", ":")
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", m):
        return None
    return m


VALID_SCOPES = ("device", "network")


def normalize_scope(raw: Optional[str], device_mac: Optional[str]) -> str:
    """Resolve the requested enforcement breadth.

    A rule with no MAC is network-wide by definition — there is no device to
    scope it to — so it reports 'network' whatever was asked for. Otherwise an
    unrecognised value falls back to 'device': the narrow reading, because
    over-blocking silently is the failure that hurts.
    """
    if not device_mac:
        return "network"
    s = (raw or "").strip().lower()
    return s if s in VALID_SCOPES else "device"


def add_rule(domain: str, device_mac: Optional[str] = None,
             note: Optional[str] = None,
             scope: Optional[str] = None) -> Optional[dict]:
    """Create (or re-enable) a blocking rule.  Returns the rule, or None if
    *domain* isn't a valid DNS name."""
    d = normalize_domain(domain)
    if not d:
        return None
    mac = normalize_mac(device_mac)
    scope_val = normalize_scope(scope, mac)
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            # Re-adding an existing rule re-enables it rather than erroring —
            # that is what "block this again" means from the UI.
            cur.execute(
                """
                INSERT INTO blocking_rules (domain, device_mac, note, scope)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain, COALESCE(device_mac, '')) DO UPDATE SET
                    enabled = 1,
                    note = COALESCE(excluded.note, note),
                    scope = excluded.scope
                """,
                (d, mac, note, scope_val),
            )
            conn.commit()
            cur.execute(
                "SELECT * FROM blocking_rules "
                "WHERE domain = ? AND COALESCE(device_mac, '') = ?",
                (d, mac or ""),
            )
            row = cur.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error("add_rule error: %s", e)
        return None


def delete_rule(rule_id: int) -> bool:
    """Remove a rule entirely.  Returns True if a row was deleted."""
    try:
        with get_connection() as conn:
            cur = conn.execute("DELETE FROM blocking_rules WHERE id = ?", (int(rule_id),))
            conn.commit()
            return (cur.rowcount or 0) > 0
    except sqlite3.Error as e:
        logger.error("delete_rule error: %s", e)
        return False


def set_rule_enabled(rule_id: int, enabled: bool) -> bool:
    """Toggle a rule without losing it.  Returns True if a row changed."""
    try:
        with get_connection() as conn:
            cur = conn.execute(
                "UPDATE blocking_rules SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, int(rule_id)),
            )
            conn.commit()
            return (cur.rowcount or 0) > 0
    except sqlite3.Error as e:
        logger.error("set_rule_enabled error: %s", e)
        return False


def get_rules(enabled_only: bool = False) -> List[dict]:
    """All blocking rules, with the client's friendly name joined in."""
    where = "WHERE r.enabled = 1" if enabled_only else ""
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(f"""
                SELECT r.id, r.created_at, r.domain, r.device_mac, r.enabled,
                       r.hit_count, r.last_hit, r.note,
                       -- A MAC-less rule is network-wide however it is stored.
                       CASE WHEN r.device_mac IS NULL OR r.device_mac = ''
                            THEN 'network' ELSE r.scope END AS scope,
                       COALESCE(NULLIF(d.hostname, ''),
                                NULLIF(d.device_name, '')) AS device_name
                FROM blocking_rules r
                LEFT JOIN devices d
                    ON LOWER(d.mac_address) = LOWER(r.device_mac)
                {where}
                ORDER BY r.created_at DESC
            """)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_rules error: %s", e)
        return []


def record_hits(counts: dict) -> None:
    """Bump hit_count/last_hit for {rule_id: n}.

    Called from the blocker's sender thread, batched — a blocked client can
    retry a lookup many times per second and we do not want a write per packet.
    """
    if not counts:
        return
    try:
        with get_connection() as conn:
            conn.executemany(
                "UPDATE blocking_rules "
                "SET hit_count = hit_count + ?, last_hit = datetime('now') "
                "WHERE id = ?",
                [(int(n), int(rid)) for rid, n in counts.items()],
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error("record_hits error: %s", e)
