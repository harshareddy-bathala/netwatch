"""
stats_queries.py - Real-time Statistics & Dashboard
=====================================================

Aggregated stats endpoints that power the dashboard.
All device counts route through ``get_active_device_count()``
from ``device_queries`` so the number is consistent everywhere.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List

from database.connection import get_connection, dict_from_row
from utils.query_cache import time_query, TTLCache
from database.queries.device_queries import (
    get_active_device_count,
    _PRIVATE_IP_FILTER_SOURCE,
    _PRIVATE_IP_FILTER_DEST,
    _VALID_MAC_FILTER_SOURCE,
    _VALID_MAC_FILTER_DEST,
    _detect_subnet,
    _current_mode_name,
    VALID_DEVICE_IP_FILTER,
)
from database.queries.traffic_queries import (
    get_bandwidth_history,
    get_protocol_distribution,
)
from database.queries.alert_queries import (
    get_alerts,
    get_alert_counts,
)

logger = logging.getLogger(__name__)

# Cache for dashboard data (5s TTL matches frontend poll interval)
_stats_cache = TTLCache(ttl_seconds=5)


# ---------------------------------------------------------------------------
# Real-time stats
# ---------------------------------------------------------------------------

@time_query
def get_realtime_stats(live_bandwidth_bps: float = None) -> dict:
    """
    Current network snapshot used by the dashboard.

    * Bandwidth: uses *live_bandwidth_bps* from CaptureEngine when
      available, otherwise falls back to bytes in the last 10 s from DB.
    * Device count: routed through :func:`get_active_device_count`
    * Today's totals

    Args:
        live_bandwidth_bps: Real-time bytes/s from BandwidthCalculator.
                            If provided, overrides the DB-derived value.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now()
            ten_secs = (now - timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")

            # Last 10 seconds — with upload/download breakdown
            cursor.execute("""
                SELECT
                    SUM(bytes_transferred) AS bytes,
                    COUNT(*) AS packets,
                    SUM(CASE WHEN direction = 'download' THEN bytes_transferred ELSE 0 END) AS dl_bytes,
                    SUM(CASE WHEN direction = 'upload'   THEN bytes_transferred ELSE 0 END) AS ul_bytes
                FROM traffic_summary WHERE timestamp >= ?
            """, (ten_secs,))
            recent = cursor.fetchone()
            bytes_recent = (recent["bytes"] or 0) if recent else 0
            packets_recent = (recent["packets"] or 0) if recent else 0
            dl_bytes_recent = (recent["dl_bytes"] or 0) if recent else 0
            ul_bytes_recent = (recent["ul_bytes"] or 0) if recent else 0
            bandwidth_bps = bytes_recent / 10
            download_bps = dl_bytes_recent / 10
            upload_bps = ul_bytes_recent / 10

            # Active devices — INLINE the query to avoid a nested
            # get_connection() call which causes pool exhaustion.
            # Uses the same logic as get_active_device_count() but
            # reuses the connection we already hold.
            five_min_ago = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            current_subnet = _detect_subnet()
            skip_subnet = _current_mode_name in ("port_mirror", "hotspot")
            sf_src = sf_dst = sf_dev = ""
            sp_src = [five_min_ago]
            sp_dst = [five_min_ago]
            sp_dev = [five_min_ago]
            if current_subnet and not skip_subnet:
                sf_src = "AND source_ip LIKE ?"
                sf_dst = "AND dest_ip LIKE ?"
                sf_dev = "AND ip_address LIKE ?"
                sp_src.append(f"{current_subnet}.%")
                sp_dst.append(f"{current_subnet}.%")
                sp_dev.append(f"{current_subnet}.%")

            cursor.execute(f"""
                SELECT COUNT(DISTINCT ip_address) AS count
                FROM (
                    SELECT source_ip AS ip_address
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        AND ({_PRIVATE_IP_FILTER_SOURCE})
                        {sf_src}
                    UNION
                    SELECT dest_ip AS ip_address
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_DEST}
                        AND ({_PRIVATE_IP_FILTER_DEST})
                        {sf_dst}
                    UNION
                    SELECT ip_address
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {VALID_DEVICE_IP_FILTER}
                        {sf_dev}
                )
            """, (*sp_src, *sp_dst, *sp_dev))
            dev_row = cursor.fetchone()
            active_devices = dev_row["count"] if dev_row else 0

            # Today totals
            cursor.execute("""
                SELECT SUM(bytes_transferred) AS bytes, COUNT(*) AS packets
                FROM traffic_summary WHERE timestamp >= ?
            """, (today_start,))
            today = cursor.fetchone()

            # Use live bandwidth if provided, otherwise fall back to DB
            effective_bps = live_bandwidth_bps if live_bandwidth_bps is not None else bandwidth_bps

            # Convert to Mbps for frontend
            effective_mbps = round((effective_bps * 8) / 1_000_000, 4)
            download_mbps = round((download_bps * 8) / 1_000_000, 4)
            upload_mbps = round((upload_bps * 8) / 1_000_000, 4)

            return {
                "bandwidth_bps": round(effective_bps, 2),
                "bandwidth_mbps": effective_mbps,
                "download_bps": round(download_bps, 2),
                "download_mbps": download_mbps,
                "upload_bps": round(upload_bps, 2),
                "upload_mbps": upload_mbps,
                "active_devices": active_devices,
                "packets_per_second": round(packets_recent / 10, 2),
                "total_bytes_today": (today["bytes"] or 0) if today else 0,
                "total_packets_today": (today["packets"] or 0) if today else 0,
                "timestamp": now.isoformat(),
            }

    except sqlite3.Error as e:
        logger.error("get_realtime_stats error: %s", e)
        return {
            "bandwidth_bps": 0, "bandwidth_mbps": 0,
            "download_bps": 0, "download_mbps": 0,
            "upload_bps": 0, "upload_mbps": 0,
            "active_devices": 0, "packets_per_second": 0,
            "total_bytes_today": 0, "total_packets_today": 0,
            "timestamp": datetime.now().isoformat(), "error": str(e),
        }


# ---------------------------------------------------------------------------
# Health score
# ---------------------------------------------------------------------------

@time_query
def get_health_score() -> dict:
    """
    Network health 0 – 100.

    Factors:
    * Unresolved critical / warning alerts
    * Traffic presence
    * Device connectivity

    Device count is sourced from ``get_active_device_count()``.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now()
            one_hour = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

            # Consolidated: critical + warning counts in a single query
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS critical_count,
                    SUM(CASE WHEN severity IN ('warning', 'medium') THEN 1 ELSE 0 END) AS warning_count
                FROM alerts
                WHERE resolved = 0
            """)
            alert_row = cursor.fetchone()
            critical_alerts = (alert_row["critical_count"] or 0) if alert_row else 0
            warning_alerts = (alert_row["warning_count"] or 0) if alert_row else 0

            # Device count — SINGLE SOURCE OF TRUTH (using shared SQL fragments)
            # Also includes devices from the devices table (ARP-discovered)
            five_min_ago = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            from database.queries.device_queries import VALID_DEVICE_IP_FILTER as _VDIF_HS
            cursor.execute(f"""
                SELECT COUNT(DISTINCT mac_address) AS count
                FROM (
                    SELECT source_mac AS mac_address
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_SOURCE}
                        AND ({_PRIVATE_IP_FILTER_SOURCE})
                    UNION
                    SELECT dest_mac AS mac_address
                    FROM traffic_summary
                    WHERE timestamp >= ?
                        AND {_VALID_MAC_FILTER_DEST}
                        AND ({_PRIVATE_IP_FILTER_DEST})
                    UNION
                    SELECT mac_address
                    FROM devices
                    WHERE last_seen >= ?
                        AND mac_address IS NOT NULL AND mac_address != ''
                        AND mac_address != 'ff:ff:ff:ff:ff:ff'
                        AND mac_address != '00:00:00:00:00:00'
                        AND {_VDIF_HS}
                )
            """, (five_min_ago, five_min_ago, five_min_ago))
            device_count = (cursor.fetchone()["count"] or 0)

            # Traffic in last hour
            cursor.execute("""
                SELECT COUNT(*) AS count FROM traffic_summary WHERE timestamp >= ?
            """, (one_hour,))
            traffic_count = (cursor.fetchone()["count"] or 0)

            # --- Score ---
            score = 100
            factors: List[str] = []

            crit_penalty = min(critical_alerts * 15, 45)
            if crit_penalty:
                score -= crit_penalty
                factors.append(f"-{crit_penalty} pts: {critical_alerts} critical alert(s)")

            warn_penalty = min(warning_alerts * 3, 15)
            if warn_penalty:
                score -= warn_penalty
                factors.append(f"-{warn_penalty} pts: {warning_alerts} warning alert(s)")

            if traffic_count:
                factors.append(f"✓ Traffic monitoring active ({traffic_count:,} packets/hr)")
            else:
                score -= 5
                factors.append("-5 pts: No traffic detected in last hour")

            if device_count:
                factors.append(f"✓ {device_count} device(s) connected")

            score = max(0, min(100, score))
            status = "good" if score >= 80 else ("warning" if score >= 50 else "critical")

            return {
                "score": score,
                "status": status,
                "factors": factors,
                "device_count": device_count,
                "traffic_count": traffic_count,
                "critical_alerts": critical_alerts,
                "warning_alerts": warning_alerts,
                "timestamp": now.isoformat(),
            }

    except sqlite3.Error as e:
        logger.error("get_health_score error: %s", e)
        return {
            "score": 0, "status": "unknown",
            "factors": [f"Error: {e}"],
            "timestamp": datetime.now().isoformat(),
        }


# ---------------------------------------------------------------------------
# Dashboard aggregate
# ---------------------------------------------------------------------------

@time_query
def get_dashboard_data() -> dict:
    """
    All data the dashboard needs in a **single DB connection**.

    Previously this called 7 separate functions each acquiring their own pool
    connection. Now we do everything inside one ``with get_connection()`` block,
    reducing pool contention and eliminating 6 extra connection round-trips.
    """
    from database.queries.device_queries import get_top_devices

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now()
            ten_secs = (now - timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")
            one_hour = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S")

            # ── 1. Realtime stats ──────────────────────────────────────
            cursor.execute("""
                SELECT
                    SUM(bytes_transferred) AS bytes,
                    COUNT(*) AS packets,
                    SUM(CASE WHEN direction = 'download' THEN bytes_transferred ELSE 0 END) AS dl_bytes,
                    SUM(CASE WHEN direction = 'upload'   THEN bytes_transferred ELSE 0 END) AS ul_bytes
                FROM traffic_summary WHERE timestamp >= ?
            """, (ten_secs,))
            recent = cursor.fetchone()
            bytes_recent = (recent["bytes"] or 0) if recent else 0
            packets_recent = (recent["packets"] or 0) if recent else 0
            dl_bytes_recent = (recent["dl_bytes"] or 0) if recent else 0
            ul_bytes_recent = (recent["ul_bytes"] or 0) if recent else 0
            bandwidth_bps = bytes_recent / 10
            download_bps = dl_bytes_recent / 10
            upload_bps = ul_bytes_recent / 10

            # Active devices — use the single source of truth function
            from database.queries.device_queries import get_active_device_count
            active_devices = get_active_device_count(minutes=5)

            # Today totals
            cursor.execute("""
                SELECT SUM(bytes_transferred) AS bytes, COUNT(*) AS packets
                FROM traffic_summary WHERE timestamp >= ?
            """, (today_start,))
            today = cursor.fetchone()

            stats = {
                "bandwidth_bps": round(bandwidth_bps, 2),
                "bandwidth_mbps": round((bandwidth_bps * 8) / 1_000_000, 4),
                "download_bps": round(download_bps, 2),
                "download_mbps": round((download_bps * 8) / 1_000_000, 4),
                "upload_bps": round(upload_bps, 2),
                "upload_mbps": round((upload_bps * 8) / 1_000_000, 4),
                "active_devices": active_devices,
                "packets_per_second": round(packets_recent / 10, 2),
                "total_bytes_today": (today["bytes"] or 0) if today else 0,
                "total_packets_today": (today["packets"] or 0) if today else 0,
                "timestamp": now.isoformat(),
            }

            # ── 2. Health score ────────────────────────────────────────
            # Consolidated: critical + warning + traffic count in 2 queries
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS critical_count,
                    SUM(CASE WHEN severity IN ('warning', 'medium') THEN 1 ELSE 0 END) AS warning_count
                FROM alerts
                WHERE resolved = 0
            """)
            alert_row = cursor.fetchone()
            critical_alerts = (alert_row["critical_count"] or 0) if alert_row else 0
            warning_alerts = (alert_row["warning_count"] or 0) if alert_row else 0

            cursor.execute("""
                SELECT COUNT(*) AS count FROM traffic_summary WHERE timestamp >= ?
            """, (one_hour,))
            traffic_count = (cursor.fetchone()["count"] or 0)

            score = 100
            factors: List[str] = []
            crit_penalty = min(critical_alerts * 15, 45)
            if crit_penalty:
                score -= crit_penalty
                factors.append(f"-{crit_penalty} pts: {critical_alerts} critical alert(s)")
            warn_penalty = min(warning_alerts * 3, 15)
            if warn_penalty:
                score -= warn_penalty
                factors.append(f"-{warn_penalty} pts: {warning_alerts} warning alert(s)")
            if traffic_count:
                factors.append(f"Traffic monitoring active ({traffic_count:,} packets/hr)")
            else:
                score -= 5
                factors.append("-5 pts: No traffic detected in last hour")
            if active_devices:
                factors.append(f"{active_devices} device(s) connected")
            score = max(0, min(100, score))
            status = "good" if score >= 80 else ("warning" if score >= 50 else "critical")

            health = {
                "score": score, "status": status, "factors": factors,
                "device_count": active_devices, "traffic_count": traffic_count,
                "critical_alerts": critical_alerts, "warning_alerts": warning_alerts,
                "timestamp": now.isoformat(),
            }

            # ── 3. Protocol distribution (last 1 h) ───────────────────
            cursor.execute("""
                SELECT protocol AS name,
                       COUNT(*) AS count,
                       SUM(bytes_transferred) AS bytes
                FROM traffic_summary WHERE timestamp >= ?
                GROUP BY protocol ORDER BY bytes DESC
            """, (one_hour,))
            proto_rows = [dict_from_row(r) for r in cursor.fetchall() if dict_from_row(r)]
            proto_total = sum(d.get('bytes', 0) or 0 for d in proto_rows)
            protocols = []
            for d in proto_rows:
                b = d.get('bytes', 0) or 0
                d['percentage'] = round((b / proto_total * 100) if proto_total else 0, 2)
                protocols.append(d)

            # ── 4. Bandwidth history (last 1 h, per minute) ───────────
            cursor.execute("""
                SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) AS time_bucket,
                       SUM(bytes_transferred) AS total_bytes, COUNT(*) AS packet_count,
                       SUM(CASE WHEN direction='download' THEN bytes_transferred ELSE 0 END) AS bytes_received,
                       SUM(CASE WHEN direction='upload'   THEN bytes_transferred ELSE 0 END) AS bytes_sent
                FROM traffic_summary WHERE timestamp >= ?
                GROUP BY time_bucket ORDER BY time_bucket ASC
            """, (one_hour,))
            bw_history = []
            for row in cursor.fetchall():
                total = row["total_bytes"] or 0
                bw_history.append({
                    "timestamp": row["time_bucket"],
                    "bytes_per_second": round(total / 60, 2),
                    "bytes_sent": row["bytes_sent"] or 0,
                    "bytes_received": row["bytes_received"] or 0,
                    "total_bytes": total,
                    "packet_count": row["packet_count"],
                })

            # ── 5. Recent alerts ───────────────────────────────────────
            cursor.execute("""
                SELECT * FROM alerts WHERE resolved = 0
                ORDER BY timestamp DESC LIMIT 5
            """)
            alerts = [dict_from_row(r) for r in cursor.fetchall()]

            # ── 6. Alert counts ────────────────────────────────────────
            cursor.execute("""
                SELECT severity, COUNT(*) AS count
                FROM alerts WHERE resolved = 0 GROUP BY severity
            """)
            alert_counts = {"info": 0, "low": 0, "medium": 0, "warning": 0,
                            "high": 0, "critical": 0, "total": 0}
            for row in cursor.fetchall():
                alert_counts[row["severity"]] = row["count"]
                alert_counts["total"] += row["count"]

        # ── 7. Top devices (uses its own connection for hostname resolution) ──
        top_devices = get_top_devices(limit=5, hours=1)

        return {
            "stats": stats,
            "health": health,
            "top_devices": top_devices,
            "protocols": protocols,
            "bandwidth_history": bw_history,
            "alerts": alerts,
            "alert_counts": alert_counts,
        }

    except sqlite3.Error as e:
        logger.error("get_dashboard_data error: %s", e)
        return {
            "stats": get_realtime_stats(),
            "health": get_health_score(),
            "top_devices": [],
            "protocols": [],
            "bandwidth_history": [],
            "alerts": [],
            "alert_counts": {"total": 0},
        }


# ---------------------------------------------------------------------------
# Recent activity timeline
# ---------------------------------------------------------------------------

@time_query
def get_recent_activity(limit: int = 20) -> List[dict]:
    """Combined alerts + high-traffic events for the activity feed."""
    try:
        activities: List[dict] = []
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT 'alert' AS activity_type, timestamp,
                       alert_type AS type, severity, message, source_ip
                FROM alerts
                WHERE timestamp >= datetime('now', '-24 hours')
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            for row in cursor.fetchall():
                d = dict_from_row(row)
                d["icon"] = ("fa-exclamation-triangle"
                             if d.get("severity") in ("critical", "high")
                             else "fa-bell")
                activities.append(d)

            cursor.execute("""
                SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) AS time_bucket,
                       source_ip, SUM(bytes_transferred) AS total_bytes,
                       COUNT(*) AS packet_count
                FROM traffic_summary
                WHERE timestamp >= datetime('now', '-1 hour')
                GROUP BY time_bucket, source_ip
                HAVING total_bytes > 1000000
                ORDER BY total_bytes DESC LIMIT 5
            """)
            for row in cursor.fetchall():
                mb = (row["total_bytes"] or 0) / (1024 * 1024)
                activities.append({
                    "activity_type": "traffic",
                    "timestamp": row["time_bucket"],
                    "type": "bandwidth",
                    "severity": "info",
                    "message": f"High traffic from {row['source_ip']}: {mb:.1f} MB",
                    "source_ip": row["source_ip"],
                    "icon": "fa-chart-line",
                })

        activities.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return activities[:limit]

    except sqlite3.Error as e:
        logger.error("get_recent_activity error: %s", e)
        return []
