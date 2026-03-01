"""
traffic_queries.py - Bandwidth & Traffic Analysis
====================================================

Queries for bandwidth time-series, protocol distribution, top talkers,
and raw traffic records.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from database.connection import get_connection, dict_from_row
from utils.query_cache import time_query, TTLCache

logger = logging.getLogger(__name__)

# Cache for frequently-polled queries (10s TTL — bandwidth history changes
# slowly relative to the dashboard and caching avoids repeated expensive
# GROUP BY scans on traffic_summary).
_traffic_cache = TTLCache(ttl_seconds=10)


# ---------------------------------------------------------------------------
# Bandwidth / time-series
# ---------------------------------------------------------------------------

@time_query
def get_bandwidth_history(hours: int = 1, interval: str = "minute") -> List[dict]:
    """
    Aggregate traffic over *hours*, bucketed by *interval*.

    Uses the Phase 2 ``direction`` column for upload/download split.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            if interval == "hour":
                fmt, secs = "%Y-%m-%d %H:00:00", 3600
            elif interval == "day":
                fmt, secs = "%Y-%m-%d 00:00:00", 86400
            else:
                fmt, secs = "%Y-%m-%d %H:%M:00", 60

            cursor.execute(f"""
                SELECT
                    strftime('{fmt}', timestamp) AS time_bucket,
                    SUM(bytes_transferred)                                          AS total_bytes,
                    COUNT(*)                                                        AS packet_count,
                    SUM(CASE WHEN direction = 'download' THEN bytes_transferred ELSE 0 END) AS bytes_received,
                    SUM(CASE WHEN direction = 'upload'   THEN bytes_transferred ELSE 0 END) AS bytes_sent
                FROM traffic_summary
                WHERE timestamp >= ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """, (since,))

            results = []
            for row in cursor.fetchall():
                total = row["total_bytes"] or 0
                bps = total / secs if secs else 0
                results.append({
                    "timestamp": row["time_bucket"],
                    "bytes_per_second": round(bps, 2),
                    "bytes_sent": row["bytes_sent"] or 0,
                    "bytes_received": row["bytes_received"] or 0,
                    "total_bytes": total,
                    "packet_count": row["packet_count"],
                })
            return results

    except sqlite3.Error as e:
        logger.error("get_bandwidth_history error: %s", e)
        return []


@time_query
def get_bandwidth_history_dual(hours: int = 1, interval: str = "minute") -> List[dict]:
    """
    Same as ``get_bandwidth_history`` but returns Mbps fields for
    dual-line download/upload charts.

    Supports sub-minute intervals (``10s``, ``30s``) for the 1H view so
    the chart resolution matches the BandwidthCalculator's 10-second
    sliding window.  Sub-minute intervals only use raw data from
    ``traffic_summary`` (rollup data is hourly and too coarse).

    Results are cached for 3 seconds (matches SSE push interval).
    """
    cache_key = f"bw_dual_{hours}_{interval}"
    cached = _traffic_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Sub-minute intervals: use epoch-based bucketing on raw data only.
            # Use julianday() instead of strftime('%s', ...) because %s is not
            # supported on all SQLite builds (e.g. Windows).
            # NOTE: timestamps are stored as LOCAL time (datetime.now()), so
            # julianday() treats them as UTC internally.  We must NOT apply
            # 'localtime' on output — that would double-count the timezone
            # offset.  The round-trip through 'unixepoch' (without 'localtime')
            # returns the original local-time string correctly.
            if interval in ("10s", "30s"):
                bucket_secs = 10 if interval == "10s" else 30
                bucket_expr = (
                    f"datetime((CAST((julianday(timestamp) - 2440587.5) * 86400 AS INTEGER) / {bucket_secs}) "
                    f"* {bucket_secs}, 'unixepoch')"
                )
                cursor.execute(f"""
                    SELECT
                        {bucket_expr} AS time_bucket,
                        SUM(bytes_transferred) AS total_bytes,
                        COUNT(*) AS packet_count,
                        SUM(CASE WHEN direction = 'download' THEN bytes_transferred ELSE 0 END) AS bytes_download,
                        SUM(CASE WHEN direction = 'upload'   THEN bytes_transferred ELSE 0 END) AS bytes_upload
                    FROM traffic_summary
                    WHERE timestamp >= ?
                    GROUP BY time_bucket
                    ORDER BY time_bucket ASC
                """, (since,))
                secs = bucket_secs
            else:
                # Minute / hour / day: use strftime on traffic_summary only.
                # traffic_summary retains 24h of raw data, which covers the
                # typical 1H/6H/24H dashboard views.  For longer ranges the
                # data simply thins out naturally.  Removing the UNION with
                # traffic_rollup avoids double-counting and cuts query time.
                if interval == "hour":
                    fmt, secs = "%Y-%m-%d %H:00:00", 3600
                elif interval == "day":
                    fmt, secs = "%Y-%m-%d 00:00:00", 86400
                else:
                    fmt, secs = "%Y-%m-%d %H:%M:00", 60

                cursor.execute(f"""
                    SELECT
                        strftime('{fmt}', timestamp) AS time_bucket,
                        SUM(bytes_transferred) AS total_bytes,
                        COUNT(*) AS packet_count,
                        SUM(CASE WHEN direction = 'download' THEN bytes_transferred ELSE 0 END) AS bytes_download,
                        SUM(CASE WHEN direction = 'upload'   THEN bytes_transferred ELSE 0 END) AS bytes_upload
                    FROM traffic_summary
                    WHERE timestamp >= ?
                    GROUP BY time_bucket
                    ORDER BY time_bucket ASC
                """, (since,))

            mbps_mult = 8 / secs / 1_000_000 if secs else 0
            results = []
            for row in cursor.fetchall():
                total = row["total_bytes"] or 0
                dl = row["bytes_download"] or 0
                ul = row["bytes_upload"] or 0
                results.append({
                    "timestamp": row["time_bucket"],
                    "download_mbps": round(dl * mbps_mult, 3),
                    "upload_mbps": round(ul * mbps_mult, 3),
                    "total_mbps": round(total * mbps_mult, 3),
                    "bytes_download": dl,
                    "bytes_upload": ul,
                    "total_bytes": total,
                    "packet_count": row["packet_count"],
                })
            _traffic_cache.set(cache_key, results)
            return results

    except sqlite3.Error as e:
        logger.error("get_bandwidth_history_dual error: %s", e)
        return []


@time_query
def get_bandwidth_timeseries(minutes: int = 60) -> List[dict]:
    """
    Per-**second** bandwidth granularity for the last *minutes* minutes.

    Returns ``[{timestamp, upload_bps, download_bps}, ...]``
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                SELECT
                    strftime('%Y-%m-%d %H:%M:%S', timestamp) AS ts,
                    SUM(CASE WHEN direction = 'upload'   THEN bytes_transferred ELSE 0 END) AS upload_bytes,
                    SUM(CASE WHEN direction = 'download' THEN bytes_transferred ELSE 0 END) AS download_bytes
                FROM traffic_summary
                WHERE timestamp >= ?
                GROUP BY ts
                ORDER BY ts ASC
            """, (since,))

            return [
                {
                    "timestamp": row["ts"],
                    "upload_bps": (row["upload_bytes"] or 0) * 8,
                    "download_bps": (row["download_bytes"] or 0) * 8,
                }
                for row in cursor.fetchall()
            ]

    except sqlite3.Error as e:
        logger.error("get_bandwidth_timeseries error: %s", e)
        return []


# ---------------------------------------------------------------------------
# Protocol distribution
# ---------------------------------------------------------------------------

@time_query
def get_protocol_distribution(hours: int = 1) -> List[dict]:
    """
    Return ``[{name, count, bytes, percentage}, ...]`` grouped by protocol.

    Optimised: single query with window function instead of two separate queries.
    """
    cache_key = f"proto_dist_{hours}"
    cached = _traffic_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Single query: aggregate + compute percentage in one pass
            cursor.execute("""
                SELECT
                    protocol,
                    COUNT(*) AS count,
                    SUM(bytes_transferred) AS bytes,
                    ROUND(
                        SUM(bytes_transferred) * 100.0 /
                        MAX(1, SUM(SUM(bytes_transferred)) OVER()),
                    2) AS percentage
                FROM traffic_summary
                WHERE timestamp >= ?
                GROUP BY protocol
                ORDER BY bytes DESC
            """, (since,))

            results = [
                {
                    "name": row["protocol"],
                    "count": row["count"],
                    "bytes": row["bytes"] or 0,
                    "percentage": row["percentage"] or 0,
                }
                for row in cursor.fetchall()
            ]
            _traffic_cache.set(cache_key, results)
            return results

    except sqlite3.Error as e:
        logger.error("get_protocol_distribution error: %s", e)
        return []


@time_query
def get_protocol_history(protocol: str, hours: int = 1) -> List[dict]:
    """Per-minute traffic for a single *protocol*."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) AS time_bucket,
                       SUM(bytes_transferred) AS total_bytes,
                       COUNT(*) AS packet_count
                FROM traffic_summary
                WHERE protocol = ? AND timestamp >= ?
                GROUP BY time_bucket ORDER BY time_bucket ASC
            """, (protocol, since))

            return [dict_from_row(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        logger.error("get_protocol_history error: %s", e)
        return []


# ---------------------------------------------------------------------------
# Top talkers
# ---------------------------------------------------------------------------

@time_query
def get_top_talkers(limit: int = 10, hours: int = 1) -> List[dict]:
    """
    Devices ranked by total bandwidth in the last *hours* hours.

    Groups by MAC address and includes hostname when available.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                WITH talkers AS (
                    SELECT source_mac AS mac, source_ip AS ip,
                           device_name, vendor,
                           bytes_transferred AS bw, timestamp
                    FROM traffic_summary
                    WHERE timestamp >= ? AND source_mac IS NOT NULL AND source_mac != ''
                    UNION ALL
                    SELECT dest_mac, dest_ip, NULL, NULL, bytes_transferred, timestamp
                    FROM traffic_summary
                    WHERE timestamp >= ? AND dest_mac IS NOT NULL AND dest_mac != ''
                )
                SELECT mac AS mac_address,
                       MAX(ip) AS ip_address,
                       MAX(device_name) AS hostname,
                       MAX(vendor) AS vendor,
                       SUM(bw) AS total_bytes,
                       COUNT(*) AS packet_count,
                       MAX(timestamp) AS last_seen
                FROM talkers
                GROUP BY mac
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (since, since, limit))

            return [dict_from_row(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        logger.error("get_top_talkers error: %s", e)
        return []


# ---------------------------------------------------------------------------
# Raw traffic
# ---------------------------------------------------------------------------

def get_traffic_summary(hours: int = 1, limit: int = 1000, device_ip: str = None) -> List[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            if device_ip:
                cursor.execute("""
                    SELECT * FROM traffic_summary
                    WHERE timestamp >= ? AND (source_ip = ? OR dest_ip = ?)
                    ORDER BY timestamp DESC LIMIT ?
                """, (since, device_ip, device_ip, limit))
            else:
                cursor.execute("""
                    SELECT * FROM traffic_summary WHERE timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (since, limit))
            return [dict_from_row(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("get_traffic_summary error: %s", e)
        return []


@time_query
def get_traffic_by_ip(ip_address: str, hours: int = 1) -> dict:
    """Traffic breakdown for a single IP address.

    Optimised: consolidated sent/received into a single UNION ALL query,
    and combined protocol + connection queries into two index-friendly passes.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

            # Single query for sent/received totals using UNION ALL
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN source_ip = ? THEN bytes_transferred ELSE 0 END) AS bytes_sent,
                    SUM(CASE WHEN source_ip = ? THEN 1 ELSE 0 END) AS packets_sent,
                    SUM(CASE WHEN dest_ip = ? THEN bytes_transferred ELSE 0 END) AS bytes_received,
                    SUM(CASE WHEN dest_ip = ? THEN 1 ELSE 0 END) AS packets_received
                FROM (
                    SELECT source_ip, dest_ip, bytes_transferred
                    FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                    UNION ALL
                    SELECT source_ip, dest_ip, bytes_transferred
                    FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                )
            """, (ip_address, ip_address, ip_address, ip_address,
                  ip_address, since, ip_address, since))
            totals = cursor.fetchone()
            bytes_sent = (totals["bytes_sent"] or 0) if totals else 0
            packets_sent = (totals["packets_sent"] or 0) if totals else 0
            bytes_received = (totals["bytes_received"] or 0) if totals else 0
            packets_received = (totals["packets_received"] or 0) if totals else 0

            # Protocol breakdown (UNION ALL for index usage)
            cursor.execute("""
                SELECT protocol, COUNT(*) AS count, SUM(bytes_transferred) AS bytes
                FROM (
                    SELECT protocol, bytes_transferred FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                    UNION ALL
                    SELECT protocol, bytes_transferred FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                )
                GROUP BY protocol ORDER BY bytes DESC
            """, (ip_address, since, ip_address, since))
            protocols = [dict_from_row(r) for r in cursor.fetchall()]

            # Top connections
            cursor.execute("""
                SELECT
                    CASE WHEN source_ip = ? THEN dest_ip ELSE source_ip END AS connected_ip,
                    COUNT(*) AS connection_count,
                    SUM(bytes_transferred) AS bytes
                FROM (
                    SELECT source_ip, dest_ip, bytes_transferred FROM traffic_summary
                    WHERE source_ip = ? AND timestamp >= ?
                    UNION ALL
                    SELECT source_ip, dest_ip, bytes_transferred FROM traffic_summary
                    WHERE dest_ip = ? AND timestamp >= ?
                )
                GROUP BY connected_ip ORDER BY bytes DESC LIMIT 10
            """, (ip_address, ip_address, since, ip_address, since))
            connections = [dict_from_row(r) for r in cursor.fetchall()]

            return {
                "ip_address": ip_address,
                "hours": hours,
                "bytes_sent": bytes_sent,
                "packets_sent": packets_sent,
                "bytes_received": bytes_received,
                "packets_received": packets_received,
                "total_bytes": bytes_sent + bytes_received,
                "protocols": protocols,
                "connections": connections,
            }

    except sqlite3.Error as e:
        logger.error("get_traffic_by_ip error: %s", e)
        return {"ip_address": ip_address, "error": str(e)}
