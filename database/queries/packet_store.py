"""
packet_store.py - Packet & Traffic Record Storage
===================================================

Writes traffic records and device upserts to the database.
Contains both the single-packet path (``save_packet``) and the
optimized batch path (``save_packets_batch``) with pre-aggregation.

Extracted from device_queries.py to separate write-heavy traffic
storage from read-oriented device CRUD queries.
"""

import sqlite3
import logging
from datetime import datetime
from typing import Optional

from database.connection import get_connection
from database.queries.network_filters import (
    _build_mac_to_ipv4,
    _is_valid_device_for_insert,
    _is_multicast_or_broadcast,
    _active_mode_for_mac,
)
from database.queries import network_filters as _nf

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Packet / device save
# ---------------------------------------------------------------------------

def save_packet(packet_data: dict) -> Optional[int]:
    """
    Save a single packet and upsert its source/dest device.

    *Only private IPs* are inserted into the ``devices`` table so that
    public destinations (google.com, cloudflare.com …) never pollute the
    device list.
    """
    if not packet_data:
        return None

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            timestamp = packet_data.get("timestamp", datetime.now())
            if isinstance(timestamp, datetime):
                timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            source_ip = packet_data.get("source_ip") or packet_data.get("src", "unknown")
            dest_ip = packet_data.get("dest_ip") or packet_data.get("dst", "unknown")
            source_mac = packet_data.get("source_mac")
            dest_mac = packet_data.get("dest_mac")
            source_port = packet_data.get("source_port")
            dest_port = packet_data.get("dest_port")
            protocol = packet_data.get("protocol", "UNKNOWN")
            raw_protocol = packet_data.get("raw_protocol", protocol)
            bytes_transferred = packet_data.get("bytes", 0)
            device_name = packet_data.get("device_name")
            vendor = packet_data.get("vendor")
            dest_vendor = packet_data.get("dest_vendor")
            direction = packet_data.get("direction", "unknown")

            # 1. Insert traffic record (always)
            cursor.execute("""
                INSERT INTO traffic_summary
                (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                 source_port, dest_port, protocol, raw_protocol,
                 bytes_transferred, device_name, vendor, direction)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                  source_port, dest_port, protocol, raw_protocol,
                  bytes_transferred, device_name, vendor, direction))

            record_id = cursor.lastrowid

            # 2. Upsert source device — ONLY if valid local device
            if _is_valid_device_for_insert(source_ip, source_mac):
                _is_ipv6_src = source_ip and ":" in source_ip
                _src_active_mode = _active_mode_for_mac(source_mac)
                cursor.execute("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         device_name, vendor,
                         first_seen, last_seen,
                         total_bytes_sent, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor       = COALESCE(excluded.vendor, vendor),
                        last_seen    = excluded.last_seen,
                        total_bytes_sent = total_bytes_sent + excluded.total_bytes_sent,
                        total_packets    = total_packets + 1,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, (source_mac, source_ip,
                      None if _is_ipv6_src else source_ip,
                      source_ip if _is_ipv6_src else None,
                      device_name, vendor,
                      timestamp, timestamp, bytes_transferred,
                      _src_active_mode, _nf._current_mode_name))

            # 3. Upsert dest device — ONLY if valid local device
            if _is_valid_device_for_insert(dest_ip, dest_mac):
                _is_ipv6_dst = dest_ip and ":" in dest_ip
                _dst_active_mode = _active_mode_for_mac(dest_mac)
                cursor.execute("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         device_name, vendor,
                         first_seen, last_seen,
                         total_bytes_received, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor      = COALESCE(excluded.vendor, vendor),
                        last_seen   = excluded.last_seen,
                        total_bytes_received = total_bytes_received + excluded.total_bytes_received,
                        total_packets        = total_packets + 1,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, (dest_mac, dest_ip,
                      None if _is_ipv6_dst else dest_ip,
                      dest_ip if _is_ipv6_dst else None,
                      device_name, dest_vendor,
                      timestamp, timestamp, bytes_transferred,
                      _dst_active_mode, _nf._current_mode_name))

            # 4. Update daily usage (inside the same transaction)
            if _is_valid_device_for_insert(source_ip, source_mac):
                _update_daily_usage_cursor(cursor, source_mac, source_ip, device_name, bytes_transferred, 0, 1)
            if _is_valid_device_for_insert(dest_ip, dest_mac):
                _update_daily_usage_cursor(cursor, dest_mac, dest_ip, None, 0, bytes_transferred, 0)

            # 5. IPv6 traffic attribution (same logic as save_packets_batch)
            src_is_ipv6 = source_ip and ":" in source_ip
            dst_is_ipv6 = dest_ip and ":" in dest_ip

            if src_is_ipv6 and source_mac:
                mac_to_ipv4 = _build_mac_to_ipv4(cursor)
                mapped_ip = mac_to_ipv4.get(source_mac.lower())
                if mapped_ip and _is_valid_device_for_insert(mapped_ip, source_mac):
                    cursor.execute("""
                        UPDATE devices SET
                            total_bytes_sent = total_bytes_sent + ?,
                            total_packets = total_packets + 1,
                            last_seen = ?,
                            ipv6_address = COALESCE(ipv6_address, ?)
                        WHERE mac_address = ?
                    """, (bytes_transferred, timestamp, source_ip, source_mac))
                    _update_daily_usage_cursor(
                        cursor, source_mac, mapped_ip,
                        device_name, bytes_transferred, 0, 1)

            if dst_is_ipv6 and dest_mac:
                if not src_is_ipv6:
                    mac_to_ipv4 = _build_mac_to_ipv4(cursor)
                mapped_ip = mac_to_ipv4.get(dest_mac.lower())
                if mapped_ip and _is_valid_device_for_insert(mapped_ip, dest_mac):
                    cursor.execute("""
                        UPDATE devices SET
                            total_bytes_received = total_bytes_received + ?,
                            total_packets = total_packets + 1,
                            last_seen = ?,
                            ipv6_address = COALESCE(ipv6_address, ?)
                        WHERE mac_address = ?
                    """, (bytes_transferred, timestamp, dest_ip, dest_mac))
                    _update_daily_usage_cursor(
                        cursor, dest_mac, mapped_ip,
                        None, 0, bytes_transferred, 0)

            conn.commit()

            return record_id

    except sqlite3.Error as e:
        logger.error("save_packet error: %s", e)
        return None
    except Exception as e:
        logger.error("Unexpected save_packet error: %s", e)
        return None


def save_packets_batch(packets: list) -> int:
    """
    Save multiple packets in a **single transaction** for performance.

    Only devices passing ``_is_valid_device_for_insert`` (private IP,
    valid MAC, correct subnet, not our own device) are inserted into
    the devices table.  Traffic records are always saved.

    Phase 3 optimization: traffic_summary rows are inserted via a single
    ``executemany()`` call (~10× faster than per-packet INSERT loops for
    typical batch sizes of 100–1000 packets).

    Phase 4 optimization: device UPSERTs, daily usage, and IPv6 attribution
    are pre-aggregated by MAC address and also use ``executemany()`` —
    reducing N per-packet UPSERTs down to (unique MACs) batch calls.

    Packets where **both** source and dest are multicast / broadcast are
    skipped entirely (they carry no useful device information).

    Returns the count of successfully saved packets.
    """
    if not packets:
        return 0

    saved = 0
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Pre-build MAC → IPv4 lookup for IPv6 traffic attribution
            mac_to_ipv4 = _build_mac_to_ipv4(cursor)

            # ---------------------------------------------------------------
            # Phase 3: Bulk INSERT traffic_summary via executemany()
            # ---------------------------------------------------------------
            traffic_rows = []
            normalized_packets = []  # parallel list of normalised dicts

            for pkt in packets:
                try:
                    timestamp = pkt.get("timestamp", datetime.now())
                    if isinstance(timestamp, datetime):
                        timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                    source_ip = pkt.get("source_ip") or pkt.get("src", "unknown")
                    dest_ip = pkt.get("dest_ip") or pkt.get("dst", "unknown")

                    # Skip packets where BOTH endpoints are multicast/broadcast
                    # — they carry no useful device information.
                    if (_is_multicast_or_broadcast(source_ip)
                            and _is_multicast_or_broadcast(dest_ip)):
                        continue

                    source_mac = pkt.get("source_mac")
                    dest_mac = pkt.get("dest_mac")
                    source_port = pkt.get("source_port")
                    dest_port = pkt.get("dest_port")
                    protocol = pkt.get("protocol", "UNKNOWN")
                    raw_protocol = pkt.get("raw_protocol", protocol)
                    bytes_transferred = pkt.get("bytes", 0)
                    device_name = pkt.get("device_name")
                    vendor = pkt.get("vendor")
                    dest_vendor = pkt.get("dest_vendor")
                    direction = pkt.get("direction", "unknown")

                    traffic_rows.append((
                        timestamp, source_ip, dest_ip, source_mac, dest_mac,
                        source_port, dest_port, protocol, raw_protocol,
                        bytes_transferred, device_name, vendor, direction,
                    ))
                    normalized_packets.append({
                        "timestamp": timestamp,
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "source_mac": source_mac,
                        "dest_mac": dest_mac,
                        "source_port": source_port,
                        "dest_port": dest_port,
                        "protocol": protocol,
                        "raw_protocol": raw_protocol,
                        "bytes": bytes_transferred,
                        "device_name": device_name,
                        "vendor": vendor,
                        "dest_vendor": dest_vendor,
                        "direction": direction,
                    })
                except Exception as e:
                    logger.warning("Error normalizing packet for batch: %s", e)

            # Bulk traffic_summary insert
            if traffic_rows:
                cursor.executemany("""
                    INSERT INTO traffic_summary
                    (timestamp, source_ip, dest_ip, source_mac, dest_mac,
                     source_port, dest_port, protocol, raw_protocol,
                     bytes_transferred, device_name, vendor, direction)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, traffic_rows)
                saved = len(traffic_rows)

            # ---------------------------------------------------------------
            # Phase 4: Pre-aggregate device data by MAC, then batch UPSERT
            # ---------------------------------------------------------------
            # Collect per-MAC aggregations to reduce N individual UPSERTs
            # to at most 2 × (unique MACs) executemany calls.
            src_agg: dict = {}   # mac -> {bytes, packets, ip, ipv4, ipv6, name, vendor, ts}
            dst_agg: dict = {}   # mac -> {bytes, packets, ip, ipv4, ipv6, vendor, ts}
            daily_agg: dict = {} # (mac, ip, role) -> {sent, recv, pkts, name}
            ipv6_src_agg: dict = {}  # mac -> {bytes, ts, ipv6}
            ipv6_dst_agg: dict = {}  # mac -> {bytes, ts, ipv6}

            for npkt in normalized_packets:
                try:
                    timestamp = npkt["timestamp"]
                    source_ip = npkt["source_ip"]
                    dest_ip = npkt["dest_ip"]
                    source_mac = npkt["source_mac"]
                    dest_mac = npkt["dest_mac"]
                    bytes_transferred = npkt["bytes"]
                    device_name = npkt["device_name"]
                    vendor = npkt["vendor"]
                    dest_vendor = npkt["dest_vendor"]

                    # Source device — only valid local devices
                    if _is_valid_device_for_insert(source_ip, source_mac):
                        is_ipv6 = source_ip and ":" in source_ip
                        agg = src_agg.get(source_mac)
                        if agg is None:
                            agg = {"bytes": 0, "packets": 0, "ip": source_ip,
                                   "ipv4": None if is_ipv6 else source_ip,
                                   "ipv6": source_ip if is_ipv6 else None,
                                   "name": device_name, "vendor": vendor, "ts": timestamp}
                            src_agg[source_mac] = agg
                        agg["bytes"] += bytes_transferred
                        agg["packets"] += 1
                        agg["ts"] = timestamp  # keep latest
                        if not is_ipv6:
                            agg["ipv4"] = source_ip
                            agg["ip"] = source_ip
                        elif is_ipv6:
                            agg["ipv6"] = source_ip
                        if device_name and not agg["name"]:
                            agg["name"] = device_name
                        if vendor and not agg["vendor"]:
                            agg["vendor"] = vendor

                        # Daily usage aggregation (source)
                        dk = (source_mac, source_ip, "src")
                        du = daily_agg.get(dk)
                        if du is None:
                            du = {"sent": 0, "recv": 0, "pkts": 0, "name": device_name}
                            daily_agg[dk] = du
                        du["sent"] += bytes_transferred
                        du["pkts"] += 1

                    # Dest device — only valid local devices
                    if _is_valid_device_for_insert(dest_ip, dest_mac):
                        is_ipv6 = dest_ip and ":" in dest_ip
                        agg = dst_agg.get(dest_mac)
                        if agg is None:
                            agg = {"bytes": 0, "packets": 0, "ip": dest_ip,
                                   "ipv4": None if is_ipv6 else dest_ip,
                                   "ipv6": dest_ip if is_ipv6 else None,
                                   "name": device_name, "vendor": dest_vendor,
                                   "ts": timestamp}
                            dst_agg[dest_mac] = agg
                        agg["bytes"] += bytes_transferred
                        agg["packets"] += 1
                        agg["ts"] = timestamp
                        if not is_ipv6:
                            agg["ipv4"] = dest_ip
                            agg["ip"] = dest_ip
                        elif is_ipv6:
                            agg["ipv6"] = dest_ip
                        if dest_vendor and not agg["vendor"]:
                            agg["vendor"] = dest_vendor
                        if device_name and not agg.get("name"):
                            agg["name"] = device_name

                        # Daily usage aggregation (dest)
                        dk = (dest_mac, dest_ip, "dst")
                        du = daily_agg.get(dk)
                        if du is None:
                            du = {"sent": 0, "recv": 0, "pkts": 0, "name": None}
                            daily_agg[dk] = du
                        du["recv"] += bytes_transferred

                    # IPv6 traffic attribution aggregation
                    src_is_ipv6 = source_ip and ":" in source_ip
                    dst_is_ipv6 = dest_ip and ":" in dest_ip

                    if src_is_ipv6 and source_mac:
                        mapped_ip = mac_to_ipv4.get(source_mac.lower())
                        if mapped_ip and _is_valid_device_for_insert(mapped_ip, source_mac):
                            agg = ipv6_src_agg.get(source_mac)
                            if agg is None:
                                agg = {"bytes": 0, "ts": timestamp, "ipv6": source_ip, "mapped_ip": mapped_ip, "name": device_name}
                                ipv6_src_agg[source_mac] = agg
                            agg["bytes"] += bytes_transferred
                            agg["ts"] = timestamp

                            dk = (source_mac, mapped_ip, "src")
                            du = daily_agg.get(dk)
                            if du is None:
                                du = {"sent": 0, "recv": 0, "pkts": 0, "name": device_name}
                                daily_agg[dk] = du
                            du["sent"] += bytes_transferred
                            du["pkts"] += 1

                    if dst_is_ipv6 and dest_mac:
                        mapped_ip = mac_to_ipv4.get(dest_mac.lower())
                        if mapped_ip and _is_valid_device_for_insert(mapped_ip, dest_mac):
                            agg = ipv6_dst_agg.get(dest_mac)
                            if agg is None:
                                agg = {"bytes": 0, "ts": timestamp, "ipv6": dest_ip, "mapped_ip": mapped_ip}
                                ipv6_dst_agg[dest_mac] = agg
                            agg["bytes"] += bytes_transferred
                            agg["ts"] = timestamp

                            dk = (dest_mac, mapped_ip, "dst")
                            du = daily_agg.get(dk)
                            if du is None:
                                du = {"sent": 0, "recv": 0, "pkts": 0, "name": None}
                                daily_agg[dk] = du
                            du["recv"] += bytes_transferred

                except Exception as e:
                    logger.warning("Error aggregating packet in batch: %s", e)
                    continue

            # Batch source device UPSERTs
            if src_agg:
                src_rows = []
                for mac, a in src_agg.items():
                    _src_am = _active_mode_for_mac(mac)
                    src_rows.append((mac, a["ip"], a["ipv4"], a["ipv6"],
                                     a["name"], a["vendor"],
                                     a["ts"], a["ts"], a["bytes"],
                                     a["packets"],
                                     _src_am, _nf._current_mode_name))
                cursor.executemany("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         device_name, vendor,
                         first_seen, last_seen,
                         total_bytes_sent, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor       = COALESCE(excluded.vendor, vendor),
                        last_seen    = excluded.last_seen,
                        total_bytes_sent = total_bytes_sent + excluded.total_bytes_sent,
                        total_packets    = total_packets + excluded.total_packets,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, src_rows)

            # Batch dest device UPSERTs
            if dst_agg:
                dst_rows = []
                for mac, a in dst_agg.items():
                    _dst_am = _active_mode_for_mac(mac)
                    dst_rows.append((mac, a["ip"], a["ipv4"], a["ipv6"],
                                     a.get("name"), a["vendor"],
                                     a["ts"], a["ts"], a["bytes"],
                                     a["packets"],
                                     _dst_am, _nf._current_mode_name))
                cursor.executemany("""
                    INSERT INTO devices
                        (mac_address, ip_address,
                         ipv4_address, ipv6_address,
                         device_name, vendor,
                         first_seen, last_seen,
                         total_bytes_received, total_packets,
                         active_mode, detected_mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                        ipv4_address = CASE
                            WHEN excluded.ipv4_address IS NOT NULL
                            THEN excluded.ipv4_address
                            ELSE ipv4_address END,
                        ipv6_address = CASE
                            WHEN excluded.ipv6_address IS NOT NULL
                            THEN excluded.ipv6_address
                            ELSE ipv6_address END,
                        ip_address   = COALESCE(
                            CASE WHEN excluded.ipv4_address IS NOT NULL
                                 THEN excluded.ipv4_address
                                 ELSE ipv4_address END,
                            CASE WHEN excluded.ipv6_address IS NOT NULL
                                 THEN excluded.ipv6_address
                                 ELSE ipv6_address END),
                        device_name  = CASE
                            WHEN device_name IS NULL OR device_name = ''
                            THEN COALESCE(excluded.device_name, device_name)
                            ELSE device_name END,
                        vendor      = COALESCE(excluded.vendor, vendor),
                        last_seen   = excluded.last_seen,
                        total_bytes_received = total_bytes_received + excluded.total_bytes_received,
                        total_packets        = total_packets + excluded.total_packets,
                        active_mode  = COALESCE(excluded.active_mode, active_mode)
                """, dst_rows)

            # Batch IPv6 source attribution
            if ipv6_src_agg:
                ipv6_src_rows = [(a["bytes"], a["ts"], a["ipv6"], mac)
                                 for mac, a in ipv6_src_agg.items()]
                cursor.executemany("""
                    UPDATE devices SET
                        total_bytes_sent = total_bytes_sent + ?,
                        total_packets = total_packets + 1,
                        last_seen = ?,
                        ipv6_address = COALESCE(ipv6_address, ?)
                    WHERE mac_address = ?
                """, ipv6_src_rows)

            # Batch IPv6 dest attribution
            if ipv6_dst_agg:
                ipv6_dst_rows = [(a["bytes"], a["ts"], a["ipv6"], mac)
                                 for mac, a in ipv6_dst_agg.items()]
                cursor.executemany("""
                    UPDATE devices SET
                        total_bytes_received = total_bytes_received + ?,
                        total_packets = total_packets + 1,
                        last_seen = ?,
                        ipv6_address = COALESCE(ipv6_address, ?)
                    WHERE mac_address = ?
                """, ipv6_dst_rows)

            # Batch daily usage UPSERTs
            if daily_agg:
                today = datetime.now().strftime("%Y-%m-%d")
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                daily_rows = []
                for (mac, ip, _role), du in daily_agg.items():
                    total = du["sent"] + du["recv"]
                    daily_rows.append((
                        today, mac, ip, du["name"],
                        du["sent"], du["recv"], total, du["pkts"],
                        now_str, now_str,
                    ))
                cursor.executemany("""
                    INSERT INTO daily_usage
                    (date, mac_address, ip_address, device_name,
                     bytes_sent, bytes_received, total_bytes, packet_count,
                     first_seen_today, last_seen_today)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(date, mac_address) DO UPDATE SET
                        ip_address   = COALESCE(excluded.ip_address, ip_address),
                        device_name  = COALESCE(excluded.device_name, device_name),
                        bytes_sent     = bytes_sent     + excluded.bytes_sent,
                        bytes_received = bytes_received + excluded.bytes_received,
                        total_bytes    = total_bytes    + excluded.total_bytes,
                        packet_count   = packet_count   + excluded.packet_count,
                        last_seen_today = excluded.last_seen_today
                """, daily_rows)

            conn.commit()

        # Periodic WAL checkpoint after large batches to prevent the
        # write-ahead log from growing unboundedly, which would degrade
        # read latency on subsequent dashboard queries.
        if saved >= 20:
            try:
                from database.connection import wal_checkpoint
                wal_checkpoint("PASSIVE")
            except Exception:
                pass  # non-critical

    except sqlite3.OperationalError as e:
        if "locked" in str(e).lower():
            # Retry with exponential backoff (up to 3 attempts)
            for attempt in range(1, 4):
                delay = 0.2 * (2 ** (attempt - 1))   # 0.2, 0.4, 0.8s
                logger.warning(
                    "save_packets_batch: DB locked (attempt %d/3), "
                    "retrying in %.2fs", attempt, delay,
                )
                import time as _time
                _time.sleep(delay)
                try:
                    with get_connection() as conn2:
                        cursor2 = conn2.cursor()
                        if traffic_rows:
                            cursor2.executemany("""
                                INSERT INTO traffic_summary
                                (timestamp, source_ip, dest_ip, source_mac,
                                 dest_mac, source_port, dest_port, protocol,
                                 raw_protocol, bytes_transferred, device_name,
                                 vendor, direction)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                            """, traffic_rows)
                            saved = len(traffic_rows)
                        conn2.commit()
                    logger.info(
                        "save_packets_batch: retry %d succeeded (%d rows)",
                        attempt, saved,
                    )
                    break
                except sqlite3.OperationalError:
                    if attempt == 3:
                        logger.error("save_packets_batch: all retries exhausted: %s", e)
        else:
            logger.error("Batch save error: %s", e)
    except sqlite3.Error as e:
        logger.error("Batch save error: %s", e)

    return saved


# ---------------------------------------------------------------------------
# Daily usage helpers
# ---------------------------------------------------------------------------

def update_daily_usage(mac_address: str, ip_address: str, device_name: Optional[str],
                       bytes_sent: int, bytes_received: int, packet_count: int = 1) -> bool:
    if not mac_address:
        return False
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            _update_daily_usage_cursor(cursor, mac_address, ip_address,
                                       device_name, bytes_sent, bytes_received, packet_count)
            conn.commit()
            return True
    except sqlite3.Error as e:
        logger.error("update_daily_usage error: %s", e)
        return False


def _update_daily_usage_cursor(cursor, mac_address, ip_address, device_name,
                                bytes_sent, bytes_received, packet_count):
    """Inner helper that works on an existing cursor (no commit)."""
    today = datetime.now().strftime("%Y-%m-%d")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_bytes = bytes_sent + bytes_received
    cursor.execute("""
        INSERT INTO daily_usage
        (date, mac_address, ip_address, device_name, bytes_sent, bytes_received,
         total_bytes, packet_count, first_seen_today, last_seen_today)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(date, mac_address) DO UPDATE SET
            ip_address   = COALESCE(excluded.ip_address, ip_address),
            device_name  = COALESCE(excluded.device_name, device_name),
            bytes_sent     = bytes_sent     + excluded.bytes_sent,
            bytes_received = bytes_received + excluded.bytes_received,
            total_bytes    = total_bytes    + excluded.total_bytes,
            packet_count   = packet_count   + excluded.packet_count,
            last_seen_today = excluded.last_seen_today
    """, (today, mac_address, ip_address, device_name, bytes_sent, bytes_received,
          total_bytes, packet_count, now, now))
