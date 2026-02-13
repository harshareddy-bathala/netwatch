-- 005_fix_slow_queries.sql
-- ========================
-- EMERGENCY FIX: Add missing indexes to eliminate 5-10 second query times.
--
-- Root cause: get_top_devices() and get_dashboard_data() perform UNION ALL
-- across traffic_summary grouped by MAC + filtered by timestamp.  Without
-- covering indexes on (source_mac, timestamp, bytes_transferred) and
-- (dest_mac, timestamp, bytes_transferred) the query planner falls back to
-- full table scans.
--
-- Expected improvement: 5-10s → <100ms

-- Covering index for source device bandwidth aggregation
-- Covers: WHERE timestamp > ? ... GROUP BY source_mac ... SUM(bytes_transferred)
CREATE INDEX IF NOT EXISTS idx_traffic_src_mac_ts_bytes
    ON traffic_summary(source_mac, timestamp, bytes_transferred);

-- Covering index for destination device bandwidth aggregation
CREATE INDEX IF NOT EXISTS idx_traffic_dst_mac_ts_bytes
    ON traffic_summary(dest_mac, timestamp, bytes_transferred);

-- Index for daily_usage lookups (used in get_device_today_usage N+1 queries)
CREATE INDEX IF NOT EXISTS idx_daily_usage_date_mac_covering
    ON daily_usage(date, mac_address, total_bytes, bytes_sent, bytes_received, packet_count);

-- Index for devices table hostname/device_name lookups by IP or MAC
CREATE INDEX IF NOT EXISTS idx_devices_ip_mac
    ON devices(ip_address, mac_address);

-- Rebuild query planner statistics with new indexes
ANALYZE;
