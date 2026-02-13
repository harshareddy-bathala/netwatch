-- 004_optimize_indexes.sql
-- ========================
-- Add composite indexes for common query patterns to eliminate table scans.
--
-- These indexes cover the most frequent query patterns:
--   1. Bandwidth history: timestamp + direction
--   2. Device bandwidth: source_mac/dest_mac + timestamp
--   3. Protocol aggregation: protocol + timestamp
--   4. Active device queries: devices.last_seen
--   5. Alert filtering: resolved + severity, resolved + timestamp

-- For bandwidth history queries (timestamp + direction split)
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp_direction
    ON traffic_summary(timestamp, direction);

-- For device bandwidth queries grouped by MAC
CREATE INDEX IF NOT EXISTS idx_traffic_src_mac_ts
    ON traffic_summary(source_mac, timestamp);

CREATE INDEX IF NOT EXISTS idx_traffic_dst_mac_ts
    ON traffic_summary(dest_mac, timestamp);

-- For protocol aggregation over time
CREATE INDEX IF NOT EXISTS idx_traffic_protocol_timestamp
    ON traffic_summary(protocol, timestamp);

-- For bytes aggregation queries (covering index)
CREATE INDEX IF NOT EXISTS idx_traffic_ts_bytes_dir
    ON traffic_summary(timestamp, bytes_transferred, direction);

-- Alert queries: filter by resolved + severity (covers dashboard & health)
CREATE INDEX IF NOT EXISTS idx_alerts_resolved_severity
    ON alerts(resolved, severity);

-- Alert queries: filter by resolved + timestamp (covers recent alerts)
CREATE INDEX IF NOT EXISTS idx_alerts_resolved_timestamp
    ON alerts(resolved, timestamp);

-- Device bandwidth by IP + timestamp (covers get_traffic_by_ip)
CREATE INDEX IF NOT EXISTS idx_traffic_src_ip_ts_bytes
    ON traffic_summary(source_ip, timestamp, bytes_transferred);

CREATE INDEX IF NOT EXISTS idx_traffic_dst_ip_ts_bytes
    ON traffic_summary(dest_ip, timestamp, bytes_transferred);

-- Update query planner statistics
ANALYZE;
