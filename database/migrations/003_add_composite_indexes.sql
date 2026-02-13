-- Migration 003: Add composite indexes for device detail query performance
-- These indexes speed up the fallback CTE query in get_device_details()
-- by allowing efficient range scans on (ip, timestamp) pairs.

CREATE INDEX IF NOT EXISTS idx_traffic_src_ip_ts ON traffic_summary(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_dst_ip_ts ON traffic_summary(dest_ip, timestamp);
