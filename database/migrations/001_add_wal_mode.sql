-- 001_add_wal_mode.sql
-- ======================
-- Phase 3 migration: enable WAL mode and add missing indexes.
-- Executed on startup by init_db.py if not already applied.

-- Enable WAL mode for better concurrency
-- (read transactions no longer block writes)
PRAGMA journal_mode = WAL;

-- Balance between safety and performance
PRAGMA synchronous = NORMAL;

-- Add direction-related indexes if missing
CREATE INDEX IF NOT EXISTS idx_traffic_direction ON traffic_summary(direction);
CREATE INDEX IF NOT EXISTS idx_traffic_source_mac ON traffic_summary(source_mac);
CREATE INDEX IF NOT EXISTS idx_traffic_dest_mac ON traffic_summary(dest_mac);

-- Ensure devices.last_seen is indexed (speeds up active-device queries)
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
