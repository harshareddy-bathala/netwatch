-- 006_drop_redundant_indexes.sql
-- ================================
-- Phase 4 #45: Remove 13 redundant single-column / prefix-duplicate indexes
-- on traffic_summary.  These are all covered by wider composite indexes
-- added in migrations 004 and 005.
--
-- BEFORE: 21 indexes on traffic_summary
-- AFTER:  8 indexes (composite + covering)
--
-- Redundancy analysis:
--   idx_traffic_timestamp        ⊂ idx_traffic_timestamp_direction (leftmost prefix)
--   idx_traffic_source_ip        ⊂ idx_traffic_src_ip_ts_bytes
--   idx_traffic_dest_ip          ⊂ idx_traffic_dst_ip_ts_bytes
--   idx_traffic_protocol         ⊂ idx_traffic_protocol_timestamp
--   idx_traffic_source_port      — rarely queried, no composite user
--   idx_traffic_dest_port        — rarely queried, no composite user
--   idx_traffic_direction        — low cardinality (~3 values), useless alone
--   idx_traffic_source_mac       ⊂ idx_traffic_src_mac_ts_bytes
--   idx_traffic_dest_mac         ⊂ idx_traffic_dst_mac_ts_bytes
--   idx_traffic_src_ip_ts        ⊂ idx_traffic_src_ip_ts_bytes (strict prefix)
--   idx_traffic_dst_ip_ts        ⊂ idx_traffic_dst_ip_ts_bytes (strict prefix)
--   idx_traffic_src_mac_ts       ⊂ idx_traffic_src_mac_ts_bytes (strict prefix)
--   idx_traffic_dst_mac_ts       ⊂ idx_traffic_dst_mac_ts_bytes (strict prefix)
--
-- Expected improvement: ~40% less write amplification on INSERT,
--   negligible read impact (composite indexes cover all query patterns).

DROP INDEX IF EXISTS idx_traffic_timestamp;
DROP INDEX IF EXISTS idx_traffic_source_ip;
DROP INDEX IF EXISTS idx_traffic_dest_ip;
DROP INDEX IF EXISTS idx_traffic_protocol;
DROP INDEX IF EXISTS idx_traffic_source_port;
DROP INDEX IF EXISTS idx_traffic_dest_port;
DROP INDEX IF EXISTS idx_traffic_direction;
DROP INDEX IF EXISTS idx_traffic_source_mac;
DROP INDEX IF EXISTS idx_traffic_dest_mac;
DROP INDEX IF EXISTS idx_traffic_src_ip_ts;
DROP INDEX IF EXISTS idx_traffic_dst_ip_ts;
DROP INDEX IF EXISTS idx_traffic_src_mac_ts;
DROP INDEX IF EXISTS idx_traffic_dst_mac_ts;

-- Rebuild statistics with the reduced index set
ANALYZE;
