"""
db_handler.py - Backward-Compatibility Shim (Phase 3)
=======================================================

The monolithic db_handler.py (2,004 lines) has been split into focused modules
under database/queries/.  This file re-exports every public name so that
existing callers (routes.py, main.py, detector.py, capture_engine.py, etc.)
continue to work **without any import changes**.

New code should import from the specific module instead:
    from database.queries.device_queries import get_active_device_count
    from database.queries.alert_queries  import create_alert

The original file is preserved at archive/db_handler.py.old.
"""

# Connection pool (replaces the old per-call sqlite3.connect)
from database.connection import get_connection, dict_from_row

# IP helpers
from database.queries.device_queries import (
    is_private_ip as _is_private_ip,
    is_valid_device_ip,
    is_valid_device,
    get_current_subnet,
    VALID_DEVICE_IP_FILTER,
)

# Device CRUD
from database.queries.device_queries import (
    save_packet,
    save_packets_batch,
    get_active_device_count,
    get_device_count,
    get_active_devices,
    get_all_devices,
    get_top_devices,
    get_device_by_ip,
    get_device_by_mac,
    update_device_name,
    get_device_details,
    update_daily_usage,
    get_daily_usage,
    get_device_today_usage,
)

# Traffic / bandwidth
from database.queries.traffic_queries import (
    get_bandwidth_history,
    get_bandwidth_history_dual,
    get_bandwidth_timeseries,
    get_protocol_distribution,
    get_protocol_history,
    get_top_talkers,
    get_traffic_summary,
    get_traffic_by_ip,
)

# Alerts
from database.queries.alert_queries import (
    create_alert,
    get_alerts,
    get_alert_by_id,
    acknowledge_alert,
    resolve_alert,
    count_alerts,
    get_alert_counts,
    get_alert_summary,
    delete_old_alerts,
)

# Stats & dashboard
from database.queries.stats_queries import (
    get_realtime_stats,
    get_health_score,
    get_dashboard_data,
    get_recent_activity,
)

# Maintenance (Phase 2)
from database.queries.maintenance import (
    cleanup_old_traffic,
    run_full_cleanup,
    get_database_size_mb,
    get_table_row_counts,
    get_maintenance_report,
    vacuum_database,
)

# Helper retained for any direct callers
from database.queries.device_queries import _format_bytes as format_bytes


def cleanup_old_data(days_to_keep: int = 7) -> int:
    """Cleanup old traffic and alert data."""
    import sqlite3, logging
    from datetime import datetime, timedelta
    logger = logging.getLogger(__name__)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=days_to_keep)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("DELETE FROM traffic_summary WHERE timestamp < ?", (cutoff,))
            deleted_traffic = cursor.rowcount
            alert_cutoff = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("DELETE FROM alerts WHERE timestamp < ? AND resolved = 1", (alert_cutoff,))
            deleted_alerts = cursor.rowcount
            cursor.execute(
                "INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('last_cleanup', ?, datetime('now'))",
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),))
            conn.commit()
            total = deleted_traffic + deleted_alerts
            if total:
                logger.info(f"Cleanup: {deleted_traffic} traffic, {deleted_alerts} alerts deleted")
            return total
    except sqlite3.Error as e:
        logger.error(f"Cleanup error: {e}")
        return 0
