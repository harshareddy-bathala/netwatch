"""
NetWatch Database Package – Phase 3
=====================================

All database access should go through this package.

After Phase 3 the heavy lifting lives in:
    database/connection.py        – pooled connections, WAL mode
    database/models.py            – dataclasses (PacketData, Device, …)
    database/queries/
        device_queries.py         – device CRUD + THE device-count function
        traffic_queries.py        – bandwidth / protocol analytics
        alert_queries.py          – alert CRUD
        stats_queries.py          – real-time stats, health score, dashboard

For **backward compatibility** every public name that used to be importable
from ``database.db_handler`` is re-exported here so existing call-sites
(routes.py, main.py, detector.py …) keep working without changes.
"""

# ------------------------------------------------------------------
# Init / maintenance  (unchanged location)
# ------------------------------------------------------------------
from database.init_db import (
    initialize_database,
    reset_database,
    check_database_exists,
    get_database_path,
    get_database_info,
    verify_database_integrity,
)

# ------------------------------------------------------------------
# Connection pool
# ------------------------------------------------------------------
from database.connection import (
    get_connection,
    init_pool,
    shutdown_pool,
    dict_from_row,
)

# ------------------------------------------------------------------
# Query modules  (new Phase 3 locations)
# ------------------------------------------------------------------
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
    is_private_ip,
    is_valid_device_ip,
    VALID_DEVICE_IP_FILTER,
    update_daily_usage,
    get_daily_usage,
    get_device_today_usage,
)

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

from database.queries.stats_queries import (
    get_realtime_stats,
    get_health_score,
    get_dashboard_data,
    get_recent_activity,
)

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------
from database.models import (
    PacketData,
    Device,
    Alert,
    TrafficStats,
    HealthScore,
)

# ------------------------------------------------------------------
# __all__ – explicit public surface
# ------------------------------------------------------------------
__all__ = [
    # Init / maintenance
    "initialize_database", "reset_database", "check_database_exists",
    "get_database_path", "get_database_info", "verify_database_integrity",
    # Connection
    "get_connection", "init_pool", "shutdown_pool", "dict_from_row",
    # Devices
    "save_packet", "save_packets_batch", "get_active_device_count",
    "get_device_count", "get_active_devices", "get_all_devices",
    "get_top_devices", "get_device_by_ip", "get_device_by_mac",
    "update_device_name", "get_device_details", "is_private_ip",
    "is_valid_device_ip", "VALID_DEVICE_IP_FILTER",
    "update_daily_usage", "get_daily_usage", "get_device_today_usage",
    # Traffic
    "get_bandwidth_history", "get_bandwidth_history_dual",
    "get_bandwidth_timeseries", "get_protocol_distribution",
    "get_protocol_history", "get_top_talkers", "get_traffic_summary",
    "get_traffic_by_ip",
    # Alerts
    "create_alert", "get_alerts", "get_alert_by_id",
    "acknowledge_alert", "resolve_alert", "count_alerts",
    "get_alert_counts", "get_alert_summary", "delete_old_alerts",
    # Stats / dashboard
    "get_realtime_stats", "get_health_score",
    "get_dashboard_data", "get_recent_activity",
    # Models
    "PacketData", "Device", "Alert", "TrafficStats", "HealthScore",
]
