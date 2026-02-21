"""
queries/__init__.py - Query Module Exports
============================================

Re-exports every public function from the four query sub-modules so that
callers can do:

    from database.queries import get_active_device_count, create_alert
"""

from database.queries.device_queries import (
    save_packet,
    save_packets_batch,
    get_active_device_count,
    get_active_devices,
    get_all_devices,
    get_top_devices,
    get_device_by_ip,
    get_device_by_mac,
    update_device_name,
    get_device_details,
    is_private_ip,
    is_valid_device_ip,
    get_device_count,
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

from database.queries.maintenance import (
    cleanup_old_traffic,
    cleanup_old_alerts as maintenance_cleanup_alerts,
    cleanup_old_bandwidth_stats,
    cleanup_old_protocol_stats,
    cleanup_old_daily_usage,
    run_full_cleanup,
    get_database_size_mb,
    get_table_row_counts,
    get_maintenance_report,
    vacuum_database,
    schedule_daily_cleanup,
    stop_scheduled_cleanup,
)

__all__ = [
    # Device
    "save_packet",
    "save_packets_batch",
    "get_active_device_count",
    "get_active_devices",
    "get_all_devices",
    "get_top_devices",
    "get_device_by_ip",
    "get_device_by_mac",
    "update_device_name",
    "get_device_details",
    "is_private_ip",
    "is_valid_device_ip",
    "get_device_count",
    "update_daily_usage",
    "get_daily_usage",
    "get_device_today_usage",
    # Traffic
    "get_bandwidth_history",
    "get_bandwidth_history_dual",
    "get_bandwidth_timeseries",
    "get_protocol_distribution",
    "get_protocol_history",
    "get_top_talkers",
    "get_traffic_summary",
    "get_traffic_by_ip",
    # Alerts
    "create_alert",
    "get_alerts",
    "get_alert_by_id",
    "acknowledge_alert",
    "resolve_alert",
    "count_alerts",
    "get_alert_counts",
    "get_alert_summary",
    "delete_old_alerts",
    # Stats
    "get_realtime_stats",
    "get_health_score",
    "get_dashboard_data",
    "get_recent_activity",
    # Maintenance
    "cleanup_old_traffic",
    "maintenance_cleanup_alerts",
    "cleanup_old_bandwidth_stats",
    "cleanup_old_protocol_stats",
    "cleanup_old_daily_usage",
    "run_full_cleanup",
    "get_database_size_mb",
    "get_table_row_counts",
    "get_maintenance_report",
    "vacuum_database",
    "schedule_daily_cleanup",
    "stop_scheduled_cleanup",
]
