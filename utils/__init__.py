# Utils package

from utils.formatters import format_bandwidth_rate, format_total_data, bytes_to_mbps

try:
    from utils.health_monitor import HealthMonitor
    HEALTH_MONITOR_AVAILABLE = True
except ImportError:
    HealthMonitor = None
    HEALTH_MONITOR_AVAILABLE = False

try:
    from utils.logger import setup_logging
    from utils.performance_logger import log_performance, log_system_health
    from utils.exceptions import (
        NetWatchError, CaptureError, DatabaseError,
        ConfigurationError, APIError, retry, CircuitBreaker,
    )
    from utils.metrics import metrics_collector
    PRODUCTION_UTILS_AVAILABLE = True
except ImportError:
    PRODUCTION_UTILS_AVAILABLE = False
