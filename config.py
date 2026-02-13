# NetWatch Configuration
# This file contains all configuration constants for the NetWatch system.
# Modify these values to customize the behavior of the application.

import os
from datetime import timedelta

# =============================================================================
# APPLICATION ENVIRONMENT
# =============================================================================

import sys
import platform

# Application environment: 'development', 'production', or 'testing'
APP_ENV = os.getenv('NETWATCH_ENV', 'development')
IS_PRODUCTION = APP_ENV == 'production'
IS_TESTING = APP_ENV == 'testing'

# Application name
APP_NAME = "NetWatch"

# Application version
APP_VERSION = "2.0.0"

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform == 'darwin'
PLATFORM_NAME = platform.system()

# Debug mode (disable in production)
DEBUG_MODE = APP_ENV == 'development'

# Allow insecure requests (HTTP) - set to False in production
ALLOW_INSECURE_REQUESTS = APP_ENV != 'production'

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================

# Path to the SQLite database file
if IS_PRODUCTION:
    if IS_WINDOWS:
        _db_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'NetWatch')
    else:
        _db_dir = '/var/lib/netwatch'
    DATABASE_PATH = os.path.join(_db_dir, 'netwatch.db')
else:
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch.db")

# Database connection timeout in seconds
DATABASE_TIMEOUT = 30

# =============================================================================
# NETWORK INTERFACE CONFIGURATION
# =============================================================================

# Default network interface for packet capture
# Windows: Use interface name like "Ethernet" or "Wi-Fi"
# Linux: Use interface name like "eth0", "wlan0", "enp0s3"
# Set to None for Scapy to auto-detect
NETWORK_INTERFACE = None

# Number of packets to capture in each batch (0 = continuous)
PACKET_BATCH_SIZE = 0

# Packet capture timeout in seconds (None = no timeout)
CAPTURE_TIMEOUT = None

# =============================================================================
# MODE DETECTION SETTINGS
# =============================================================================

# How often (in seconds) the background thread re-checks the network mode
MODE_REFRESH_INTERVAL = 30

# Enable automatic mode detection in a background thread
ENABLE_AUTO_MODE_DETECTION = True

# Override: force safe (public-network) mode regardless of detection
# Useful when you want to guarantee no scanning / promiscuous behaviour
FORCE_SAFE_MODE = False

# Fraction of foreign source MACs (0.0–1.0) that indicates a port-mirror/SPAN port
PORT_MIRROR_FOREIGN_MAC_THRESHOLD = 0.50

# =============================================================================
# FLASK SERVER CONFIGURATION
# =============================================================================

# Host address for the Flask server (localhost only for security)
FLASK_HOST = "127.0.0.1"

# Port number for the Flask server
FLASK_PORT = 5000

# Enable Flask debug mode (set to False in production)
FLASK_DEBUG = APP_ENV == 'development'

# Flask session configuration
SESSION_COOKIE_SECURE = APP_ENV == 'production'  # Require HTTPS for cookies in production
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to cookies
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
PERMANENT_SESSION_LIFETIME = timedelta(hours=24)  # Session timeout

# Flask JSON configuration
JSON_SORT_KEYS = False
JSONIFY_PRETTYPRINT_REGULAR = APP_ENV == 'development'

# Maximum request size in bytes (default 16MB)
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# =============================================================================
# ANOMALY DETECTION THRESHOLDS
# =============================================================================

# Bandwidth threshold in bytes per second to trigger warning (legacy)
BANDWIDTH_WARNING_THRESHOLD = 10_000_000  # 10 MB/s

# Bandwidth threshold in bytes per second to trigger critical alert (legacy)
BANDWIDTH_CRITICAL_THRESHOLD = 50_000_000  # 50 MB/s

# ---------------------------------------------------------------------------
# Alert Thresholds (Phase 4 - human-readable units)
# ---------------------------------------------------------------------------
BANDWIDTH_WARNING_MBPS = 10     # 10 megabits per second
BANDWIDTH_CRITICAL_MBPS = 50    # 50 megabits per second

DEVICE_COUNT_WARNING = 50       # 50 local network devices
DEVICE_COUNT_CRITICAL = 100     # 100 local network devices

HEALTH_SCORE_WARNING = 50       # Health score below 50
HEALTH_SCORE_CRITICAL = 30      # Health score below 30

# Alert Deduplication
ALERT_COOLDOWN_SECONDS = 300    # 5 minutes between duplicate alerts

# Isolation Forest contamination parameter (expected proportion of anomalies)
# 0.01 = 1% false positive rate — catches real anomalies without alert fatigue
ISOLATION_FOREST_CONTAMINATION = 0.01

# Minimum number of samples before running anomaly detection
# 60 samples (~15 min at 15s intervals) — enough baseline to learn normal patterns
MIN_SAMPLES_FOR_ANOMALY_DETECTION = 60

# How often (seconds) to collect a bandwidth sample for anomaly training
STATS_COLLECTION_INTERVAL = 15

# =============================================================================
# HEALTH SCORE CONFIGURATION
# =============================================================================

# Weights for health score calculation (must sum to 1.0)
HEALTH_WEIGHT_BANDWIDTH = 0.3
HEALTH_WEIGHT_PACKET_LOSS = 0.25
HEALTH_WEIGHT_LATENCY = 0.25
HEALTH_WEIGHT_ANOMALIES = 0.2

# Health score thresholds
HEALTH_SCORE_GOOD = 80  # Score >= 80 is "Good"
HEALTH_SCORE_WARNING = 50  # Score >= 50 and < 80 is "Warning"
# Score < 50 is "Critical"

# =============================================================================
# DATA RETENTION CONFIGURATION
# =============================================================================

# Number of hours to keep detailed traffic data
TRAFFIC_DATA_RETENTION_HOURS = 24

# Number of days to keep alerts
ALERT_RETENTION_DAYS = 7

# Maximum number of records to keep in traffic_summary table
MAX_TRAFFIC_RECORDS = 1_000_000

# =============================================================================
# REFRESH INTERVALS (in seconds)
# =============================================================================

# How often the anomaly detector should run (seconds)
ANOMALY_CHECK_INTERVAL = 30

# How often to aggregate traffic statistics
STATS_AGGREGATION_INTERVAL = 60

# How often the frontend should poll for updates (used in documentation)
FRONTEND_REFRESH_INTERVAL = 3

# =============================================================================
# PROTOCOL PORT MAPPINGS
# =============================================================================

PROTOCOL_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "INFO"

# Log file path (None = console only; used by fallback logger)
LOG_FILE = None

# Log format string (used by fallback logger)
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Rotating log file settings
LOG_FILE_MAX_SIZE = 10 * 1024 * 1024   # 10 MB per file
LOG_FILE_BACKUP_COUNT = 5              # keep 5 rotated copies

# Log directory for production structured logs (JSON)
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

# =============================================================================
# CORS CONFIGURATION
# =============================================================================

# Allowed origins for CORS (in production, restrict these)
CORS_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000", "http://localhost:3000"]

# Allow credentials in CORS requests
CORS_ALLOW_CREDENTIALS = True

# =============================================================================
# ALERT SEVERITY LEVELS
# =============================================================================

# Alert severity levels
ALERT_SEVERITY_LOW = "low"
ALERT_SEVERITY_MEDIUM = "medium"
ALERT_SEVERITY_HIGH = "high"
ALERT_SEVERITY_CRITICAL = "critical"

# Alert severity thresholds (for automatic classification)
ALERT_SEVERITY_MAPPING = {
    "bandwidth_warning": ALERT_SEVERITY_MEDIUM,
    "bandwidth_critical": ALERT_SEVERITY_CRITICAL,
    "device_count_warning": ALERT_SEVERITY_LOW,
    "device_count_critical": ALERT_SEVERITY_HIGH,
    "anomaly_detected": ALERT_SEVERITY_HIGH,
    "packet_loss": ALERT_SEVERITY_MEDIUM,
}

# =============================================================================
# THREADING CONFIGURATION
# =============================================================================

# Number of worker threads for packet processing (0 = auto-detect CPU count)
PACKET_WORKER_THREADS = 0

# Queue size for buffering packets between capture and processing
PACKET_QUEUE_MAX_SIZE = 100000

# Timeout for queue operations in seconds
QUEUE_TIMEOUT_SECONDS = 1

# =============================================================================
# ANOMALY DETECTION FEATURE ENGINEERING
# =============================================================================

# Features to extract for anomaly detection model
ANOMALY_DETECTION_FEATURES = [
    "total_bandwidth",
    "active_connections",
    "unique_protocols",
    "packet_loss_rate",
    "average_latency",
    "dns_queries_count",
    "http_requests_count",
    "https_requests_count",
]

# =============================================================================
# API RESPONSE CONFIGURATION
# =============================================================================

# Maximum number of records to return in a single API response
MAX_API_RESPONSE_SIZE = 1000

# Default page size for paginated API responses
DEFAULT_PAGE_SIZE = 50

# API request timeout in seconds
API_REQUEST_TIMEOUT = 30

# =============================================================================
# DEVICE DISCOVERY CONFIGURATION
# =============================================================================

# Time in seconds to consider a device as "active" without new packets
DEVICE_INACTIVITY_TIMEOUT = 300  # 5 minutes

# Minimum number of packets from a device to track it
MIN_PACKETS_TO_TRACK_DEVICE = 5

# =============================================================================
# DATA AGGREGATION CONFIGURATION
# =============================================================================

# Interval for aggregating traffic statistics (in seconds)
TRAFFIC_STATS_AGGREGATION_INTERVAL = 60

# Number of aggregation periods to keep in memory
AGGREGATION_PERIODS_IN_MEMORY = 1440  # 24 hours if aggregation_interval is 60s

# =============================================================================
# EXPORT AND REPORTING CONFIGURATION
# =============================================================================

# Enable data export functionality
ENABLE_DATA_EXPORT = True

# Supported export formats
EXPORT_FORMATS = ["csv", "json", "xlsx"]

# Maximum export size in records
MAX_EXPORT_RECORDS = 100000

# =============================================================================
# SCAPY CONFIGURATION
# =============================================================================

# Scapy packet capture verbose level (0 = off, 1 = on)
SCAPY_VERBOSE = 0

# Packet filter (BPF syntax) - None means capture all
# Example: "tcp port 80 or tcp port 443" to capture HTTP/HTTPS only
PACKET_FILTER = None

# =============================================================================
# FEATURE FLAGS
# =============================================================================

# Enable real-time alerts
ENABLE_REALTIME_ALERTS = True

# Enable anomaly detection
ENABLE_ANOMALY_DETECTION = True

# Enable device tracking
ENABLE_DEVICE_TRACKING = True

# Enable protocol detection
ENABLE_PROTOCOL_DETECTION = True

# =============================================================================
# TIMEZONE AND LOCALIZATION
# =============================================================================

# Timezone for the application (use IANA timezone format)
TIMEZONE = "UTC"

# Date format for API responses
DATE_FORMAT = "%Y-%m-%d"

# DateTime format for API responses
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Timestamp precision in milliseconds
TIMESTAMP_PRECISION_MS = True

# =============================================================================
# CACHING CONFIGURATION
# =============================================================================

# Enable caching
ENABLE_CACHING = True

# Cache type: 'simple', 'redis', or 'memcached'
CACHE_TYPE = 'simple'

# Cache default timeout in seconds
CACHE_DEFAULT_TIMEOUT = 300

# Cache key prefix
CACHE_KEY_PREFIX = "netwatch_"

# Redis configuration (if CACHE_TYPE is 'redis')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Cache TTL for different data types
CACHE_TTL_DEVICE_LIST = 60  # 1 minute
CACHE_TTL_TRAFFIC_STATS = 30  # 30 seconds
CACHE_TTL_ALERTS = 15  # 15 seconds
CACHE_TTL_HEALTH_SCORE = 60  # 1 minute

# =============================================================================
# INPUT VALIDATION CONFIGURATION
# =============================================================================

# Maximum length for device names
MAX_DEVICE_NAME_LENGTH = 255

# Maximum length for descriptions
MAX_DESCRIPTION_LENGTH = 1000

# Valid IP address formats (IPv4, IPv6)
VALID_IP_VERSIONS = [4, 6]

# Maximum number of IPs to accept in a filter
MAX_IPS_IN_FILTER = 1000

# Regular expression patterns for validation
VALID_MAC_ADDRESS_PATTERN = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
VALID_IPADDR_PATTERN_V4 = r'^(\d{1,3}\.){3}\d{1,3}$'

# =============================================================================
# RATE LIMITING CONFIGURATION
# =============================================================================

# Enable rate limiting
ENABLE_RATE_LIMITING = APP_ENV == 'production'

# Rate limit: requests per minute per IP
RATE_LIMIT_REQUESTS_PER_MINUTE = 100

# Rate limit: requests per hour per IP
RATE_LIMIT_REQUESTS_PER_HOUR = 2000

# Bypass rate limiting for localhost
RATE_LIMIT_BYPASS_LOCALHOST = True

# =============================================================================
# ERROR RECOVERY CONFIGURATION
# =============================================================================

# Maximum number of retries for failed operations
MAX_RETRIES = 3

# Retry delay in seconds (exponential backoff)
RETRY_DELAY_SECONDS = 1

# Retry backoff multiplier
RETRY_BACKOFF_MULTIPLIER = 2

# Database connection retry attempts
DB_CONNECTION_RETRIES = 5

# Database connection retry delay in seconds
DB_CONNECTION_RETRY_DELAY = 2

# =============================================================================
# MEMORY AND PERFORMANCE OPTIMIZATION
# =============================================================================

# Maximum size of in-memory packet buffer (in packets)
PACKET_BUFFER_MAX_SIZE = 100000 if IS_PRODUCTION else 50000

# =============================================================================
# DEVICE FILTERING CONFIGURATION
# =============================================================================

# Whether to show our own device in the device list
SHOW_OWN_DEVICE = True

# Whether to show the gateway/router in device list
# Disabled by default — gateway shows as a phantom device in WiFi client mode
SHOW_GATEWAY = False

# Only show devices in the current subnet
FILTER_TO_SUBNET = True

# Maximum size of in-memory device cache
DEVICE_CACHE_MAX_SIZE = 10000

# Garbage collection interval in seconds
GARBAGE_COLLECTION_INTERVAL = 300

# Enable memory profiling (development only)
ENABLE_MEMORY_PROFILING = APP_ENV == 'development'

# =============================================================================
# BATCH PROCESSING CONFIGURATION
# =============================================================================

# Batch size for bulk database operations
DB_BATCH_SIZE = 1000

# Batch size for API responses
API_BATCH_SIZE = 100

# Time window for batch aggregation in seconds
BATCH_AGGREGATION_WINDOW = 60

# Maximum items per batch operation
MAX_BATCH_ITEMS = 5000

# =============================================================================
# MONITORING AND METRICS CONFIGURATION
# =============================================================================

# Enable metrics collection
ENABLE_METRICS = True

# Enable application performance monitoring (APM)
ENABLE_APM = APP_ENV == 'production'

# Metrics retention period in days
METRICS_RETENTION_DAYS = 30

# Metrics collection interval in seconds
METRICS_COLLECTION_INTERVAL = 60

# Track API response times
TRACK_API_RESPONSE_TIMES = True

# Track database query performance
TRACK_DB_QUERY_PERFORMANCE = APP_ENV == 'development'

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Secret key for session management and CSRF protection
# IMPORTANT: Set SECRET_KEY env var in production!
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
if IS_PRODUCTION and SECRET_KEY == 'dev-secret-key-change-in-production':
    raise RuntimeError(
        'FATAL: SECRET_KEY is using the default dev value in production! '
        'Set the SECRET_KEY environment variable before starting.'
    )

# ---------------------------------------------------------------------------
# API Authentication
# ---------------------------------------------------------------------------
# Enable API key authentication on all /api/* routes.
# In development mode this defaults to OFF so the dashboard works out-of-box.
# In production, set NETWATCH_API_KEY to enable.
AUTH_ENABLED = os.getenv('NETWATCH_AUTH_ENABLED', 'false').lower() in ('1', 'true', 'yes') or IS_PRODUCTION
API_KEY = os.getenv('NETWATCH_API_KEY', '')

# Routes that bypass authentication (health checks, static assets)
AUTH_EXEMPT_ROUTES = ['/health', '/', '/index.html', '/api/status', '/api/info']
AUTH_EXEMPT_PREFIXES = ['/css/', '/js/', '/assets/']

# API key validation (if applicable)
ENABLE_API_KEY_AUTH = False

# HTTPS enforcement
ENFORCE_HTTPS = APP_ENV == 'production'

# Enable CORS (Cross-Origin Resource Sharing)
ENABLE_CORS = True

# Allowed HTTP methods
ALLOWED_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']

# Disable HTTP methods if needed
DISABLED_HTTP_METHODS = []

# X-Frame-Options header to prevent clickjacking
X_FRAME_OPTIONS = 'SAMEORIGIN'

# Content Security Policy
CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"

# =============================================================================
# DATABASE PERFORMANCE TUNING
# =============================================================================

# SQLite PRAGMA settings
DB_JOURNAL_MODE = 'WAL'  # Write-Ahead Logging for better concurrency
DB_SYNCHRONOUS = 'NORMAL'  # Balance between safety and performance
DB_CACHE_SIZE = -64000  # 64MB cache
DB_TEMP_STORE = 'MEMORY'  # Use memory for temporary tables
DB_FOREIGN_KEYS = True  # Enable foreign key constraints
DB_BUSY_TIMEOUT = 5000  # Wait 5 seconds on locked database

# Connection pooling
# Dev needs more connections: SSE stream + dashboard + bandwidth/dual +
# capture-engine batch writes + anomaly detector + health monitor all
# run concurrently.  Nested get_connection() calls can deadlock if the
# pool is too small.
DB_CONNECTION_POOL_SIZE = 15 if IS_PRODUCTION else 15
DB_POOL_RECYCLE = 3600  # Recycle connections after 1 hour

# Query optimization
DB_QUERY_TIMEOUT = 30  # Maximum query execution time in seconds
DB_EXPLAIN_QUERY_PLAN = APP_ENV == 'development'

# =============================================================================
# FILE UPLOAD AND EXPORT CONFIGURATION
# =============================================================================

# Upload directory for temporary files
UPLOAD_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

# Allowed file extensions for upload
ALLOWED_UPLOAD_EXTENSIONS = ['txt', 'csv', 'json']

# Maximum file upload size in bytes (10MB)
MAX_UPLOAD_SIZE = 10 * 1024 * 1024

# Export directory
EXPORT_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exports")

# Compression for exports
COMPRESS_EXPORTS = True

# =============================================================================
# API CONFIGURATION
# =============================================================================

# API version
API_VERSION = "v1"

# API base path
API_BASE_PATH = f"/api/{API_VERSION}"

# Enable API documentation
ENABLE_API_DOCS = True

# API documentation path
API_DOCS_PATH = "/api/docs"

# Paginate responses by default
DEFAULT_PAGINATION_ENABLED = True

# Sort responses by default
DEFAULT_SORT_ENABLED = True

# Allow filtering by default
DEFAULT_FILTERING_ENABLED = True

# =============================================================================
# DASHBOARD CONFIGURATION
# =============================================================================

# Dashboard refresh interval in seconds (frontend polling)
# NOTE: Frontend uses DASHBOARD_UPDATE_INTERVAL from performance tuning section
DASHBOARD_REFRESH_INTERVAL = 10

# Maximum number of devices to display in real-time view
MAX_DEVICES_IN_REALTIME_VIEW = 100

# Maximum number of alerts to display in dashboard
MAX_ALERTS_IN_DASHBOARD = 50

# Chart update frequency in seconds
CHART_UPDATE_FREQUENCY = 5

# Default time range for historical data (in hours)
DEFAULT_HISTORY_RANGE_HOURS = 24

# Enable real-time WebSocket updates (if implemented)
ENABLE_WEBSOCKET_UPDATES = False

# =============================================================================
# NOTIFICATION CONFIGURATION
# =============================================================================

# Enable notifications
ENABLE_NOTIFICATIONS = True

# Notification methods
NOTIFICATION_METHODS = ['in_app']  # ['in_app', 'email', 'sms']

# Email notification settings (if email notifications enabled)
SMTP_SERVER = os.getenv('SMTP_SERVER', 'localhost')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_USE_TLS = True
EMAIL_FROM_ADDRESS = os.getenv('EMAIL_FROM_ADDRESS', 'netwatch@example.com')

# Notification throttling (prevent alert fatigue)
NOTIFICATION_THROTTLE_SECONDS = 300  # Don't send same alert more than once per 5 minutes

# =============================================================================
# PACKET CAPTURE ENGINE SETTINGS (Phase 2)
# =============================================================================

# Maximum number of packets to buffer between capture and processing threads
PACKET_QUEUE_SIZE = 100000

# Number of packets to accumulate before a single batch DB write
BATCH_SIZE = 1000

# Maximum seconds to wait before flushing a partial batch to DB
BATCH_TIMEOUT = 0.5

# Sliding window (seconds) for real-time bandwidth calculation
# 10s window retains peaks while smoothing jitter, and responds
# within 10 s when traffic stops (fixes the "bandwidth doesn't drop" bug).
BANDWIDTH_WINDOW_SECONDS = 10

# =============================================================================
# PERFORMANCE TUNING — Prevents NetWatch from degrading network performance
# =============================================================================

# Maximum packets processed per second (0 = unlimited).
# Set to 0 for accurate bandwidth monitoring — the Scapy capture engine
# already uses BPF filters to limit captured traffic to our own host.
# A non-zero cap (e.g. 200) will silently drop packets during high-throughput
# activities like HD video streaming and yield inaccurate bandwidth readings.
MAX_PACKETS_PER_SECOND = 0

# Packet sampling rate: process 1 out of every N packets.
# Set to 1 to process every packet (full fidelity).
# Set to 5-10 on busy networks to reduce CPU load.
# Bandwidth stats are scaled up automatically so totals stay accurate.
PACKET_SAMPLE_RATE = 1

# Dashboard polling interval (seconds) — how often the frontend fetches data.
# Lower = more responsive but more API / DB load.
DASHBOARD_UPDATE_INTERVAL = 10

# SSE (Server-Sent Events) push interval in seconds
SSE_PUSH_INTERVAL = 3

# =============================================================================
# PACKET CAPTURE ADVANCED SETTINGS
# =============================================================================

# Enable promiscuous mode (capture all packets on network)
# NOTE: Phase 2 CaptureEngine uses mode.should_use_promiscuous() instead.
# This flag is retained only for legacy/manual override.
ENABLE_PROMISCUOUS_MODE = True

# Packet snaplen (packet size to capture in bytes)
PACKET_SNAPLEN = 65535  # Capture full packet

# Enable hardware acceleration if available
ENABLE_HW_ACCELERATION = True

# Packet capture error handling
CAPTURE_ERROR_RECOVERY = True
CAPTURE_ERROR_MAX_RETRIES = 5

# =============================================================================
# STATISTICS AND REPORTING
# =============================================================================

# Enable detailed statistics
ENABLE_DETAILED_STATS = True

# Report generation interval in hours
REPORT_GENERATION_INTERVAL = 24

# Number of top N items to track (top devices, top protocols, etc.)
TOP_ITEMS_COUNT = 10

# Statistical percentiles to track (for latency, bandwidth)
PERCENTILES = [50, 75, 90, 95, 99]

# =============================================================================
# CLEANUP AND MAINTENANCE
# =============================================================================

# Enable automatic cleanup tasks
ENABLE_AUTO_CLEANUP = True

# Cleanup check interval in seconds
CLEANUP_CHECK_INTERVAL = 3600  # 1 hour

# Database maintenance interval in seconds
DB_MAINTENANCE_INTERVAL = 86400  # 24 hours

# Empty trash/temp files older than (in days)
TRASH_CLEANUP_DAYS = 7

# =============================================================================
# TESTING CONFIGURATION
# =============================================================================

# Test mode flag
TEST_MODE = APP_ENV == 'testing'

# Use mock data in test mode
USE_MOCK_DATA = TEST_MODE

# Test database path
TEST_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_netwatch.db")

# =============================================================================
# ADDITIONAL LOGGING (production overrides)
# =============================================================================

# Log file for production (overrides the earlier LOG_FILE = None default)
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "netwatch.log") if APP_ENV == 'production' else None

# Log file maximum size in bytes (10MB)
LOG_FILE_MAX_SIZE = 10 * 1024 * 1024

# Number of log files to keep (rotation)
LOG_FILE_BACKUP_COUNT = 10

# Enable request logging
ENABLE_REQUEST_LOGGING = APP_ENV == 'development'

# Enable database query logging
ENABLE_QUERY_LOGGING = APP_ENV == 'development'
