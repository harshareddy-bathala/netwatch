# NetWatch Configuration
# This file contains all configuration constants for the NetWatch system.
# Modify these values to customize the behavior of the application.

import os

# ---------------------------------------------------------------------------
# Load .env file (lightweight, no external dependency)
# ---------------------------------------------------------------------------
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.isfile(_ENV_PATH):
    with open(_ENV_PATH, encoding="utf-8") as _fh:
        for _line in _fh:
            _line = _line.strip()
            if not _line or _line.startswith("#"):
                continue
            if "=" in _line:
                _key, _, _val = _line.partition("=")
                _key = _key.strip()
                _val = _val.strip().strip('"').strip("'")
                # Only set if not already provided by the real environment
                if _key and not os.environ.get(_key):
                    os.environ[_key] = _val

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

# Application version — single source of truth from VERSION file
_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VERSION')
try:
    with open(_VERSION_FILE, encoding='utf-8') as _vf:
        APP_VERSION = _vf.read().strip()
except FileNotFoundError:
    APP_VERSION = '0.0.0'

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
if os.getenv('DATABASE_PATH'):
    DATABASE_PATH = os.getenv('DATABASE_PATH')
elif IS_PRODUCTION:
    if IS_WINDOWS:
        _db_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'NetWatch')
    else:
        _db_dir = '/var/lib/netwatch'
    DATABASE_PATH = os.path.join(_db_dir, 'netwatch.db')
else:
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netwatch.db")

# Database connection timeout in seconds.
# SQLite allows only one writer at a time; this is how long a thread
# waits for the write-lock before raising "database is locked".
DATABASE_TIMEOUT = 60

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

# Fraction of foreign source MACs (0.0-1.0) that indicates a port-mirror/SPAN port.
# NOTE: Port mirror is ONLY detected on Ethernet interfaces.  Wi-Fi cannot carry
# mirrored traffic (shared wireless medium causes false positives).  A physical
# Ethernet cable to a managed switch's SPAN/mirror port is required.
PORT_MIRROR_FOREIGN_MAC_THRESHOLD = 0.50

# =============================================================================
# FLASK SERVER CONFIGURATION
# =============================================================================

# Host address for the Flask server (localhost only for security)
FLASK_HOST = os.getenv('FLASK_HOST', '127.0.0.1')

# Port number for the Flask server
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))

# Enable Flask debug mode (set to False in production)
FLASK_DEBUG = APP_ENV == 'development'

# Waitress WSGI server thread count
WAITRESS_THREADS = int(os.getenv('WAITRESS_THREADS', '8'))

# =============================================================================
# ANOMALY DETECTION THRESHOLDS
# =============================================================================

# ---------------------------------------------------------------------------
# Alert Thresholds (human-readable units)
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
# 30 samples (~7.5 min at 15s intervals) — enough baseline to learn normal
# patterns while reducing the warmup window where detection is inactive.
MIN_SAMPLES_FOR_ANOMALY_DETECTION = 30

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
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Log file path (set automatically for production; None = console only in dev)
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "netwatch.log") if APP_ENV == 'production' else None

# Log format string (used by fallback logger)
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Rotating log file settings
LOG_FILE_MAX_SIZE = 50 * 1024 * 1024   # 50 MB per file
LOG_FILE_BACKUP_COUNT = 5              # keep 5 rotated copies

# Log directory for production structured logs (JSON)
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

# =============================================================================
# CORS CONFIGURATION
# =============================================================================

# Allowed origins for CORS (in production, restrict to your deployment URL)
# localhost:3000 is included for development with a separate frontend dev server
# Read from CORS_ORIGINS env var (comma-separated) or use defaults
_cors_env = os.getenv('CORS_ORIGINS')
CORS_ORIGINS = _cors_env.split(',') if _cors_env else [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://localhost:5000",
    "https://127.0.0.1:5000",
]

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
    "tcp_retransmit_ratio",
    "icmp_unreachable_rate",
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
# Reserved for a future Redis integration. NetWatch currently uses
# in-memory TTLCache only.

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
# Enabled so all network devices (including the router) are visible.
# In WiFi client mode the gateway is legitimately part of the network.
SHOW_GATEWAY = True

# Only show devices in the current subnet
FILTER_TO_SUBNET = True

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

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Secret key for session management and CSRF protection
# IMPORTANT: Set SECRET_KEY env var in production!
_secret_key_env = os.getenv('SECRET_KEY')
if _secret_key_env:
    SECRET_KEY = _secret_key_env
elif IS_PRODUCTION:
    raise RuntimeError(
        'FATAL: SECRET_KEY environment variable is not set! '
        'Set the SECRET_KEY environment variable before starting in production.'
    )
else:
    SECRET_KEY = 'dev-secret-key-change-in-production'

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

# Enable CORS (Cross-Origin Resource Sharing)
ENABLE_CORS = True

# Allowed HTTP methods
ALLOWED_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']

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
DB_CONNECTION_POOL_SIZE = int(os.getenv('DB_CONNECTION_POOL_SIZE', '15'))

# Query optimization
DB_QUERY_TIMEOUT = 30  # Maximum query execution time in seconds

# Busy handler timeout — increase for port mirror high-write scenarios
DB_BUSY_TIMEOUT = int(os.getenv('DB_BUSY_TIMEOUT', '10000'))

# =============================================================================
# DASHBOARD CONFIGURATION (reserved — frontend uses DASHBOARD_UPDATE_INTERVAL)
# =============================================================================

# =============================================================================
# NOTIFICATION CONFIGURATION (reserved for future email/SMS integration)
# =============================================================================

# =============================================================================
# PACKET CAPTURE ENGINE SETTINGS (Phase 2)
# =============================================================================

# Maximum number of packets to buffer between capture and processing threads
PACKET_QUEUE_SIZE = 100000

# Number of packets to accumulate before a single batch DB write
BATCH_SIZE = 500

# Maximum seconds to wait before flushing a partial batch to DB
BATCH_TIMEOUT = 1.0

# Sliding window (seconds) for real-time bandwidth calculation.
# 30s smooths bursty protocols like YouTube (which downloads in 3-5s
# bursts separated by 10-15s pauses while the player drains its buffer).
# A 10s window drops to zero between bursts; 30s keeps at least one
# burst in the window for a stable, realistic rate display.
# Still drops to 0 within 30s when traffic truly stops.
BANDWIDTH_WINDOW_SECONDS = 30

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

# Maximum simultaneous SSE connections (prevents resource exhaustion)
SSE_MAX_CONNECTIONS = int(os.getenv('SSE_MAX_CONNECTIONS', '10'))

# =============================================================================
# PACKET CAPTURE ADVANCED SETTINGS
# =============================================================================

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

# (Reserved for future per-report settings)

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
# 24/7 PRODUCTION HARDENING (Phase 3)
# =============================================================================

# Maximum database size before emergency cleanup triggers (GB)
MAX_DATABASE_SIZE_GB = float(os.getenv('MAX_DATABASE_SIZE_GB', '20'))

# Emergency retention when disk is low (hours)
EMERGENCY_RETENTION_HOURS = int(os.getenv('EMERGENCY_RETENTION_HOURS', '6'))

# Batch size for hourly mini-cleanup (rows per DELETE)
HOURLY_CLEANUP_BATCH_SIZE = int(os.getenv('HOURLY_CLEANUP_BATCH_SIZE', '10000'))

# WAL checkpoint interval in minutes (0 = disabled)
WAL_CHECKPOINT_INTERVAL_MINUTES = int(os.getenv('WAL_CHECKPOINT_INTERVAL_MINUTES', '30'))

# Disk space warning/critical thresholds (percentage free)
DISK_SPACE_WARNING_PERCENT = int(os.getenv('DISK_SPACE_WARNING_PERCENT', '10'))
DISK_SPACE_CRITICAL_PERCENT = int(os.getenv('DISK_SPACE_CRITICAL_PERCENT', '5'))

# Port mirror specific settings
PORT_MIRROR_MAX_PPS = int(os.getenv('PORT_MIRROR_MAX_PPS', '5000'))
PORT_MIRROR_MAX_UNIQUE_MACS_PER_MINUTE = int(os.getenv('PORT_MIRROR_MAX_UNIQUE_MACS', '500'))
PORT_MIRROR_CONNECTION_TIMEOUT = int(os.getenv('PORT_MIRROR_CONNECTION_TIMEOUT', '300'))

# Memory management: stale device pruning interval (seconds)
STALE_DEVICE_PRUNE_INTERVAL = int(os.getenv('STALE_DEVICE_PRUNE_INTERVAL', '300'))
STALE_DEVICE_TIMEOUT_HOURS = int(os.getenv('STALE_DEVICE_TIMEOUT_HOURS', '2'))
MAX_IN_MEMORY_DEVICES = int(os.getenv('MAX_IN_MEMORY_DEVICES', '10000'))

# Write queue overflow thresholds (percentage of BATCH_SIZE * max_queue_batches)
WRITE_QUEUE_WARNING_PERCENT = 80
WRITE_QUEUE_CRITICAL_PERCENT = 95

# DatabaseWriter queue size (number of batch slots).
# Higher values provide more buffer for high-traffic modes (port_mirror).
# Default 500 = 500 batches * BATCH_SIZE packets of headroom.
DB_WRITER_QUEUE_SIZE = int(os.getenv('DB_WRITER_QUEUE_SIZE', '500'))

# =============================================================================
# TESTING CONFIGURATION
# =============================================================================

# Test mode flag
TEST_MODE = APP_ENV == 'testing'

# Use mock data in test mode
USE_MOCK_DATA = TEST_MODE

# Test database path
TEST_DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_netwatch.db")

