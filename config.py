# ============================================================
# NETWORK TRAFFIC ANALYZER - CONFIGURATION
# ============================================================


# ============================================================
# APPLICATION
# ============================================================

APPLICATION_NAME = (
    "NETWORK TRAFFIC ANALYZER"
)

APPLICATION_VERSION = (
    "1.0.0"
)


# ============================================================
# NETWORK INTERFACES
# ============================================================

WIFI_INTERFACE_NAME = (
    "Intel(R) Wi-Fi 6E AX211 160MHz"
)

LOOPBACK_INTERFACE_NAME = (
    "Software Loopback Interface 1"
)


# ============================================================
# LOGGING
# ============================================================

SECURITY_LOG_FILE = (
    "logs\\security_alerts.log"
)


# ============================================================
# DASHBOARD
# ============================================================

# Number of packets visible in LIVE PACKET STREAM
PACKET_HISTORY_SIZE = 12

# Number of historical traffic values
# stored for graphs
GRAPH_HISTORY_SIZE = 30

# Number of alerts visible on one page
ALERT_PAGE_SIZE = 8

# Dashboard refresh rate
DASHBOARD_REFRESH_RATE = 5


# ============================================================
# GRAPH
# ============================================================

GRAPH_WIDTH = 30

GRAPH_HEIGHT = 8


# ============================================================
# SECURITY DETECTORS
# ============================================================

# ------------------------------------------------------------
# Enable / disable detectors
# ------------------------------------------------------------

ENABLE_PLAINTEXT_DETECTOR = True

ENABLE_PORTSCAN_DETECTOR = True

ENABLE_TCP_FLAG_DETECTOR = True


# ============================================================
# PLAINTEXT / HTTP DETECTOR
# ============================================================

# Ports considered plaintext protocols
PLAINTEXT_PORTS = {
    21: "FTP",
    23: "TELNET",
    80: "HTTP",
    8000: "HTTP-TEST"
}


# HTTP destination ports
HTTP_PORTS = {
    80,
    8000
}


# HTTP request methods
HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH"
]


# Maximum HTTP connection buffer
MAX_HTTP_BUFFER_SIZE = 8192


# HTTP alert cooldown in seconds
HTTP_ALERT_COOLDOWN = 10


# Plaintext alert cooldown in seconds
PLAINTEXT_ALERT_COOLDOWN = 10


# Maximum number of HTTP buffers before cleanup
MAX_HTTP_BUFFERS = 1000


# Number of old HTTP buffers removed during cleanup
HTTP_BUFFER_CLEANUP_COUNT = 500


# ============================================================
# PORT SCAN DETECTOR
# ============================================================

# Number of unique destination ports required
# to trigger a port-scan alert
PORTSCAN_THRESHOLD = 10


# Time window used to count unique ports
PORTSCAN_TIME_WINDOW = 10


# Alert cooldown in seconds
PORTSCAN_ALERT_COOLDOWN = 10


# ============================================================
# TCP FLAG ANOMALY DETECTOR
# ============================================================

# Suspicious TCP flag combinations
TCP_SUSPICIOUS_COMBINATIONS = [
    {"S", "F"},
    {"S", "R"},
    {"F", "R"}
]


# Alert cooldown in seconds
TCP_FLAG_ALERT_COOLDOWN = 10


# ============================================================
# ALERT TYPES
# ============================================================

ALERT_TYPE_PLAINTEXT = "PLAINTEXT"

ALERT_TYPE_PLAINTEXT_HTTP = "PLAINTEXT HTTP"

ALERT_TYPE_PORT_SCAN = "PORT SCAN"

ALERT_TYPE_TCP_FLAG = "TCP FLAG ANOMALY"

ALERT_TYPE_TEST = "TEST ALERT"

# ============================================================
# SECURITY ALERT SEVERITY
# ============================================================

SEVERITY_LOW = "LOW"

SEVERITY_MEDIUM = "MEDIUM"

SEVERITY_HIGH = "HIGH"

SEVERITY_CRITICAL = "CRITICAL"


# ============================================================
# DEFAULT DETECTOR SEVERITY
# ============================================================

PLAINTEXT_ALERT_SEVERITY = (
    SEVERITY_MEDIUM
)

PORTSCAN_ALERT_SEVERITY = (
    SEVERITY_HIGH
)

TCP_FLAG_ALERT_SEVERITY = (
    SEVERITY_HIGH
)

# ============================================================
# LOG MANAGEMENT
# ============================================================

LOG_BACKUP_DIRECTORY = (
    "logs\\backups"
)

ARCHIVE_LOG_ON_START = True

LOG_BACKUP_PREFIX = (
    "security_alerts_"
)

# ============================================================
# BACKUP RETENTION
# ============================================================

MAX_LOG_BACKUPS = 20