from scapy.all import sniff, IP, TCP, UDP, Raw, conf

from alert_manager import AlertManager

import time
import config


# ============================================================
# PLAINTEXT PROTOCOLS
# ============================================================

PLAINTEXT_PORTS = (
    config.PLAINTEXT_PORTS
)


# ============================================================
# ALERT MANAGER
# ============================================================

alert_manager = AlertManager()


def set_alert_manager(manager):
    """
    Use the shared AlertManager created by main.py.
    """

    global alert_manager

    alert_manager = manager


# ============================================================
# HTTP SETTINGS
# ============================================================

HTTP_PORTS = (
    config.HTTP_PORTS
)

HTTP_METHODS = (
    config.HTTP_METHODS
)

MAX_HTTP_BUFFER_SIZE = (
    config.MAX_HTTP_BUFFER_SIZE
)

HTTP_ALERT_COOLDOWN = (
    config.HTTP_ALERT_COOLDOWN
)


# ============================================================
# HTTP BUFFERS
# ============================================================

http_buffers = {}

http_last_alert = {}


# ============================================================
# PLAINTEXT ALERT TRACKING
# ============================================================

last_plaintext_alert = {}

PLAINTEXT_ALERT_COOLDOWN = (
    config.PLAINTEXT_ALERT_COOLDOWN
)


# ============================================================
# HTTP REQUEST DETECTION
# ============================================================

def detect_http_request(packet):

    # --------------------------------------------------------
    # Check IP
    # --------------------------------------------------------

    if IP not in packet:
        return

    # --------------------------------------------------------
    # Check TCP
    # --------------------------------------------------------

    if TCP not in packet:
        return

    source_port = packet[TCP].sport

    destination_port = packet[TCP].dport

    # --------------------------------------------------------
    # HTTP request normally goes TO port 80 or 8000
    # --------------------------------------------------------

    if destination_port not in HTTP_PORTS:
        return

    # --------------------------------------------------------
    # HTTP request needs TCP payload
    # --------------------------------------------------------

    if Raw not in packet:
        return

    try:

        payload = packet[Raw].load.decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:

        return

    if not payload:
        return

    # ========================================================
    # CONNECTION ID
    # ========================================================

    connection_id = (
        packet[IP].src,
        source_port,
        packet[IP].dst,
        destination_port
    )

    if connection_id not in http_buffers:

        http_buffers[connection_id] = ""

    http_buffers[connection_id] += payload

    # ========================================================
    # PROTECT BUFFER
    # ========================================================

    if (
        len(
            http_buffers[connection_id]
        )
        > MAX_HTTP_BUFFER_SIZE
    ):

        http_buffers[connection_id] = (
            http_buffers[connection_id]
            [-MAX_HTTP_BUFFER_SIZE:]
        )

    data = http_buffers[
        connection_id
    ]

    # ========================================================
    # WAIT FOR COMPLETE HTTP HEADERS
    # ========================================================

    if "\r\n\r\n" not in data:

        return

    header_part = data.split(
        "\r\n\r\n",
        1
    )[0]

    lines = header_part.split(
        "\r\n"
    )

    if not lines:

        return

    request_line = lines[0]

    # ========================================================
    # DETECT METHOD
    # ========================================================

    detected_method = None

    for method in HTTP_METHODS:

        if request_line.startswith(
            method + " "
        ):

            detected_method = method

            break

    # ========================================================
    # NOT AN HTTP REQUEST
    # ========================================================

    if detected_method is None:

        http_buffers[
            connection_id
        ] = ""

        return

    # ========================================================
    # EXTRACT PATH
    # ========================================================

    parts = request_line.split(
        " "
    )

    if len(parts) >= 2:

        path = parts[1]

    else:

        path = "Unknown"

    # ========================================================
    # EXTRACT HTTP VERSION
    # ========================================================

    if len(parts) >= 3:

        http_version = parts[2]

    else:

        http_version = "Unknown"

    # ========================================================
    # EXTRACT HOST
    # ========================================================

    host = "Unknown"

    for line in lines:

        if line.lower().startswith(
            "host:"
        ):

            host = line.split(
                ":",
                1
            )[1].strip()

            break

    # ========================================================
    # REQUEST ID
    # ========================================================

    request_id = (
        packet[IP].src,
        packet[IP].dst,
        destination_port,
        detected_method,
        path
    )

    current_time = time.time()

    previous_alert = http_last_alert.get(
        request_id,
        0
    )

    # ========================================================
    # DISPLAY HTTP REQUEST
    # ========================================================

    print()

    print(
        "========================================"
    )

    print(
        "       HTTP REQUEST DETECTED"
    )

    print(
        "========================================"
    )

    print(
        "Method          :",
        detected_method
    )

    print(
        "Path            :",
        path
    )

    print(
        "Host            :",
        host
    )

    print(
        "HTTP Version    :",
        http_version
    )

    print(
        "Source IP       :",
        packet[IP].src
    )

    print(
        "Destination IP  :",
        packet[IP].dst
    )

    print(
        "Source Port     :",
        source_port
    )

    print(
        "Destination Port:",
        destination_port
    )

    print(
        "========================================"
    )

    # ========================================================
    # SEND ALERT
    # ========================================================

    if (
        current_time
        - previous_alert
        >= HTTP_ALERT_COOLDOWN
    ):

        alert_manager.add_alert(

            config.ALERT_TYPE_PLAINTEXT_HTTP,

            packet[IP].src,

            packet[IP].dst,

            (
                f"{detected_method} request "
                f"detected on port "
                f"{destination_port} "
                f"for {path}"
            ),

            config.PLAINTEXT_ALERT_SEVERITY
        )

        http_last_alert[
            request_id
        ] = current_time

    # ========================================================
    # CLEAR BUFFER
    # ========================================================

    http_buffers[
        connection_id
    ] = ""


# ============================================================
# PLAINTEXT TRAFFIC DETECTION
# ============================================================

def detect_plaintext(packet):

    # --------------------------------------------------------
    # Check IP
    # --------------------------------------------------------

    if IP not in packet:
        return

    source_port = None
    destination_port = None
    protocol = None

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if TCP in packet:

        protocol = "TCP"

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif UDP in packet:

        protocol = "UDP"

        source_port = packet[UDP].sport

        destination_port = packet[UDP].dport

    else:

        return

    # ========================================================
    # CHECK PLAINTEXT PORT
    # ========================================================

    detected_protocol = None

    if destination_port in PLAINTEXT_PORTS:

        detected_protocol = (
            PLAINTEXT_PORTS[
                destination_port
            ]
        )

    elif source_port in PLAINTEXT_PORTS:

        detected_protocol = (
            PLAINTEXT_PORTS[
                source_port
            ]
        )

    if not detected_protocol:

        return

    # ========================================================
    # HTTP IS HANDLED BY HTTP DETECTOR
    # ========================================================

    if detected_protocol in {
        "HTTP",
        "HTTP-TEST"
    }:

        return

    # ========================================================
    # ALERT KEY
    # ========================================================

    alert_key = (
        packet[IP].src,
        packet[IP].dst,
        detected_protocol
    )

    current_time = time.time()

    previous_alert = last_plaintext_alert.get(
        alert_key,
        0
    )

    # ========================================================
    # COOLDOWN
    # ========================================================

    if (
        current_time
        - previous_alert
        < PLAINTEXT_ALERT_COOLDOWN
    ):

        return

    # ========================================================
    # DISPLAY WARNING
    # ========================================================

    print()

    print(
        "========================================"
    )

    print(
        "  WARNING: PLAINTEXT TRAFFIC DETECTED"
    )

    print(
        "========================================"
    )

    print(
        "Protocol        :",
        detected_protocol
    )

    print(
        "Transport       :",
        protocol
    )

    print(
        "Source IP       :",
        packet[IP].src
    )

    print(
        "Destination IP  :",
        packet[IP].dst
    )

    print(
        "Source Port     :",
        source_port
    )

    print(
        "Destination Port:",
        destination_port
    )

    print(
        "========================================"
    )

    # ========================================================
    # ALERT MANAGER
    # ========================================================

    alert_manager.add_alert(

        f"PLAINTEXT {detected_protocol}",

        packet[IP].src,

        packet[IP].dst,

        (
            f"{detected_protocol} traffic "
            f"detected on port "
            f"{destination_port}"
        ),

        config.PLAINTEXT_ALERT_SEVERITY
    )

    last_plaintext_alert[
        alert_key
    ] = current_time


# ============================================================
# MAIN ANALYZER INTERFACE
# ============================================================

def analyze_packet(packet):

    if not config.ENABLE_PLAINTEXT_DETECTOR:

        return

    detect_plaintext(packet)

    detect_http_request(packet)


# ============================================================
# CLEAN OLD HTTP BUFFERS
# ============================================================

def cleanup_http_buffers():

    if len(http_buffers) <= (
        config.MAX_HTTP_BUFFERS
    ):

        return

    connection_ids = list(
        http_buffers.keys()
    )

    for connection_id in (
        connection_ids[
            :config.HTTP_BUFFER_CLEANUP_COUNT
        ]
    ):

        http_buffers.pop(
            connection_id,
            None
        )


# ============================================================
# START DETECTOR DIRECTLY
# ============================================================

def start_plaintext_detector():

    print(
        "========================================"
    )

    print(
        "       PLAINTEXT TRAFFIC DETECTOR"
    )

    print(
        "========================================"
    )

    print()

    print(
        "Monitoring:"
    )

    print(
        "HTTP       : Port 80"
    )

    print(
        "HTTP TEST  : Port 8000"
    )

    print(
        "FTP        : Port 21"
    )

    print(
        "TELNET     : Port 23"
    )

    print()

    print(
        "HTTP Request Detection: ENABLED"
    )

    print(
        "AlertManager           : ENABLED"
    )

    print(
        "Interface              : Windows Loopback"
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print()

    try:

        while True:

            sniff(

                iface=r"\Device\NPF_Loopback",

                filter="tcp or udp",

                prn=analyze_packet,

                store=False,

                timeout=1
            )

            cleanup_http_buffers()

    except KeyboardInterrupt:

        print()

        print(
            "========================================"
        )

        print(
            "Plaintext detector stopped."
        )

        print(
            "========================================"
        )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    start_plaintext_detector()