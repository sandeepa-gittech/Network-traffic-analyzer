from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from collections import deque
from datetime import datetime

import time
import msvcrt
import threading
import os
import config


# ============================================================
# PROFESSIONAL TERMINAL THEME
# ============================================================

TEXT_COLOR = "bright_white"
LIVE_COLOR = "bright_green"
PACKET_COLOR = "green"
TELEMETRY_COLOR = "cyan"
GRAPH_COLOR = "blue"
GRAPH_DATA_COLOR = "bright_cyan"
GENERATOR_COLOR = "magenta"
SECURITY_COLOR = "red"
STATUS_COLOR = "yellow"
FOOTER_COLOR = "bright_white"


# ============================================================
# SEVERITY COLORS
# ============================================================

SEVERITY_LOW_COLOR = "green"
SEVERITY_MEDIUM_COLOR = "yellow"
SEVERITY_HIGH_COLOR = "red"
SEVERITY_CRITICAL_COLOR = "bright_red"


# ============================================================
# GRAPH CONFIGURATION
# ============================================================

GRAPH_HISTORY_SIZE = (
    config.GRAPH_HISTORY_SIZE
)

GRAPH_WIDTH = (
    config.GRAPH_WIDTH
)

GRAPH_HEIGHT = (
    config.GRAPH_HEIGHT
)


# ============================================================
# DASHBOARD STATE
# ============================================================

class DashboardState:

    def __init__(self):

        self.lock = threading.Lock()

        # ----------------------------------------------------
        # Traffic statistics
        # ----------------------------------------------------

        self.total_packets = 0
        self.total_bytes = 0

        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.other_packets = 0

        self.wifi_packets = 0
        self.loopback_packets = 0

        # ----------------------------------------------------
        # Interval statistics
        # ----------------------------------------------------

        self.interval_packets = 0
        self.interval_bytes = 0

        self.last_update_time = time.time()

        self.packets_per_second = 0.0
        self.bytes_per_second = 0.0

        # ----------------------------------------------------
        # Graph history
        # ----------------------------------------------------

        self.packet_rate_history = deque(
            maxlen=GRAPH_HISTORY_SIZE
        )

        self.byte_rate_history = deque(
            maxlen=GRAPH_HISTORY_SIZE
        )

        # ----------------------------------------------------
        # Stable graph scales
        # ----------------------------------------------------

        self.packet_graph_scale = 1.0

        self.bandwidth_graph_scale = 1.0

        # ----------------------------------------------------
        # Packet history
        # ----------------------------------------------------

        self.packet_history = deque(
            maxlen=config.PACKET_HISTORY_SIZE
        )

        # ----------------------------------------------------
        # Top network generators
        # ----------------------------------------------------

        self.source_counter = {}

        # ----------------------------------------------------
        # Security log cache
        # ----------------------------------------------------

        self.cached_log_mtime = 0
        self.cached_log_signature = None

        self.cached_alert_counts = {
            "PLAINTEXT HTTP": 0,
            "PORT SCAN": 0,
            "TCP FLAG ANOMALY": 0,
            "TEST ALERT": 0,

            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        self.cached_alerts = []

        # ----------------------------------------------------
        # Interface status
        # ----------------------------------------------------

        self.wifi_status = "STARTING"
        self.loopback_status = "STARTING"

        # ----------------------------------------------------
        # Security detector status
        # ----------------------------------------------------

        self.http_status = "ON"
        self.portscan_status = "ON"
        self.tcpflag_status = "ON"


    # ========================================================
    # ADD PACKET
    # ========================================================

    def add_packet(
        self,
        packet_data
    ):

        with self.lock:

            packet_size = packet_data.get(
                "size",
                0
            )

            self.total_packets += 1
            self.total_bytes += packet_size

            self.interval_packets += 1
            self.interval_bytes += packet_size

            protocol = packet_data.get(
                "protocol",
                "OTHER"
            )

            if protocol == "TCP":

                self.tcp_packets += 1

            elif protocol == "UDP":

                self.udp_packets += 1

            elif protocol == "ICMP":

                self.icmp_packets += 1

            else:

                self.other_packets += 1

            # ------------------------------------------------
            # Interface statistics
            # ------------------------------------------------

            interface = packet_data.get(
                "interface"
            )

            if interface == "Wi-Fi":

                self.wifi_packets += 1

            elif interface == "Loopback":

                self.loopback_packets += 1

            # ------------------------------------------------
            # Source IP counter
            # ------------------------------------------------

            source_ip = packet_data.get(
                "src",
                "-"
            )

            self.source_counter[source_ip] = (
                self.source_counter.get(
                    source_ip,
                    0
                ) + 1
            )

            # ------------------------------------------------
            # Packet history
            # ------------------------------------------------

            self.packet_history.appendleft(
                packet_data
            )


    # ========================================================
    # UPDATE RATES
    # ========================================================

    def update_rates(self):

        with self.lock:

            current_time = time.time()

            elapsed = (
                current_time
                - self.last_update_time
            )

            if elapsed <= 0:

                elapsed = 1

            self.packets_per_second = (
                self.interval_packets
                / elapsed
            )

            self.bytes_per_second = (
                self.interval_bytes
                / elapsed
            )

            # ------------------------------------------------
            # Save graph history
            # ------------------------------------------------

            self.packet_rate_history.append(
                self.packets_per_second
            )

            self.byte_rate_history.append(
                self.bytes_per_second
            )

            # ------------------------------------------------
            # Reset interval counters
            # ------------------------------------------------

            self.interval_packets = 0
            self.interval_bytes = 0

            self.last_update_time = current_time


    # ========================================================
    # UPDATE GRAPH SCALES
    # ========================================================

    def update_graph_scales(self):

        with self.lock:

            # ------------------------------------------------
            # Packet graph scale
            # ------------------------------------------------

            if self.packet_rate_history:

                packet_peak = max(
                    self.packet_rate_history
                )

                target_packet_scale = max(
                    1.0,
                    packet_peak * 1.20
                )

                if target_packet_scale > (
                    self.packet_graph_scale
                ):

                    self.packet_graph_scale = (
                        target_packet_scale
                    )

                else:

                    self.packet_graph_scale += (
                        target_packet_scale
                        - self.packet_graph_scale
                    ) * 0.05

            # ------------------------------------------------
            # Bandwidth graph scale
            # ------------------------------------------------

            if self.byte_rate_history:

                bandwidth_peak = max(
                    self.byte_rate_history
                )

                target_bandwidth_scale = max(
                    1.0,
                    bandwidth_peak * 1.20
                )

                if target_bandwidth_scale > (
                    self.bandwidth_graph_scale
                ):

                    self.bandwidth_graph_scale = (
                        target_bandwidth_scale
                    )

                else:

                    self.bandwidth_graph_scale += (
                        target_bandwidth_scale
                        - self.bandwidth_graph_scale
                    ) * 0.05


    # ========================================================
    # SET INTERFACE STATUS
    # ========================================================

    def set_interface_status(
        self,
        interface_name,
        status
    ):

        with self.lock:

            if interface_name == "Wi-Fi":

                self.wifi_status = status

            elif interface_name == "Loopback":

                self.loopback_status = status


# ============================================================
# FORMAT BYTES
# ============================================================

def format_bytes(value):

    if value >= 1024 * 1024:

        return (
            f"{value / (1024 * 1024):.2f} MB"
        )

    if value >= 1024:

        return (
            f"{value / 1024:.2f} KB"
        )

    return (
        f"{value:.0f} B"
    )


# ============================================================
# NORMALIZE SEVERITY
# ============================================================

def normalize_severity(
    severity
):

    if not severity:

        return config.SEVERITY_MEDIUM

    severity = (
        str(severity)
        .strip()
        .upper()
    )

    valid_severities = {
        config.SEVERITY_LOW,
        config.SEVERITY_MEDIUM,
        config.SEVERITY_HIGH,
        config.SEVERITY_CRITICAL
    }

    if severity not in valid_severities:

        return config.SEVERITY_MEDIUM

    return severity


# ============================================================
# FIND HISTORICAL SECURITY LOG FILES
# ============================================================

def get_historical_log_files(
    log_file
):
    """
    Return archived security log files stored in the backup
    directory, excluding the current session log.
    """

    log_path = os.path.abspath(
        log_file
    )

    log_directory = os.path.dirname(
        log_path
    )

    backup_directory = os.path.join(
        log_directory,
        "backups"
    )

    try:
        if not os.path.isdir(
            backup_directory
        ):
            return []

        files = []

        for filename in os.listdir(
            backup_directory
        ):

            if not filename.lower().endswith(
                ".log"
            ):
                continue

            full_path = os.path.join(
                backup_directory,
                filename
            )

            if os.path.isfile(
                full_path
            ):
                files.append(
                    full_path
                )

        return sorted(
            files
        )

    except OSError:
        return []


# ============================================================
# PARSE ONE SECURITY LOG FILE
# ============================================================

def parse_security_log(
    log_file
):
    """
    Parse one security log file and return:
        counts, alerts
    """

    counts = {
        "PLAINTEXT HTTP": 0,
        "PORT SCAN": 0,
        "TCP FLAG ANOMALY": 0,
        "TEST ALERT": 0,

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    all_alerts = []

    try:

        with open(
            log_file,
            "r",
            encoding="utf-8"
        ) as file:

            lines = file.readlines()

    except (
        FileNotFoundError,
        OSError
    ):

        return (
            counts,
            all_alerts
        )

    current_alert = {}

    for line in lines:

        line = line.strip()

        # ----------------------------------------------------
        # TIME
        # ----------------------------------------------------

        if line.startswith(
            "Time"
        ):

            parts = line.split(
                ":",
                1
            )

            if len(parts) == 2:

                current_alert[
                    "time"
                ] = parts[1].strip()

        # ----------------------------------------------------
        # SEVERITY
        # ----------------------------------------------------

        elif line.startswith(
            "Severity"
        ):

            parts = line.split(
                ":",
                1
            )

            if len(parts) == 2:

                current_alert[
                    "severity"
                ] = normalize_severity(
                    parts[1].strip()
                )

        # ----------------------------------------------------
        # ALERT TYPE
        # ----------------------------------------------------

        elif line.startswith(
            "Alert Type"
        ):

            parts = line.split(
                ":",
                1
            )

            if len(parts) == 2:

                alert_type = (
                    parts[1].strip()
                )

                current_alert[
                    "type"
                ] = alert_type

                if alert_type in (
                    "PLAINTEXT HTTP",
                    "PORT SCAN",
                    "TCP FLAG ANOMALY",
                    "TEST ALERT"
                ):

                    counts[
                        alert_type
                    ] += 1

        # ----------------------------------------------------
        # SOURCE IP
        # ----------------------------------------------------

        elif line.startswith(
            "Source IP"
        ):

            parts = line.split(
                ":",
                1
            )

            if len(parts) == 2:

                current_alert[
                    "source"
                ] = parts[1].strip()

        # ----------------------------------------------------
        # DESTINATION IP
        # ----------------------------------------------------

        elif line.startswith(
            "Destination IP"
        ):

            parts = line.split(
                ":",
                1
            )

            if len(parts) == 2:

                current_alert[
                    "destination"
                ] = parts[1].strip()

        # ----------------------------------------------------
        # DETAILS
        # ----------------------------------------------------

        elif line.startswith(
            "Details"
        ):

            parts = line.split(
                ":",
                1
            )

            if len(parts) == 2:

                current_alert[
                    "details"
                ] = parts[1].strip()

                # Old logs without Severity are MEDIUM.
                current_alert[
                    "severity"
                ] = normalize_severity(
                    current_alert.get(
                        "severity"
                    )
                )

                counts[
                    current_alert["severity"]
                ] += 1

                all_alerts.append(
                    current_alert.copy()
                )

                current_alert = {}

    return (
        counts,
        all_alerts
    )


# ============================================================
# READ SECURITY LOGS WITH CACHE
# ============================================================

def read_security_alerts(
    log_file,
    state=None
):

    # --------------------------------------------------------
    # Current session log modification time
    # --------------------------------------------------------

    try:

        current_mtime = os.path.getmtime(
            log_file
        )

    except OSError:

        current_mtime = 0

    # --------------------------------------------------------
    # Historical backup log modification state
    # --------------------------------------------------------

    historical_files = get_historical_log_files(
        log_file
    )

    historical_mtimes = []

    for filename in historical_files:

        try:

            historical_mtimes.append(
                (
                    filename,
                    os.path.getmtime(
                        filename
                    )
                )
            )

        except OSError:

            historical_mtimes.append(
                (
                    filename,
                    0
                )
            )

    cache_key = (
        current_mtime,
        tuple(
            historical_mtimes
        )
    )

    # --------------------------------------------------------
    # Use cache if nothing changed
    # --------------------------------------------------------

    if state is not None:

        with state.lock:

            if (
                getattr(
                    state,
                    "cached_log_signature",
                    None
                )
                == cache_key
            ):

                return (
                    state.cached_alert_counts.copy(),
                    list(
                        state.cached_alerts
                    )
                )

    # ========================================================
    # CURRENT SESSION
    # ========================================================

    current_counts, current_alerts = (
        parse_security_log(
            log_file
        )
    )

    # ========================================================
    # HISTORICAL BACKUPS
    # ========================================================

    historical_counts = {
        "PLAINTEXT HTTP": 0,
        "PORT SCAN": 0,
        "TCP FLAG ANOMALY": 0,
        "TEST ALERT": 0,

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    historical_alerts = []

    for filename in historical_files:

        backup_counts, backup_alerts = (
            parse_security_log(
                filename
            )
        )

        for key, value in backup_counts.items():

            historical_counts[
                key
            ] += value

        historical_alerts.extend(
            backup_alerts
        )

    # --------------------------------------------------------
    # Dashboard needs totals from all logs.
    # Recent alerts are also combined so filtering can include
    # historical alerts.
    # --------------------------------------------------------

    total_counts = {
        "PLAINTEXT HTTP": 0,
        "PORT SCAN": 0,
        "TCP FLAG ANOMALY": 0,
        "TEST ALERT": 0,

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for key in total_counts:

        total_counts[
            key
        ] = (
            current_counts.get(
                key,
                0
            )
            +
            historical_counts.get(
                key,
                0
            )
        )

    all_alerts = (
        historical_alerts
        +
        current_alerts
    )

    # --------------------------------------------------------
    # Mark whether an alert came from the current session or
    # from a historical backup.
    # --------------------------------------------------------

    for alert in historical_alerts:

        alert[
            "session"
        ] = "HISTORICAL"

    for alert in current_alerts:

        alert[
            "session"
        ] = "SESSION"

    # --------------------------------------------------------
    # Cache complete data
    # --------------------------------------------------------

    if state is not None:

        with state.lock:

            state.cached_log_mtime = current_mtime

            state.cached_alert_counts = (
                total_counts.copy()
            )

            state.cached_alerts = (
                list(
                    all_alerts
                )
            )

            state.cached_log_signature = (
                cache_key
            )

    return (
        total_counts,
        all_alerts
    )


# ============================================================
# HEADER
# ============================================================

def build_header():

    text = Text()

    text.append(
        " NETWORK TRAFFIC ANALYZER ",
        style=f"bold {TEXT_COLOR}"
    )

    text.append(
        "| LIVE ",
        style=f"bold {LIVE_COLOR}"
    )

    text.append(
        "| ",
        style=TEXT_COLOR
    )

    text.append(
        datetime.now().strftime(
            "%H:%M:%S"
        ),
        style=f"bold {TEXT_COLOR}"
    )

    return Panel(
        text,
        border_style="cyan",
        padding=(0, 1)
    )


# ============================================================
# LIVE PACKET STREAM
# ============================================================

def build_packet_stream(
    state
):

    table = Table(
        expand=True,
        box=box.MINIMAL,
        padding=(0, 0)
    )

    table.add_column(
        "Time",
        width=8,
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_column(
        "Source",
        width=18,
        no_wrap=True,
        overflow="ellipsis",
        style=TEXT_COLOR
    )

    table.add_column(
        "Destination",
        width=18,
        no_wrap=True,
        overflow="ellipsis",
        style=TEXT_COLOR
    )

    table.add_column(
        "Protocol",
        width=8,
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_column(
        "Port",
        width=13,
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_column(
        "Size",
        width=10,
        justify="right",
        no_wrap=True,
        style=TEXT_COLOR
    )

    with state.lock:

        packets = list(
            state.packet_history
        )

    for packet in packets:

        port = "-"

        if packet.get(
            "dport"
        ) not in (
            None,
            "-",
            ""
        ):

            port = (
                f"{packet.get('sport', '-')}"
                f"→"
                f"{packet.get('dport', '-')}"
            )

        table.add_row(

            packet.get(
                "time",
                "-"
            ),

            packet.get(
                "src",
                "-"
            ),

            packet.get(
                "dst",
                "-"
            ),

            packet.get(
                "protocol",
                "-"
            ),

            port,

            format_bytes(
                packet.get(
                    "size",
                    0
                )
            )
        )

    return Panel(
        table,
        title="LIVE PACKET STREAM",
        border_style=PACKET_COLOR,
        padding=(0, 0)
    )


# ============================================================
# TELEMETRY
# ============================================================

def build_telemetry(
    state
):

    with state.lock:

        packets = state.total_packets
        total_bytes = state.total_bytes

        packets_per_second = (
            state.packets_per_second
        )

        bytes_per_second = (
            state.bytes_per_second
        )

        tcp = state.tcp_packets
        udp = state.udp_packets
        icmp = state.icmp_packets
        other = state.other_packets

        wifi = state.wifi_packets
        loopback = state.loopback_packets

    table = Table(
        show_header=False,
        expand=True,
        box=box.MINIMAL,
        padding=(0, 0)
    )

    table.add_column(
        "Metric",
        width=18,
        no_wrap=True,
        overflow="ellipsis",
        style=TEXT_COLOR
    )

    table.add_column(
        "Value",
        width=14,
        justify="right",
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_row(
        "Packets/sec",
        f"{packets_per_second:.2f}"
    )

    table.add_row(
        "Bytes/sec",
        format_bytes(
            bytes_per_second
        )
    )

    table.add_row(
        "Total Packets",
        str(packets)
    )

    table.add_row(
        "Total Bytes",
        format_bytes(
            total_bytes
        )
    )

    table.add_row(
        "TCP",
        str(tcp)
    )

    table.add_row(
        "UDP",
        str(udp)
    )

    table.add_row(
        "ICMP",
        str(icmp)
    )

    table.add_row(
        "Other",
        str(other)
    )

    table.add_row(
        "Wi-Fi Packets",
        str(wifi)
    )

    table.add_row(
        "Loopback Packets",
        str(loopback)
    )

    return Panel(
        table,
        title="TELEMETRY",
        border_style=TELEMETRY_COLOR,
        padding=(0, 0)
    )


# ============================================================
# TOP NETWORK GENERATORS
# ============================================================

def build_top_generators(
    state
):

    with state.lock:

        top_sources = sorted(
            state.source_counter.items(),
            key=lambda item: item[1],
            reverse=True
        )[:8]

    table = Table(
        expand=True,
        padding=(0, 0)
    )

    table.add_column(
        "Source IP",
        width=19,
        no_wrap=True,
        overflow="ellipsis",
        style=TEXT_COLOR
    )

    table.add_column(
        "Packets",
        width=10,
        justify="right",
        no_wrap=True,
        style=TEXT_COLOR
    )

    for source_ip, packet_count in top_sources:

        table.add_row(
            source_ip,
            str(packet_count)
        )

    if not top_sources:

        table.add_row(
            "No traffic yet",
            "0"
        )

    return Panel(
        table,
        title="TOP NETWORK GENERATORS",
        border_style=GENERATOR_COLOR,
        padding=(0, 0)
    )


# ============================================================
# BUILD X-AXIS LABELS
# ============================================================

def build_time_axis(
    data_length
):

    if data_length <= 0:

        return ""

    width = max(
        data_length,
        4
    )

    axis = [
        " "
    ] * width

    positions = [

        (
            0,
            "30s"
        ),

        (
            round(
                (width - 1)
                * (1 / 3)
            ),
            "20s"
        ),

        (
            round(
                (width - 1)
                * (2 / 3)
            ),
            "10s"
        ),

        (
            max(
                0,
                width - 3
            ),
            "NOW"
        )
    ]

    occupied_end = -1

    for position, label in positions:

        position = max(
            0,
            min(
                position,
                width - len(label)
            )
        )

        if position <= occupied_end:

            position = (
                occupied_end
                + 2
            )

        if (
            position
            + len(label)
            > width
        ):

            position = (
                width
                - len(label)
            )

        if position < 0:

            continue

        for index, character in enumerate(
            label
        ):

            target = (
                position
                + index
            )

            if (
                0 <= target < width
            ):

                axis[target] = character

        occupied_end = (
            position
            + len(label)
            - 1
        )

    return "".join(axis)


# ============================================================
# PROFESSIONAL LIVE GRAPH
# ============================================================

def build_graph(
    values,
    title,
    unit,
    graph_scale,
    border_style=GRAPH_COLOR
):

    data = list(values)

    if not data:

        return Panel(
            Text(
                "Waiting for traffic...",
                style=TEXT_COLOR
            ),
            title=title,
            border_style=border_style,
            padding=(0, 0)
        )

    # --------------------------------------------------------
    # Keep graph width fixed
    # --------------------------------------------------------

    data = data[-GRAPH_WIDTH:]

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    current_value = data[-1]

    peak_value = max(data)

    average_value = (
        sum(data)
        / len(data)
    )

    minimum_value = min(data)

    maximum = max(data)

    if maximum <= 0:

        maximum = 1

    # --------------------------------------------------------
    # Use a persistent graph scale so the Y-axis does not
    # jump on every refresh. The scale can still grow when a
    # new peak arrives and then relaxes slowly afterward.
    # --------------------------------------------------------

    graph_max = max(
        graph_scale,
        maximum * 1.10
    )

    # --------------------------------------------------------
    # Graph matrix
    # --------------------------------------------------------

    graph_width = max(
        len(data),
        4
    )

    rows = [
        [" "] * graph_width
        for _ in range(
            GRAPH_HEIGHT
        )
    ]

    # --------------------------------------------------------
    # Plot points
    # --------------------------------------------------------

    for index, value in enumerate(data):

        level = int(
            (
                value
                / graph_max
            )
            * (
                GRAPH_HEIGHT
                - 1
            )
        )

        row = (
            GRAPH_HEIGHT
            - 1
            - level
        )

        if (
            0 <= row
            < GRAPH_HEIGHT
        ):

            rows[row][index] = "●"

        # ----------------------------------------------------
        # Connect previous point
        # ----------------------------------------------------

        if index > 0:

            previous_value = (
                data[index - 1]
            )

            previous_level = int(
                (
                    previous_value
                    / graph_max
                )
                * (
                    GRAPH_HEIGHT
                    - 1
                )
            )

            previous_row = (
                GRAPH_HEIGHT
                - 1
                - previous_level
            )

            low = min(
                previous_row,
                row
            )

            high = max(
                previous_row,
                row
            )

            for connector_row in range(
                low,
                high + 1
            ):

                if (
                    0 <= connector_row
                    < GRAPH_HEIGHT
                ):

                    if (
                        rows[
                            connector_row
                        ][index]
                        == " "
                    ):

                        rows[
                            connector_row
                        ][index] = "│"

    # --------------------------------------------------------
    # Graph output
    # --------------------------------------------------------

    output = Text()

    for row_index, row in enumerate(
        rows
    ):

        level_value = (
            graph_max
            *
            (
                (
                    GRAPH_HEIGHT
                    - 1
                    - row_index
                )
                /
                (
                    GRAPH_HEIGHT
                    - 1
                )
            )
        )

        output.append(
            f"{level_value:>7.0f} ┤ ",
            style="dim"
        )

        for character in row:

            if character == "●":

                output.append(
                    character,
                    style=(
                        f"bold "
                        f"{GRAPH_DATA_COLOR}"
                    )
                )

            elif character == "│":

                output.append(
                    character,
                    style=GRAPH_DATA_COLOR
                )

            else:

                output.append(
                    character
                )

        output.append(
            "\n"
        )

    # --------------------------------------------------------
    # X-axis
    # --------------------------------------------------------

    output.append(
        "        └"
        + "─" * graph_width
        + "\n",
        style="dim"
    )

    time_axis = build_time_axis(
        graph_width
    )

    output.append(
        "         "
        + time_axis
        + "\n",
        style="dim"
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    output.append(
        "\n"
    )

    output.append(
        "Current : ",
        style=TEXT_COLOR
    )

    output.append(
        f"{current_value:.2f} {unit}",
        style=(
            f"bold "
            f"{GRAPH_DATA_COLOR}"
        )
    )

    output.append(
        "    "
    )

    output.append(
        "Average : ",
        style=TEXT_COLOR
    )

    output.append(
        f"{average_value:.2f} {unit}",
        style=GRAPH_DATA_COLOR
    )

    output.append(
        "\n"
    )

    output.append(
        "Peak    : ",
        style=TEXT_COLOR
    )

    output.append(
        f"{peak_value:.2f} {unit}",
        style=(
            f"bold "
            f"{GRAPH_DATA_COLOR}"
        )
    )

    output.append(
        "    "
    )

    output.append(
        "Minimum : ",
        style=TEXT_COLOR
    )

    output.append(
        f"{minimum_value:.2f} {unit}",
        style=GRAPH_DATA_COLOR
    )

    return Panel(
        output,
        title=title,
        border_style=GRAPH_COLOR,
        padding=(0, 0)
    )


# ============================================================
# SECURITY SUMMARY
# ============================================================

def build_security_summary(
    counts,
    session_alerts
):

    # ========================================================
    # TOTAL / SESSION / HISTORICAL
    # ========================================================

    total = (
        counts.get(
            config.SEVERITY_CRITICAL,
            0
        )
        +
        counts.get(
            config.SEVERITY_HIGH,
            0
        )
        +
        counts.get(
            config.SEVERITY_MEDIUM,
            0
        )
        +
        counts.get(
            config.SEVERITY_LOW,
            0
        )
    )

    session_total = len(
        session_alerts
    )

    historical_total = max(
        0,
        total - session_total
    )

    critical = counts.get(
        config.SEVERITY_CRITICAL,
        0
    )

    high = counts.get(
        config.SEVERITY_HIGH,
        0
    )

    medium = counts.get(
        config.SEVERITY_MEDIUM,
        0
    )

    low = counts.get(
        config.SEVERITY_LOW,
        0
    )

    table = Table(
        expand=True,
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 0)
    )

    table.add_column(
        "Category",
        width=14,
        no_wrap=True
    )

    table.add_column(
        "Count",
        width=8,
        justify="right",
        no_wrap=True
    )

    table.add_row(
        Text(
            "SESSION",
            style="bold bright_white"
        ),
        Text(
            str(session_total),
            style="bold bright_white"
        )
    )

    table.add_row(
        Text(
            "HISTORICAL",
            style="bold bright_white"
        ),
        Text(
            str(historical_total),
            style="bold bright_white"
        )
    )

    table.add_row(
        Text(
            "TOTAL",
            style="bold bright_white"
        ),
        Text(
            str(total),
            style="bold bright_white"
        )
    )

    table.add_row(
        Text(
            "CRITICAL",
            style=f"bold {SEVERITY_CRITICAL_COLOR}"
        ),
        Text(
            str(critical),
            style=f"bold {SEVERITY_CRITICAL_COLOR}"
        )
    )

    table.add_row(
        Text(
            "HIGH",
            style=f"bold {SEVERITY_HIGH_COLOR}"
        ),
        Text(
            str(high),
            style=f"bold {SEVERITY_HIGH_COLOR}"
        )
    )

    table.add_row(
        Text(
            "MEDIUM",
            style=f"bold {SEVERITY_MEDIUM_COLOR}"
        ),
        Text(
            str(medium),
            style=f"bold {SEVERITY_MEDIUM_COLOR}"
        )
    )

    table.add_row(
        Text(
            "LOW",
            style=f"bold {SEVERITY_LOW_COLOR}"
        ),
        Text(
            str(low),
            style=f"bold {SEVERITY_LOW_COLOR}"
        )
    )

    return Panel(
        table,
        title="SECURITY SUMMARY",
        border_style=SECURITY_COLOR,
        padding=(0, 0)
    )


# ============================================================
# GET SEVERITY STYLE
# ============================================================

def get_severity_style(
    severity
):

    severity = normalize_severity(
        severity
    )

    if severity == config.SEVERITY_CRITICAL:

        return (
            f"bold {SEVERITY_CRITICAL_COLOR}"
        )

    if severity == config.SEVERITY_HIGH:

        return (
            f"bold {SEVERITY_HIGH_COLOR}"
        )

    if severity == config.SEVERITY_LOW:

        return (
            f"bold {SEVERITY_LOW_COLOR}"
        )

    return (
        f"bold {SEVERITY_MEDIUM_COLOR}"
    )

# ============================================================
# FILTER SECURITY ALERTS
# ============================================================

def filter_alerts(
    alerts,
    alert_filter
):

    if alert_filter == "ALL":

        return list(
            alerts
        )

    filtered = []

    for alert in alerts:

        severity = normalize_severity(
            alert.get(
                "severity"
            )
        )

        if severity == alert_filter:

            filtered.append(
                alert
            )

    return filtered


# ============================================================
# RECENT SECURITY ALERTS
# ============================================================

def build_recent_alerts(
    all_alerts,
    scroll_offset,
    page_size,
    alert_filter
):

    table = Table(
        expand=True,
        padding=(0, 0)
    )

    table.add_column(
        "Time",
        width=18,
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_column(
        "Severity",
        width=10,
        no_wrap=True,
        justify="center"
    )

    table.add_column(
        "Type",
        width=19,
        no_wrap=True,
        overflow="ellipsis",
        style=TEXT_COLOR
    )

    table.add_column(
        "Details",
        width=42,
        no_wrap=True,
        overflow="ellipsis",
        style=TEXT_COLOR
    )

    alerts = list(
        reversed(
            all_alerts
        )
    )

    alerts = filter_alerts(
        alerts,
        alert_filter
    )

    total_alerts = len(
        alerts
    )

    max_offset = max(
        0,
        total_alerts - page_size
    )

    scroll_offset = max(
        0,
        min(
            scroll_offset,
            max_offset
        )
    )

    start = scroll_offset

    end = min(
        start + page_size,
        total_alerts
    )

    visible_alerts = alerts[
        start:end
    ]

    for alert in visible_alerts:

        severity = normalize_severity(
            alert.get(
                "severity"
            )
        )

        severity_text = Text(
            severity,
            style=get_severity_style(
                severity
            )
        )

        table.add_row(

            alert.get(
                "time",
                "-"
            ),

            severity_text,

            alert.get(
                "type",
                "-"
            ),

            alert.get(
                "details",
                "-"
            )
        )

    if not visible_alerts:

        table.add_row(
            "-",
            Text(
                "NONE",
                style=TEXT_COLOR
            ),
            "NONE",
            "No security alerts"
        )

    if total_alerts > page_size:

        subtitle = (
            f"FILTER: {alert_filter} | "
            f"{start + 1}-{end} "
            f"of {total_alerts}"
        )

    else:

        subtitle = (
            f"FILTER: {alert_filter} | "
            f"{total_alerts} alerts"
        )

    return Panel(
        table,
        title="RECENT SECURITY ALERTS",
        subtitle=subtitle,
        border_style=SECURITY_COLOR,
        padding=(0, 0)
    )


# ============================================================
# SYSTEM STATUS
# ============================================================

def build_status(
    state
):

    with state.lock:

        wifi = state.wifi_status
        loopback = state.loopback_status

    table = Table(
        show_header=False,
        expand=True,
        box=box.SIMPLE,
        padding=(0, 0)
    )

    table.add_column(
        "Component",
        width=20,
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_column(
        "Status",
        width=12,
        justify="right",
        no_wrap=True,
        style=TEXT_COLOR
    )

    table.add_row(
        "Wi-Fi",
        wifi
    )

    table.add_row(
        "Loopback",
        loopback
    )

    table.add_row(
        "HTTP Detection",
        "ON"
        if config.ENABLE_PLAINTEXT_DETECTOR
        else "OFF"
    )

    table.add_row(
        "Port Scan",
        "ON"
        if config.ENABLE_PORTSCAN_DETECTOR
        else "OFF"
    )

    table.add_row(
        "TCP Flag Anomaly",
        "ON"
        if config.ENABLE_TCP_FLAG_DETECTOR
        else "OFF"
    )

    return Panel(
        table,
        title="SYSTEM STATUS",
        border_style=STATUS_COLOR,
        padding=(0, 0)
    )


# ============================================================
# BUILD COMPLETE DASHBOARD
# ============================================================

def build_dashboard(
    state,
    log_file,
    alert_scroll,
    alert_filter,
    alert_manager
):

    counts, all_alerts = (
        read_security_alerts(
            log_file,
            state
        )
    )

    layout = Layout()

    # --------------------------------------------------------
    # Main layout
    # --------------------------------------------------------

    layout.split_column(

        Layout(
            name="header",
            size=3
        ),

        Layout(
            name="body",
            ratio=1
        ),

        Layout(
            name="footer",
            size=3
        )
    )

    # --------------------------------------------------------
    # Body columns
    # --------------------------------------------------------

    layout["body"].split_row(

        Layout(
            name="left",
            ratio=3
        ),

        Layout(
            name="right",
            size=52
        )
    )

    # --------------------------------------------------------
    # Left side
    # --------------------------------------------------------

    layout["left"].split_column(

        Layout(
            name="packets",
            ratio=3
        ),

        Layout(
            name="graphs",
            ratio=3
        ),

        Layout(
            name="security_area",
            ratio=3
        )
    )

    # --------------------------------------------------------
    # Graph area
    # --------------------------------------------------------

    layout["graphs"].split_row(

        Layout(
            name="packet_graph",
            ratio=1
        ),

        Layout(
            name="bandwidth_graph",
            ratio=1
        )
    )

    # --------------------------------------------------------
    # Security area
    # --------------------------------------------------------

    layout["security_area"].split_column(

        Layout(
            name="security_summary",
            size=12
        ),

        Layout(
            name="recent_alerts",
            ratio=2
        )
    )

    # --------------------------------------------------------
    # Right side
    # --------------------------------------------------------

    layout["right"].split_column(

        Layout(
            name="telemetry",
            ratio=3
        ),

        Layout(
            name="generators",
            ratio=3
        ),

        Layout(
            name="status",
            size=8
        )
    )

    # ========================================================
    # UPDATE PANELS
    # ========================================================

    layout["header"].update(
        build_header()
    )

    layout["packets"].update(
        build_packet_stream(
            state
        )
    )

    # --------------------------------------------------------
    # Graph data
    # --------------------------------------------------------

    with state.lock:

        packet_history = list(
            state.packet_rate_history
        )

        byte_history = list(
            state.byte_rate_history
        )

        packet_graph_scale = (
            state.packet_graph_scale
        )

        bandwidth_graph_scale = (
            state.bandwidth_graph_scale
        )

    # --------------------------------------------------------
    # Packet graph
    # --------------------------------------------------------

    layout["packet_graph"].update(

        build_graph(
            packet_history,
            "PACKETS / SECOND",
            "pps",
            packet_graph_scale,
            GRAPH_COLOR
        )
    )

    # --------------------------------------------------------
    # Bandwidth graph
    # --------------------------------------------------------

    layout["bandwidth_graph"].update(

        build_graph(
            byte_history,
            "BANDWIDTH",
            "B/s",
            bandwidth_graph_scale,
            GRAPH_COLOR
        )
    )

    # --------------------------------------------------------
    # Security summary
    # --------------------------------------------------------

    session_alerts = (
        alert_manager.get_session_alerts()
    )

    layout["security_summary"].update(

        build_security_summary(
            counts,
            session_alerts
        )
    )

    # --------------------------------------------------------
    # Recent alerts
    # --------------------------------------------------------

    layout["recent_alerts"].update(

        build_recent_alerts(
            all_alerts,
            alert_scroll,
            config.ALERT_PAGE_SIZE,
            alert_filter
        )
    )

    # --------------------------------------------------------
    # Telemetry
    # --------------------------------------------------------

    layout["telemetry"].update(

        build_telemetry(
            state
        )
    )

    # --------------------------------------------------------
    # Top generators
    # --------------------------------------------------------

    layout["generators"].update(

        build_top_generators(
            state
        )
    )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    layout["status"].update(

        build_status(
            state
        )
    )

    # ========================================================
    # FOOTER
    # ========================================================

    footer = Text()

    footer.append(
        " A All ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| H High ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| M Medium ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| L Low ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| C Critical ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| ↑/↓ Scroll ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| PageUp/PageDown ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| Home/End ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| Q Quit ",
        style=f"bold {FOOTER_COLOR}"
    )

    footer.append(
        "| "
    )

    footer.append(
        "ONE CAPTURE ENGINE",
        style=f"bold {LIVE_COLOR}"
    )

    footer.append(
        " | Live Security Monitoring",
        style=FOOTER_COLOR
    )

    layout["footer"].update(

        Panel(
            footer,
            border_style="cyan",
            padding=(0, 0)
        )
    )

    return layout


# ============================================================
# KEYBOARD READER
# ============================================================

def read_key():

    if not msvcrt.kbhit():

        return None

    try:

        first = msvcrt.getch()

        # ----------------------------------------------------
        # Extended key
        # ----------------------------------------------------

        if first in (
            b"\x00",
            b"\xe0"
        ):

            second = msvcrt.getch()

            return (
                "SPECIAL",
                second
            )

        if isinstance(
            first,
            bytes
        ):

            first = first.decode(
                "utf-8",
                errors="ignore"
            )

        return (
            "NORMAL",
            first.lower()
        )

    except Exception:

        return None


# ============================================================
# PROCESS KEY
# ============================================================

def process_key(
    key_data,
    scroll_offset,
    total_alerts,
    page_size,
    alert_filter
):

    if key_data is None:

        return (
            scroll_offset,
            False,
            alert_filter
        )

    key_type, key = key_data

    # --------------------------------------------------------
    # Normal keys
    # --------------------------------------------------------

    if key_type == "NORMAL":

        # ====================================================
        # ALERT FILTERS
        # ====================================================

        if key == "a":

            alert_filter = "ALL"

            scroll_offset = 0

        elif key == "h":

            alert_filter = "HIGH"

            scroll_offset = 0

        elif key == "m":

            alert_filter = "MEDIUM"

            scroll_offset = 0

        elif key == "l":

            alert_filter = "LOW"

            scroll_offset = 0

        elif key == "c":

            alert_filter = "CRITICAL"

            scroll_offset = 0

        # ====================================================
        # QUIT
        # ====================================================

        elif key == "q":

            return (
                scroll_offset,
                True,
                alert_filter
            )

        # ====================================================
        # SIMPLE SCROLLING
        # ====================================================

        elif key == "j":

            scroll_offset += 1

        elif key == "k":

            scroll_offset -= 1

        elif key == "e":

            scroll_offset = max(
                0,
                total_alerts - page_size
            )

    # --------------------------------------------------------
    # Special keys
    # --------------------------------------------------------

    elif key_type == "SPECIAL":

        # ----------------------------------------------------
        # Up Arrow
        # ----------------------------------------------------

        if key == b"H":

            scroll_offset -= 1

        # ----------------------------------------------------
        # Down Arrow
        # ----------------------------------------------------

        elif key == b"P":

            scroll_offset += 1

        # ----------------------------------------------------
        # Page Up
        # ----------------------------------------------------

        elif key == b"I":

            scroll_offset -= page_size

        # ----------------------------------------------------
        # Page Down
        # ----------------------------------------------------

        elif key == b"Q":

            scroll_offset += page_size

        # ----------------------------------------------------
        # Home
        # ----------------------------------------------------

        elif key == b"G":

            scroll_offset = 0

        # ----------------------------------------------------
        # End
        # ----------------------------------------------------

        elif key == b"O":

            scroll_offset = max(
                0,
                total_alerts - page_size
            )

    # --------------------------------------------------------
    # Clamp
    # --------------------------------------------------------

    max_offset = max(
        0,
        total_alerts - page_size
    )

    scroll_offset = max(
        0,
        min(
            scroll_offset,
            max_offset
        )
    )

    return (
        scroll_offset,
        False,
        alert_filter
    )


# ============================================================
# DASHBOARD LOOP
# ============================================================

def run_dashboard(
    state,
    log_file,
    alert_manager
):

    alert_scroll = 0

    alert_filter = "ALL"

    with Live(

        build_dashboard(
            state,
            log_file,
            alert_scroll,
            alert_filter,
            alert_manager
        ),

        refresh_per_second=(
            config.DASHBOARD_REFRESH_RATE
        ),

        screen=True

    ) as live:

        while True:

            # ------------------------------------------------
            # Get cached alerts
            # ------------------------------------------------

            _, all_alerts = (
                read_security_alerts(
                    log_file,
                    state
                )
            )

            # ------------------------------------------------
            # Filter alerts using current filter
            # ------------------------------------------------

            filtered_alerts = filter_alerts(
                all_alerts,
                alert_filter
            )

            total_alerts = len(
                filtered_alerts
            )

            # ------------------------------------------------
            # Keyboard
            # ------------------------------------------------

            key_data = read_key()

            (
                alert_scroll,
                should_quit,
                alert_filter
            ) = process_key(
                key_data,
                alert_scroll,
                total_alerts,
                config.ALERT_PAGE_SIZE,
                alert_filter
            )

            if should_quit:

                break

            # ------------------------------------------------
            # Recalculate filtered alerts after a filter
            # change so scrolling is immediately correct.
            # ------------------------------------------------

            filtered_alerts = filter_alerts(
                all_alerts,
                alert_filter
            )

            total_alerts = len(
                filtered_alerts
            )

            max_offset = max(
                0,
                total_alerts
                - config.ALERT_PAGE_SIZE
            )

            alert_scroll = max(
                0,
                min(
                    alert_scroll,
                    max_offset
                )
            )

            # ------------------------------------------------
            # Update rates
            # ------------------------------------------------

            state.update_rates()

            # ------------------------------------------------
            # Smoothly update graph scales
            # ------------------------------------------------

            state.update_graph_scales()

            # ------------------------------------------------
            # Refresh dashboard
            # ------------------------------------------------

            live.update(

                build_dashboard(
                    state,
                    log_file,
                    alert_scroll,
                    alert_filter,
                    alert_manager
                )
            )

            # ------------------------------------------------
            # Match the dashboard refresh rate.
            #
            # Example:
            # DASHBOARD_REFRESH_RATE = 5
            # 1 / 5 = 0.2 seconds
            # ------------------------------------------------

            time.sleep(
                1 / config.DASHBOARD_REFRESH_RATE
            )