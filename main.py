from scapy.all import sniff, conf, IP, TCP, UDP, ICMP

from rich.console import Console
from rich.text import Text
from rich.panel import Panel

from alert_manager import AlertManager

from plaintext_detector import (
    analyze_packet as analyze_plaintext,
    set_alert_manager as set_plaintext_alert_manager
)

from portscan_detector import (
    analyze_packet as analyze_portscan,
    set_alert_manager as set_portscan_alert_manager
)

from tcp_flags_detector import (
    analyze_packet as analyze_tcp_flags,
    set_alert_manager as set_tcp_flag_alert_manager
)

from alert_summary import display_summary

from live_dashboard import (
    DashboardState,
    run_dashboard
)

import threading
import time
import sys
import csv
import os
from datetime import datetime
import config


# ============================================================
# TYPEWRITER TEXT OUTPUT
# ============================================================

TYPEWRITER_DELAY = 0.0015


def type_text(
    text,
    delay=TYPEWRITER_DELAY
):

    for character in text:

        sys.stdout.write(
            character
        )

        sys.stdout.flush()

        if delay > 0:

            time.sleep(
                delay
            )

    sys.stdout.write(
        "\n"
    )

    sys.stdout.flush()


# ============================================================
# COLORED TYPEWRITER TEXT OUTPUT
# ============================================================

def type_text_colored(
    console,
    text,
    style,
    delay=TYPEWRITER_DELAY
):

    for character in text:

        console.print(
            character,
            style=style,
            end="",
            markup=False
        )

        if delay > 0:

            time.sleep(
                delay
            )

    console.print()


# ============================================================
# SAFE SHUTDOWN TYPEWRITER OUTPUT
# ============================================================

def type_shutdown_text(
    text,
    ansi_color="",
    delay=0.005
):

    if ansi_color:

        sys.stdout.write(
            ansi_color
        )

    for character in text:

        sys.stdout.write(
            character
        )

        sys.stdout.flush()

        time.sleep(
            delay
        )

    if ansi_color:

        sys.stdout.write(
            "\033[0m"
        )

    sys.stdout.write(
        "\n"
    )

    sys.stdout.flush()


# ============================================================
# PROFESSIONAL STARTUP INTERFACE
# ============================================================

def show_startup_interface():

    console = Console()

    # --------------------------------------------------------
    # Clear current terminal screen
    # --------------------------------------------------------

    console.clear()

    # --------------------------------------------------------
    # ASCII TITLE
    # --------------------------------------------------------

    title = Text()

    title.append(
        "███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗        ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗\n",
        style="bold bright_cyan"
    )

    title.append(
        "████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝        ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝\n",
        style="bold bright_cyan"
    )

    title.append(
        "██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝            ██║   ██████╔╝███████║█████╗  █████╗  ██║██║     \n",
        style="bold bright_cyan"
    )

    title.append(
        "██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗            ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║     \n",
        style="bold bright_cyan"
    )

    title.append(
        "██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗           ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗\n",
        style="bold bright_cyan"
    )

    title.append(
        "╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝           ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝",
        style="bold bright_cyan"
    )

    title.append(
        "\n"
    )

    title.append(
        "\n"
    )

    title.append(
        " █████╗ ███╗   ██╗  █████╗ ██╗     ██╗   ██╗ ███████╗███████╗██████╗\n",
        style="bold bright_cyan"
    )

    title.append(
        "██╔══██╗████╗  ██║ ██╔══██╗██║     ╚██╗ ██╔╝ ╚═══██╔╝██╔════╝██╔══██╗\n",
        style="bold bright_cyan"
    )

    title.append(
        "███████║██╔██╗ ██║ ███████║██║      ╚████╔╝    ██╔═╝ █████╗  ██████╔╝\n",
        style="bold bright_cyan"
    )

    title.append(
        "██╔══██║██║╚██╗██║ ██╔══██║██║       ╚██╔╝   ██╔═╝   ██╔══╝  ██╔══██╗\n",
        style="bold bright_cyan"
    )

    title.append(
         "██║  ██║██║ ╚████║ ██║  ██║███████╗   ██║   ███████╗ ███████╗██║  ██║\n",
        style="bold bright_cyan"
    )

    title.append(
        "╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚══════╝╚═╝  ╚═╝",
        style="bold bright_cyan"
    )


    # --------------------------------------------------------
    # INFORMATION
    # --------------------------------------------------------

    info = Text()

    info.append(
        "Copyright © 2026 Sandeepa Dilmina. All rights reserved.\n",
        style="bright_white"
    )

    info.append(
        "Real-Time Network Security & Live Cyber Dashboard",
        style="bright_green"
    )

    # --------------------------------------------------------
    # HEADER PANEL
    # --------------------------------------------------------

    console.print(
        Panel(
            title,
            border_style="cyan",
            padding=(1, 2)
        )
    )

    console.print(
        Panel(
            info,
            border_style="green",
            padding=(0, 2)
        )
    )

    console.print()

    # --------------------------------------------------------
    # IP INPUT
    # --------------------------------------------------------

    console.print(
        "Please enter an IP address to monitor "
        "(or press Enter for all):",
        style="bold bright_white"
    )

    console.print()

    ip_address = console.input(
        "[bold cyan]IP Address > [/]"
    ).strip()

    console.print()

    # --------------------------------------------------------
    # SELECTED IP
    # --------------------------------------------------------

    if ip_address:

        console.print(
            Panel(
                f"Monitoring IP: [bold bright_green]{ip_address}[/]",
                border_style="green",
                padding=(0, 2)
            )
        )

    else:

        console.print(
            Panel(
                "Monitoring [bold bright_green]all network traffic[/]",
                border_style="green",
                padding=(0, 2)
            )
        )

    console.print()

    # --------------------------------------------------------
    # LAUNCHING MESSAGE
    # --------------------------------------------------------

    console.print(
        "[bold bright_green]Launching interface...[/]"
    )

    console.print(
        "[dim](Press 'Q' inside dashboard to exit)[/]"
    )

    console.print()

    return ip_address


MONITOR_IP = show_startup_interface()


# ============================================================
# NETWORK TRAFFIC ANALYZER
# ============================================================

# ============================================================
# NETWORK INTERFACES
# ============================================================

WIFI_INTERFACE = conf.ifaces.dev_from_name(
    config.WIFI_INTERFACE_NAME
)

LOOPBACK_INTERFACE = conf.ifaces.dev_from_name(
    config.LOOPBACK_INTERFACE_NAME
)


# ============================================================
# SHARED ALERT MANAGER
# ============================================================

alert_manager = AlertManager()

# ============================================================
# ARCHIVE PREVIOUS SECURITY LOG
# ============================================================

alert_manager.archive_existing_log()

alert_manager.cleanup_old_backups()


# ============================================================
# DASHBOARD STATE
# ============================================================

dashboard_state = DashboardState()

LOG_FILE = config.SECURITY_LOG_FILE


# ============================================================
# SHARE SAME ALERT MANAGER WITH ALL DETECTORS
# ============================================================

set_plaintext_alert_manager(
    alert_manager
)

set_portscan_alert_manager(
    alert_manager
)

set_tcp_flag_alert_manager(
    alert_manager
)


# ============================================================
# TRAFFIC STATISTICS
# ============================================================

total_packets = 0
total_bytes = 0

tcp_packets = 0
udp_packets = 0
icmp_packets = 0
other_packets = 0

wifi_packets = 0
loopback_packets = 0

stats_lock = threading.Lock()


# ============================================================
# CAPTURE STOP EVENT
# ============================================================

stop_event = threading.Event()


# ============================================================
# SESSION PACKET HISTORY
# ============================================================

session_history = []
history_lock = threading.Lock()


# ============================================================
# PACKET ANALYZER
# ============================================================

def analyze_packet(
    packet,
    interface_name
):

    # ========================================================
    # IP MONITORING FILTER
    # ========================================================

    if MONITOR_IP:

        if IP not in packet:

            return

        packet_source = packet[IP].src
        packet_destination = packet[IP].dst

        if (
            packet_source != MONITOR_IP
            and
            packet_destination != MONITOR_IP
        ):

            return

    global total_packets
    global total_bytes

    global tcp_packets
    global udp_packets
    global icmp_packets
    global other_packets

    global wifi_packets
    global loopback_packets

    # --------------------------------------------------------
    # Default packet information
    # --------------------------------------------------------

    source_ip = "-"
    destination_ip = "-"

    protocol = "OTHER"

    source_port = "-"
    destination_port = "-"

    # --------------------------------------------------------
    # Decode IP / transport information
    # --------------------------------------------------------

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if TCP in packet:

            protocol = "TCP"

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif UDP in packet:

            protocol = "UDP"

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        elif ICMP in packet:

            protocol = "ICMP"

    # ========================================================
    # UPDATE MAIN STATISTICS
    # ========================================================

    with stats_lock:

        total_packets += 1

        total_bytes += len(packet)

        # ----------------------------------------------------
        # Interface statistics
        # ----------------------------------------------------

        if interface_name == "Wi-Fi":

            wifi_packets += 1

        elif interface_name == "Loopback":

            loopback_packets += 1

        # ----------------------------------------------------
        # Protocol statistics
        # ----------------------------------------------------

        if TCP in packet:

            tcp_packets += 1

        elif UDP in packet:

            udp_packets += 1

        elif ICMP in packet:

            icmp_packets += 1

        else:

            other_packets += 1

    # ========================================================
    # SEND PACKET TO DASHBOARD
    # ========================================================

    dashboard_state.add_packet({

        "time": time.strftime("%H:%M:%S"),

        "src": source_ip,

        "dst": destination_ip,

        "protocol": protocol,

        "sport": source_port,

        "dport": destination_port,

        "size": len(packet),

        "interface": interface_name
    })

    # --------------------------------------------------------
    # Store packet history for optional CSV export
    # --------------------------------------------------------

    with history_lock:

        session_history.append({

            "time": time.strftime("%H:%M:%S"),

            "source": source_ip,

            "destination": destination_ip,

            "protocol": protocol,

            "source_port": source_port,

            "destination_port": destination_port,

            "size_bytes": len(packet),

            "interface": interface_name
        })

    # ========================================================
    # SECURITY DETECTOR 1
    # ========================================================

    try:

        analyze_plaintext(
            packet
        )

    except Exception as error:

        print()

        print(
            "[ERROR] Plaintext detector:",
            error
        )

    # ========================================================
    # SECURITY DETECTOR 2
    # ========================================================

    try:

        analyze_portscan(
            packet
        )

    except Exception as error:

        print()

        print(
            "[ERROR] Port scan detector:",
            error
        )

    # ========================================================
    # SECURITY DETECTOR 3
    # ========================================================

    try:

        analyze_tcp_flags(
            packet
        )

    except Exception as error:

        print()

        print(
            "[ERROR] TCP flag detector:",
            error
        )


# ============================================================
# CAPTURE INTERFACE
# ============================================================

def capture_interface(
    interface,
    interface_name
):

    print(
        f"[STARTED] {interface_name} capture"
    )

    # --------------------------------------------------------
    # Tell dashboard capture is active
    # --------------------------------------------------------

    dashboard_state.set_interface_status(
        interface_name,
        "ACTIVE"
    )

    try:

        sniff(

            iface=interface,

            prn=lambda packet:
                analyze_packet(
                    packet,
                    interface_name
                ),

            store=False,

            stop_filter=lambda packet:
                stop_event.is_set()

        )

    except Exception as error:

        # ----------------------------------------------------
        # Tell dashboard capture failed
        # ----------------------------------------------------

        dashboard_state.set_interface_status(
            interface_name,
            "ERROR"
        )

        print()

        print(
            f"[ERROR] {interface_name} capture failed:"
        )

        print(error)

    finally:

        # ----------------------------------------------------
        # Capture stopped
        # ----------------------------------------------------

        dashboard_state.set_interface_status(
            interface_name,
            "STOPPED"
        )

        # Shutdown status is printed by the main thread after
        # both capture threads have finished.


# ============================================================
# GET ALERT COUNT
# ============================================================

def get_alert_count():

    if hasattr(
        alert_manager,
        "get_alert_count"
    ):

        return (
            alert_manager.get_alert_count()
        )

    if hasattr(
        alert_manager,
        "alerts"
    ):

        return len(
            alert_manager.alerts
        )

    return 0



# ============================================================
# SAVE SESSION HISTORY AS CSV
# ============================================================

def save_session_history_to_csv():

    export_directory = "exports"

    os.makedirs(
        export_directory,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    file_path = os.path.join(
        export_directory,
        f"traffic_history_{timestamp}.csv"
    )

    with history_lock:

        history = list(
            session_history
        )

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "time",
                "source",
                "destination",
                "protocol",
                "source_port",
                "destination_port",
                "size_bytes",
                "interface"
            ]
        )

        writer.writeheader()

        writer.writerows(
            history
        )

    return file_path, len(history)


# ============================================================
# DASHBOARD LOADING SCREEN
# ============================================================

def show_dashboard_loading(
    console,
    seconds=5
):

    # --------------------------------------------------------
    # Clear the previous interface
    # --------------------------------------------------------

    console.clear()

    # --------------------------------------------------------
    # Create a Live display so the loading screen is always
    # centered and refreshed in the same position.
    # --------------------------------------------------------

    from rich.live import Live

    with Live(
        refresh_per_second=10,
        screen=False
    ) as live:

        for second in range(
            1,
            seconds + 1
        ):

            progress = (
                "█" * second
                + "░" * (
                    seconds - second
                )
            )

            loading_text = Text()

            loading_text.append(
                "Initializing Live Security Dashboard\n\n",
                style="bold bright_green"
            )

            loading_text.append(
                "Loading: ",
                style="bright_white"
            )

            loading_text.append(
                progress,
                style="bold bright_cyan"
            )

            loading_text.append(
                f"  {second}/{seconds} sec\n\n",
                style="bright_yellow"
            )

            if second < seconds:

                loading_text.append(
                    "Preparing live traffic telemetry...",
                    style="dim bright_white"
                )

            else:

                loading_text.append(
                    "Dashboard ready.",
                    style="bold bright_green"
                )

            loading_panel = Panel(
                loading_text,
                title="NETWORK TRAFFIC ANALYZER",
                border_style="cyan",
                padding=(1, 4)
            )

            live.update(
                loading_panel
            )

            time.sleep(
                1
            )

    # --------------------------------------------------------
    # Final launch message
    # --------------------------------------------------------

    console.clear()

    console.print(
        Panel(
            Text(
                "Launching live dashboard...",
                style="bold bright_green",
                justify="center"
            ),
            border_style="green",
            padding=(1, 4)
        )
    )

    time.sleep(
        0.5
    )


# ============================================================
# SECOND INTERFACE — MAIN PROGRAM STATUS
# ============================================================

def show_main_interface():

    # --------------------------------------------------------
    # Clear the startup interface
    # --------------------------------------------------------

    console = Console()

    console.clear()

    # --------------------------------------------------------
    # Color palette
    # --------------------------------------------------------

    BORDER_STYLE = "cyan"
    TITLE_STYLE = "bold bright_cyan"
    INFO_STYLE = "bright_white"
    MONITOR_STYLE = "bold bright_green"
    DETECTOR_LABEL_STYLE = "bright_white"
    DETECTOR_ON_STYLE = "bold bright_green"
    ALERT_STYLE = "bold bright_green"
    URL_STYLE = "bold bright_yellow"
    HINT_STYLE = "dim bright_white"
    START_STYLE = "bold bright_green"
    ACTIVE_STYLE = "bold bright_green"

    # --------------------------------------------------------
    # Main title
    # --------------------------------------------------------

    type_text_colored(
        console,
        "========================================",
        BORDER_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "     NETWORK TRAFFIC ANALYZER",
        TITLE_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "========================================",
        BORDER_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Interfaces
    # --------------------------------------------------------

    console.print(
        Text.assemble(
            ("Wi-Fi Interface    : ", INFO_STYLE),
            (str(WIFI_INTERFACE), "bold bright_cyan")
        )
    )

    console.print(
        Text.assemble(
            ("Loopback Interface : ", INFO_STYLE),
            (str(LOOPBACK_INTERFACE), "bold bright_magenta")
        )
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Monitoring
    # --------------------------------------------------------

    type_text_colored(
        console,
        "Monitoring network traffic...",
        MONITOR_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Security detectors
    # --------------------------------------------------------

    type_text_colored(
        console,
        "Security Detectors:",
        "bold bright_white",
        0.005
    )

    console.print(
        Text.assemble(
            ("  [ON] ", DETECTOR_ON_STYLE),
            ("Plaintext Traffic", DETECTOR_LABEL_STYLE)
        )
    )

    console.print(
        Text.assemble(
            ("  [ON] ", DETECTOR_ON_STYLE),
            ("HTTP Requests", DETECTOR_LABEL_STYLE)
        )
    )

    console.print(
        Text.assemble(
            ("  [ON] ", DETECTOR_ON_STYLE),
            ("Port Scan", DETECTOR_LABEL_STYLE)
        )
    )

    console.print(
        Text.assemble(
            ("  [ON] ", DETECTOR_ON_STYLE),
            ("TCP Flag Anomaly", DETECTOR_LABEL_STYLE)
        )
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Alert manager
    # --------------------------------------------------------

    console.print(
        Text.assemble(
            ("AlertManager : ", INFO_STYLE),
            ("ENABLED", ALERT_STYLE)
        )
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # HTTP test URL
    # --------------------------------------------------------

    type_text_colored(
        console,
        "HTTP Test URL:",
        URL_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "http://127.0.0.1:8000/",
        "underline bright_yellow",
        0.005
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Dashboard hint
    # --------------------------------------------------------

    type_text_colored(
        console,
        "Press Q in the dashboard to quit.",
        HINT_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Start capture threads
    # --------------------------------------------------------

    wifi_thread.start()

    loopback_thread.start()

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    # --------------------------------------------------------
    # Monitoring banner
    # --------------------------------------------------------

    type_text_colored(
        console,
        "========================================",
        BORDER_STYLE,
        0.005
    )

    type_text_colored(
        console,
        " BOTH INTERFACES ARE MONITORING",
        "bold bright_green",
        0.005
    )

    type_text_colored(
        console,
        "========================================",
        BORDER_STYLE,
        0.005
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    console.print(
        Text.assemble(
            ("Wi-Fi capture    : ", INFO_STYLE),
            ("ACTIVE", ACTIVE_STYLE)
        )
    )

    console.print(
        Text.assemble(
            ("Loopback capture : ", INFO_STYLE),
            ("ACTIVE", ACTIVE_STYLE)
        )
    )

    type_text_colored(
        console,
        "",
        INFO_STYLE,
        0
    )

    return console


# ============================================================
# CREATE CAPTURE THREADS
# ============================================================

wifi_thread = threading.Thread(

    target=capture_interface,

    args=(
        WIFI_INTERFACE,
        "Wi-Fi"
    ),

    daemon=True

)


loopback_thread = threading.Thread(

    target=capture_interface,

    args=(
        LOOPBACK_INTERFACE,
        "Loopback"
    ),

    daemon=True

)


# ============================================================
# START APPLICATION
# ============================================================

try:

    # --------------------------------------------------------
    # Show the second interface after the startup screen.
    # --------------------------------------------------------

    console = show_main_interface()

    # --------------------------------------------------------
    # Five-second loading screen before the live dashboard.
    # --------------------------------------------------------

    show_dashboard_loading(
        console,
        seconds=5
    )

    # --------------------------------------------------------
    # Start the existing live dashboard.
    # --------------------------------------------------------

    run_dashboard(
        dashboard_state,
        LOG_FILE,
        alert_manager
    )

    # --------------------------------------------------------
    # Dashboard returned
    # --------------------------------------------------------

    print()

    type_shutdown_text(
        "Stopping packet capture...",
        "\033[93m",
        0.005
    )

    # --------------------------------------------------------
    # Signal both Scapy capture threads to stop
    # --------------------------------------------------------

    stop_event.set()

    # --------------------------------------------------------
    # Wait for capture threads to finish
    # --------------------------------------------------------

    wifi_thread.join(
        timeout=2
    )

    loopback_thread.join(
        timeout=2
    )

    # --------------------------------------------------------
    # Print thread stop messages after both threads have fully
    # stopped, preventing terminal output from interleaving.
    # --------------------------------------------------------

    type_shutdown_text(
        "[STOPPED] Wi-Fi capture",
        "\033[92m",
        0.005
    )

    type_shutdown_text(
        "[STOPPED] Loopback capture",
        "\033[92m",
        0.005
    )


except KeyboardInterrupt:

    # --------------------------------------------------------
    # CTRL+C is also supported
    # --------------------------------------------------------

    print()

    type_shutdown_text(
        "Stopping packet capture...",
        "\033[93m",
        0.005
    )

    stop_event.set()

    wifi_thread.join(
        timeout=2
    )

    loopback_thread.join(
        timeout=2
    )

    type_shutdown_text(
        "[STOPPED] Wi-Fi capture",
        "\033[92m",
        0.005
    )

    type_shutdown_text(
        "[STOPPED] Loopback capture",
        "\033[92m",
        0.005
    )


finally:

    # ========================================================
    # COLORED SHUTDOWN / FINAL SUMMARY
    # ========================================================

    shutdown_console = Console()

    shutdown_console.print()

    shutdown_console.print(
        Text(
            "========================================",
            style="bold bright_red"
        )
    )

    shutdown_console.print(
        Text(
            "       CAPTURE STOPPED",
            style="bold bright_red"
        )
    )

    shutdown_console.print(
        Text(
            "========================================",
            style="bold bright_red"
        )
    )

    shutdown_console.print()

    # ========================================================
    # FINAL TRAFFIC STATISTICS
    # ========================================================

    with stats_lock:

        final_total_packets = total_packets
        final_total_bytes = total_bytes

        final_tcp_packets = tcp_packets
        final_udp_packets = udp_packets
        final_icmp_packets = icmp_packets
        final_other_packets = other_packets

        final_wifi_packets = wifi_packets
        final_loopback_packets = loopback_packets

    shutdown_console.print(
        Text.assemble(
            ("Total Packets : ", "bold bright_white"),
            (str(final_total_packets), "bold bright_cyan")
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("Total Bytes   : ", "bold bright_white"),
            (str(final_total_bytes), "bold bright_cyan")
        )
    )

    shutdown_console.print()

    # ========================================================
    # PROTOCOL STATISTICS
    # ========================================================

    shutdown_console.print(
        Text(
            "Protocol Statistics",
            style="bold bright_blue"
        )
    )

    shutdown_console.print(
        Text(
            "-------------------",
            style="bright_blue"
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("TCP           : ", "bright_white"),
            (str(final_tcp_packets), "bold bright_cyan")
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("UDP           : ", "bright_white"),
            (str(final_udp_packets), "bold bright_cyan")
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("ICMP          : ", "bright_white"),
            (str(final_icmp_packets), "bold bright_cyan")
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("Other         : ", "bright_white"),
            (str(final_other_packets), "bold bright_cyan")
        )
    )

    shutdown_console.print()

    # ========================================================
    # INTERFACE STATISTICS
    # ========================================================

    shutdown_console.print(
        Text(
            "Interface Statistics",
            style="bold bright_magenta"
        )
    )

    shutdown_console.print(
        Text(
            "--------------------",
            style="bright_magenta"
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("Wi-Fi         : ", "bright_white"),
            (str(final_wifi_packets), "bold bright_cyan")
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("Loopback      : ", "bright_white"),
            (str(final_loopback_packets), "bold bright_magenta")
        )
    )

    shutdown_console.print()

    # ========================================================
    # ALERT COUNT
    # ========================================================

    alert_count = get_alert_count()

    shutdown_console.print(
        Text(
            "Security Alerts Generated:",
            style="bold bright_yellow"
        )
    )

    shutdown_console.print(
        Text.assemble(
            ("Total Alerts  : ", "bright_white"),
            (
                str(alert_count),
                "bold bright_red"
                if alert_count > 0
                else "bold bright_green"
            )
        )
    )

    shutdown_console.print()

    # ========================================================
    # SECURITY SUMMARY
    # ========================================================

    display_summary()

    shutdown_console.print()

    # ========================================================
    # OPTIONAL CSV EXPORT
    # ========================================================

    shutdown_console.print(
        Text(
            "Do you want to save the history as a CSV file? (y/n):",
            style="bold bright_yellow"
        )
    )

    save_history = input(
        "CSV Export > "
    ).strip().lower()

    if save_history == "y":

        try:

            file_path, exported_count = (
                save_session_history_to_csv()
            )

            shutdown_console.print()

            shutdown_console.print(
                Text(
                    "[✓] History saved successfully.",
                    style="bold bright_green"
                )
            )

            shutdown_console.print(
                Text.assemble(
                    ("[✓] CSV file: ", "bright_white"),
                    (file_path, "bold bright_cyan")
                )
            )

            shutdown_console.print(
                Text.assemble(
                    ("[✓] Exported packets: ", "bright_white"),
                    (str(exported_count), "bold bright_cyan")
                )
            )

        except Exception as error:

            shutdown_console.print()

            shutdown_console.print(
                Text(
                    "[ERROR] Could not save CSV history.",
                    style="bold bright_red"
                )
            )

            shutdown_console.print(
                Text(
                    str(error),
                    style="bright_red"
                )
            )

    else:

        shutdown_console.print()

        shutdown_console.print(
            Text(
                "Session ended without saving.",
                style="dim bright_white"
            )
        )

    shutdown_console.print()

    shutdown_console.print(
        Text(
            "========================================",
            style="bold bright_green"
        )
    )

    shutdown_console.print(
        Text(
            "       PROGRAM EXITED CLEANLY",
            style="bold bright_green"
        )
    )

    shutdown_console.print(
        Text(
            "========================================",
            style="bold bright_green"
        )
    )