from scapy.all import sniff, conf, IP, TCP, UDP, ICMP

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
import config


# ============================================================
# NETWORK TRAFFIC ANALYZER
# ============================================================

print("========================================")
print("     NETWORK TRAFFIC ANALYZER")
print("========================================")


# ============================================================
# NETWORK INTERFACES
# ============================================================

WIFI_INTERFACE = conf.ifaces.dev_from_name(
    config.WIFI_INTERFACE_NAME
)

LOOPBACK_INTERFACE = conf.ifaces.dev_from_name(
    config.LOOPBACK_INTERFACE_NAME
)


print()

print(
    "Wi-Fi Interface    :",
    WIFI_INTERFACE
)

print(
    "Loopback Interface :",
    LOOPBACK_INTERFACE
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
# PACKET ANALYZER
# ============================================================

def analyze_packet(
    packet,
    interface_name
):

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

        print(
            f"[STOPPED] {interface_name} capture"
        )


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
# START PROGRAM
# ============================================================

print()

print(
    "Monitoring network traffic..."
)

print()

print(
    "Security Detectors:"
)

print(
    "  [ON] Plaintext Traffic"
)

print(
    "  [ON] HTTP Requests"
)

print(
    "  [ON] Port Scan"
)

print(
    "  [ON] TCP Flag Anomaly"
)

print()

print(
    "AlertManager : ENABLED"
)

print()

print(
    "Wi-Fi Interface    :",
    WIFI_INTERFACE
)

print(
    "Loopback Interface :",
    LOOPBACK_INTERFACE
)

print()

print(
    "HTTP Test URL:"
)

print(
    "http://127.0.0.1:8000/"
)

print()

print(
    "Press Q in the dashboard to quit."
)

print()


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
    # Start Wi-Fi capture
    # --------------------------------------------------------

    wifi_thread.start()

    # --------------------------------------------------------
    # Start Loopback capture
    # --------------------------------------------------------

    loopback_thread.start()

    print()

    print("========================================")
    print(" BOTH INTERFACES ARE MONITORING")
    print("========================================")

    print()

    print(
        "Wi-Fi capture    : ACTIVE"
    )

    print(
        "Loopback capture : ACTIVE"
    )

    print()

    # --------------------------------------------------------
    # Start Rich dashboard
    #
    # Press Q in dashboard to return here.
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

    print(
        "Stopping packet capture..."
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


except KeyboardInterrupt:

    # --------------------------------------------------------
    # CTRL+C is also supported
    # --------------------------------------------------------

    print()

    print(
        "Stopping packet capture..."
    )

    stop_event.set()

    wifi_thread.join(
        timeout=2
    )

    loopback_thread.join(
        timeout=2
    )


finally:

    # ========================================================
    # STOP MESSAGE
    # ========================================================

    print()
    print()

    print("========================================")
    print("       CAPTURE STOPPED")
    print("========================================")

    print()

    # ========================================================
    # FINAL TRAFFIC STATISTICS
    # ========================================================

    with stats_lock:

        final_total_packets = (
            total_packets
        )

        final_total_bytes = (
            total_bytes
        )

        final_tcp_packets = (
            tcp_packets
        )

        final_udp_packets = (
            udp_packets
        )

        final_icmp_packets = (
            icmp_packets
        )

        final_other_packets = (
            other_packets
        )

        final_wifi_packets = (
            wifi_packets
        )

        final_loopback_packets = (
            loopback_packets
        )

    print(
        "Total Packets :",
        final_total_packets
    )

    print(
        "Total Bytes   :",
        final_total_bytes
    )

    print()

    # ========================================================
    # PROTOCOL STATISTICS
    # ========================================================

    print("Protocol Statistics")
    print("-------------------")

    print(
        "TCP           :",
        final_tcp_packets
    )

    print(
        "UDP           :",
        final_udp_packets
    )

    print(
        "ICMP          :",
        final_icmp_packets
    )

    print(
        "Other         :",
        final_other_packets
    )

    print()

    # ========================================================
    # INTERFACE STATISTICS
    # ========================================================

    print("Interface Statistics")
    print("--------------------")

    print(
        "Wi-Fi         :",
        final_wifi_packets
    )

    print(
        "Loopback      :",
        final_loopback_packets
    )

    print()

    # ========================================================
    # ALERT COUNT
    # ========================================================

    print("Security Alerts Generated:")

    print(
        "Total Alerts  :",
        get_alert_count()
    )

    print()

    # ========================================================
    # SECURITY SUMMARY
    # ========================================================

    display_summary()

    print()

    print("========================================")
    print("       PROGRAM EXITED CLEANLY")
    print("========================================")