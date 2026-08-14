from scapy.all import sniff, IP, TCP

import time
import config

from alert_manager import AlertManager


# ============================================================
# PORT SCAN DETECTOR
# ============================================================

PORT_THRESHOLD = (
    config.PORTSCAN_THRESHOLD
)

TIME_WINDOW = (
    config.PORTSCAN_TIME_WINDOW
)

ALERT_COOLDOWN = (
    config.PORTSCAN_ALERT_COOLDOWN
)


# ============================================================
# TRACK SCANNING ACTIVITY
# ============================================================

scan_tracker = {}

last_alert_time = {}


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
# PORT SCAN DETECTION
# ============================================================

def detect_port_scan(packet):

    # --------------------------------------------------------
    # Check whether detector is enabled
    # --------------------------------------------------------

    if not config.ENABLE_PORTSCAN_DETECTOR:

        return

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

    # --------------------------------------------------------
    # Only inspect SYN packets
    # SYN = 0x02
    # --------------------------------------------------------

    if not packet[TCP].flags & 0x02:

        return

    # --------------------------------------------------------
    # Ignore SYN + ACK
    # ACK = 0x10
    # --------------------------------------------------------

    if packet[TCP].flags & 0x10:

        return

    # --------------------------------------------------------
    # Packet information
    # --------------------------------------------------------

    source_ip = packet[IP].src

    destination_ip = packet[IP].dst

    destination_port = packet[TCP].dport

    current_time = time.time()

    # ========================================================
    # CREATE TRACKER
    # ========================================================

    if source_ip not in scan_tracker:

        scan_tracker[source_ip] = {

            "start_time":
                current_time,

            "ports":
                set()
        }

    tracker = scan_tracker[
        source_ip
    ]

    # ========================================================
    # RESET TIME WINDOW
    # ========================================================

    if (
        current_time
        - tracker["start_time"]
        > TIME_WINDOW
    ):

        tracker["start_time"] = (
            current_time
        )

        tracker["ports"] = set()

    # ========================================================
    # ADD DESTINATION PORT
    # ========================================================

    tracker["ports"].add(
        destination_port
    )

    unique_ports = len(
        tracker["ports"]
    )

    window = (
        current_time
        - tracker["start_time"]
    )

    # ========================================================
    # CHECK PORT SCAN THRESHOLD
    # ========================================================

    if unique_ports < PORT_THRESHOLD:

        return

    # ========================================================
    # ALERT COOLDOWN
    # ========================================================

    last_alert = last_alert_time.get(
        source_ip,
        0
    )

    if (
        current_time
        - last_alert
        < ALERT_COOLDOWN
    ):

        return

    # ========================================================
    # PORT SCAN WARNING
    # ========================================================

    print()

    print(
        "========================================"
    )

    print(
        "  WARNING: POSSIBLE PORT SCAN DETECTED"
    )

    print(
        "========================================"
    )

    print(
        "Source IP        :",
        source_ip
    )

    print(
        "Destination IP   :",
        destination_ip
    )

    print(
        "Unique Ports     :",
        unique_ports
    )

    print(
        "Time Window      :",
        f"{window:.2f} seconds"
    )

    print(
        "========================================"
    )

    print()

    # ========================================================
    # SEND ALERT
    # ========================================================

    alert_manager.add_alert(

        config.ALERT_TYPE_PORT_SCAN,

        source_ip,

        destination_ip,

        (
            f"{unique_ports} unique destination "
            f"ports detected within "
            f"{window:.2f} seconds"
        )
    )

    # ========================================================
    # UPDATE COOLDOWN
    # ========================================================

    last_alert_time[
        source_ip
    ] = current_time


# ============================================================
# MAIN ANALYZER INTERFACE
# ============================================================

def analyze_packet(packet):

    detect_port_scan(
        packet
    )


# ============================================================
# CLEAN OLD SCAN TRACKERS
# ============================================================

def cleanup_scan_tracker():

    current_time = time.time()

    expired_sources = []

    for source_ip, tracker in (
        scan_tracker.items()
    ):

        if (
            current_time
            - tracker["start_time"]
            > TIME_WINDOW * 2
        ):

            expired_sources.append(
                source_ip
            )

    for source_ip in expired_sources:

        scan_tracker.pop(
            source_ip,
            None
        )


# ============================================================
# START DETECTOR DIRECTLY
# ============================================================

def start_port_scan_detector():

    print(
        "========================================"
    )

    print(
        "        PORT SCAN DETECTOR"
    )

    print(
        "========================================"
    )

    print(
        "Port threshold :",
        PORT_THRESHOLD
    )

    print(
        "Time window    :",
        TIME_WINDOW,
        "seconds"
    )

    print(
        "Alert cooldown :",
        ALERT_COOLDOWN,
        "seconds"
    )

    print()

    print(
        "Monitoring TCP SYN packets..."
    )

    print(
        "AlertManager   : ENABLED"
    )

    print(
        "Interface      : Windows Loopback"
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

                filter="tcp",

                prn=analyze_packet,

                store=False,

                timeout=1
            )

            cleanup_scan_tracker()

    except KeyboardInterrupt:

        print()

        print(
            "========================================"
        )

        print(
            "Port scan detector stopped."
        )

        print(
            "========================================"
        )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    start_port_scan_detector()