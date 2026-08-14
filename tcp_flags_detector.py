from scapy.all import sniff, IP, TCP

import time
import config

from alert_manager import AlertManager


# ============================================================
# TCP FLAG ANOMALY DETECTOR
# ============================================================

SUSPICIOUS_COMBINATIONS = (
    config.TCP_SUSPICIOUS_COMBINATIONS
)

ALERT_COOLDOWN = (
    config.TCP_FLAG_ALERT_COOLDOWN
)


# ============================================================
# ALERT TRACKING
# ============================================================

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
# TCP FLAG DETECTION
# ============================================================

def detect_tcp_flags(packet):

    # --------------------------------------------------------
    # Check whether detector is enabled
    # --------------------------------------------------------

    if not config.ENABLE_TCP_FLAG_DETECTOR:

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

    flags = packet[TCP].flags

    # --------------------------------------------------------
    # Convert Scapy flags to set
    # --------------------------------------------------------

    flag_set = set(
        str(flags)
    )

    # ========================================================
    # CHECK SUSPICIOUS COMBINATIONS
    # ========================================================

    for suspicious in SUSPICIOUS_COMBINATIONS:

        if not suspicious.issubset(
            flag_set
        ):

            continue

        source_ip = packet[IP].src

        destination_ip = packet[IP].dst

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

        # ----------------------------------------------------
        # Create readable combination
        # ----------------------------------------------------

        combination = " + ".join(
            sorted(suspicious)
        )

        # ----------------------------------------------------
        # Alert key
        # ----------------------------------------------------

        alert_key = (
            source_ip,
            destination_ip,
            combination
        )

        current_time = time.time()

        previous_alert = last_alert_time.get(
            alert_key,
            0
        )

        # ----------------------------------------------------
        # Cooldown
        # ----------------------------------------------------

        if (
            current_time
            - previous_alert
            < ALERT_COOLDOWN
        ):

            continue

        # ====================================================
        # WARNING
        # ====================================================

        print()

        print(
            "========================================"
        )

        print(
            "  WARNING: TCP FLAG ANOMALY DETECTED"
        )

        print(
            "========================================"
        )

        print(
            "Source IP       :",
            source_ip
        )

        print(
            "Destination IP  :",
            destination_ip
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
            "TCP Flags       :",
            flags
        )

        print(
            "Suspicious Combo:",
            combination
        )

        print(
            "========================================"
        )

        # ====================================================
        # ALERT MANAGER
        # ====================================================

        alert_manager.add_alert(

            config.ALERT_TYPE_TCP_FLAG,

            source_ip,

            destination_ip,

            (
                f"{combination} detected "
                f"on port {destination_port}"
            ),

            config.TCP_FLAG_ALERT_SEVERITY
        )

        # ====================================================
        # UPDATE COOLDOWN
        # ====================================================

        last_alert_time[
            alert_key
        ] = current_time


# ============================================================
# MAIN ANALYZER INTERFACE
# ============================================================

def analyze_packet(packet):

    detect_tcp_flags(
        packet
    )


# ============================================================
# START DETECTOR DIRECTLY
# ============================================================

def start_tcp_flag_detector():

    print(
        "========================================"
    )

    print(
        "      TCP FLAG ANOMALY DETECTOR"
    )

    print(
        "========================================"
    )

    print()

    print(
        "Suspicious combinations:"
    )

    print(
        "  SYN + FIN"
    )

    print(
        "  SYN + RST"
    )

    print(
        "  FIN + RST"
    )

    print()

    print(
        "Alert cooldown :",
        ALERT_COOLDOWN,
        "seconds"
    )

    print(
        "AlertManager   : ENABLED"
    )

    print(
        "Interface      : Windows Loopback"
    )

    print()

    print(
        "Monitoring TCP packets..."
    )

    print(
        "Press CTRL+C to stop."
    )

    print()

    try:

        sniff(

            iface=r"\Device\NPF_Loopback",

            filter="tcp",

            prn=analyze_packet,

            store=False

        )

    except KeyboardInterrupt:

        print()

        print(
            "========================================"
        )

        print(
            "TCP flag detector stopped."
        )

        print(
            "========================================"
        )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    start_tcp_flag_detector()