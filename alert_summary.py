import os
from collections import Counter


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = os.path.join(
    "logs",
    "security_alerts.log"
)


# ============================================================
# READ ALERT TYPES
# ============================================================

def read_alert_types():

    alert_types = []

    if not os.path.exists(LOG_FILE):
        return alert_types

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if line.startswith("Alert Type"):

                    parts = line.split(
                        ":",
                        1
                    )

                    if len(parts) == 2:

                        alert_type = parts[1].strip()

                        alert_types.append(
                            alert_type
                        )

    except Exception as error:

        print(
            "[ERROR] Could not read log file:"
        )

        print(error)

    return alert_types


# ============================================================
# DISPLAY SUMMARY
# ============================================================

def display_summary():

    alert_types = read_alert_types()

    counts = Counter(alert_types)

    total_alerts = len(alert_types)

    print()
    print("========================================")
    print("       SECURITY ALERT SUMMARY")
    print("========================================")

    print()

    print(
        "Total Alerts       :",
        total_alerts
    )

    print()

    # --------------------------------------------------------
    # PLAINTEXT ALERTS
    # --------------------------------------------------------

    print(
        "PLAINTEXT HTTP     :",
        counts.get(
            "PLAINTEXT HTTP",
            0
        )
    )

    print(
        "PLAINTEXT FTP      :",
        counts.get(
            "PLAINTEXT FTP",
            0
        )
    )

    print(
        "PLAINTEXT TELNET   :",
        counts.get(
            "PLAINTEXT TELNET",
            0
        )
    )

    # --------------------------------------------------------
    # SECURITY DETECTORS
    # --------------------------------------------------------

    print(
        "PORT SCAN          :",
        counts.get(
            "PORT SCAN",
            0
        )
    )

    print(
        "TCP FLAG ANOMALY   :",
        counts.get(
            "TCP FLAG ANOMALY",
            0
        )
    )

    print(
        "TEST ALERT         :",
        counts.get(
            "TEST ALERT",
            0
        )
    )

    print()

    print("========================================")


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    display_summary()