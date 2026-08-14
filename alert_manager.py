from datetime import datetime
import os
import threading

import config


# ============================================================
# ALERT MANAGER
# ============================================================

class AlertManager:

    def __init__(self):

        # ----------------------------------------------------
        # Store current-session alerts
        # ----------------------------------------------------

        self.alerts = []

        # ----------------------------------------------------
        # Thread safety
        # ----------------------------------------------------

        self.lock = threading.Lock()

        # ----------------------------------------------------
        # Log directory
        # ----------------------------------------------------

        self.log_directory = (
            os.path.dirname(
                config.SECURITY_LOG_FILE
            )
            or "."
        )

        # ----------------------------------------------------
        # Log file
        # ----------------------------------------------------

        self.log_file = (
            config.SECURITY_LOG_FILE
        )

        # ----------------------------------------------------
        # Create directory
        # ----------------------------------------------------

        os.makedirs(
            self.log_directory,
            exist_ok=True
        )


    # ========================================================
    # ARCHIVE EXISTING LOG
    # ========================================================

    def archive_existing_log(self):

        if not config.ARCHIVE_LOG_ON_START:
            return None

        # ----------------------------------------------------
        # Check whether current log exists
        # ----------------------------------------------------

        if not os.path.exists(
            self.log_file
        ):
            return None

        # ----------------------------------------------------
        # Check whether the log has content
        # ----------------------------------------------------

        try:

            if os.path.getsize(
                self.log_file
            ) == 0:

                return None

        except OSError:

            return None

        # ----------------------------------------------------
        # Create backup directory
        # ----------------------------------------------------

        try:

            os.makedirs(
                config.LOG_BACKUP_DIRECTORY,
                exist_ok=True
            )

        except OSError as error:

            print(
                "[ERROR] Could not create "
                "log backup directory:"
            )

            print(error)

            return None

        # ----------------------------------------------------
        # Create timestamp
        # ----------------------------------------------------

        timestamp = datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )

        backup_file = os.path.join(
            config.LOG_BACKUP_DIRECTORY,
            f"{config.LOG_BACKUP_PREFIX}{timestamp}.log"
        )

        # ----------------------------------------------------
        # Move old log into backup directory
        # ----------------------------------------------------

        try:

            os.replace(
                self.log_file,
                backup_file
            )

            print(
                f"[LOG ARCHIVED] {backup_file}"
            )

            return backup_file

        except OSError as error:

            print(
                "[ERROR] Could not archive "
                "security log:"
            )

            print(error)

            return None


    # ========================================================
    # ADD ALERT
    # ========================================================

    def add_alert(
        self,
        alert_type,
        source_ip,
        destination_ip,
        details,
        severity=config.SEVERITY_MEDIUM
    ):

        # ----------------------------------------------------
        # Create alert
        # ----------------------------------------------------

        alert = {

            "time":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "type":
                alert_type,

            "severity":
                severity,

            "source_ip":
                source_ip,

            "destination_ip":
                destination_ip,

            "details":
                details
        }

        # ====================================================
        # STORE IN MEMORY
        # ====================================================

        with self.lock:

            self.alerts.append(
                alert
            )

        # ====================================================
        # DISPLAY ALERT
        # ====================================================

        print()

        print(
            "========================================"
        )

        print(
            "          SECURITY ALERT"
        )

        print(
            "========================================"
        )

        print(
            "Time            :",
            alert["time"]
        )

        print(
            "Severity        :",
            alert["severity"]
        )

        print(
            "Alert Type      :",
            alert["type"]
        )

        print(
            "Source IP       :",
            alert["source_ip"]
        )

        print(
            "Destination IP  :",
            alert["destination_ip"]
        )

        print(
            "Details         :",
            alert["details"]
        )

        print(
            "========================================"
        )

        # ====================================================
        # WRITE ALERT TO LOG
        # ====================================================

        try:

            with open(
                self.log_file,
                "a",
                encoding="utf-8"
            ) as file:

                file.write(
                    "========================================\n"
                )

                file.write(
                    "SECURITY ALERT\n"
                )

                file.write(
                    "========================================\n"
                )

                file.write(
                    f"Time            : "
                    f"{alert['time']}\n"
                )

                file.write(
                    f"Severity        : "
                    f"{alert['severity']}\n"
                )

                file.write(
                    f"Alert Type      : "
                    f"{alert['type']}\n"
                )

                file.write(
                    f"Source IP       : "
                    f"{alert['source_ip']}\n"
                )

                file.write(
                    f"Destination IP  : "
                    f"{alert['destination_ip']}\n"
                )

                file.write(
                    f"Details         : "
                    f"{alert['details']}\n"
                )

                file.write(
                    "========================================\n"
                )

                file.write(
                    "\n"
                )

        except Exception as error:

            print()

            print(
                "[ERROR] Could not write alert "
                "to log file:"
            )

            print(error)


    # ========================================================
    # READ ALERTS FROM LOG
    # ========================================================

    def _read_log_alerts(self):

        alerts = []

        try:

            with open(
                self.log_file,
                "r",
                encoding="utf-8"
            ) as file:

                lines = file.readlines()

        except (
            FileNotFoundError,
            OSError
        ):

            return alerts

        current_alert = {}

        for line in lines:

            line = line.strip()

            # ------------------------------------------------
            # Time
            # ------------------------------------------------

            if line.startswith("Time"):

                parts = line.split(
                    ":",
                    1
                )

                if len(parts) == 2:

                    current_alert[
                        "time"
                    ] = parts[1].strip()

            # ------------------------------------------------
            # Severity
            # ------------------------------------------------

            elif line.startswith("Severity"):

                parts = line.split(
                    ":",
                    1
                )

                if len(parts) == 2:

                    current_alert[
                        "severity"
                    ] = parts[1].strip()

            # ------------------------------------------------
            # Alert type
            # ------------------------------------------------

            elif line.startswith("Alert Type"):

                parts = line.split(
                    ":",
                    1
                )

                if len(parts) == 2:

                    current_alert[
                        "type"
                    ] = parts[1].strip()

            # ------------------------------------------------
            # Source IP
            # ------------------------------------------------

            elif line.startswith("Source IP"):

                parts = line.split(
                    ":",
                    1
                )

                if len(parts) == 2:

                    current_alert[
                        "source_ip"
                    ] = parts[1].strip()

            # ------------------------------------------------
            # Destination IP
            # ------------------------------------------------

            elif line.startswith(
                "Destination IP"
            ):

                parts = line.split(
                    ":",
                    1
                )

                if len(parts) == 2:

                    current_alert[
                        "destination_ip"
                    ] = parts[1].strip()

            # ------------------------------------------------
            # Details
            # ------------------------------------------------

            elif line.startswith("Details"):

                parts = line.split(
                    ":",
                    1
                )

                if len(parts) == 2:

                    current_alert[
                        "details"
                    ] = parts[1].strip()

                    # ----------------------------------------
                    # Backward compatibility
                    #
                    # Old alerts don't have Severity.
                    # ----------------------------------------

                    if "severity" not in current_alert:

                        current_alert[
                            "severity"
                        ] = (
                            config.SEVERITY_MEDIUM
                        )

                    alerts.append(
                        current_alert.copy()
                    )

                    current_alert = {}

        return alerts


    # ========================================================
    # GET ALERT COUNT
    # ========================================================

    def get_alert_count(self):

        alerts = self._read_log_alerts()

        return len(
            alerts
        )


    # ========================================================
    # GET CURRENT SESSION ALERT COUNT
    # ========================================================

    def get_session_alert_count(self):

        with self.lock:

            return len(
                self.alerts
            )


    # ========================================================
    # GET ALL ALERTS
    # ========================================================

    def get_alerts(self):

        return self._read_log_alerts()


    # ========================================================
    # GET CURRENT SESSION ALERTS
    # ========================================================

    def get_session_alerts(self):

        with self.lock:

            return self.alerts.copy()

    # ========================================================
    # CLEAN OLD LOG BACKUPS
    # ========================================================

    def cleanup_old_backups(self):

        if not os.path.isdir(
            config.LOG_BACKUP_DIRECTORY
        ):
            return

        try:

            backup_files = []

            # ------------------------------------------------
            # Only manage timestamped security-alert backups.
            #
            # Example:
            # security_alerts_2026-08-13_11-04-48.log
            #
            # Do NOT touch legacy files, restored history files,
            # or temporary test files.
            # ------------------------------------------------

            backup_prefix = (
                config.LOG_BACKUP_PREFIX
            )

            for filename in os.listdir(
                config.LOG_BACKUP_DIRECTORY
            ):

                if not filename.lower().endswith(
                    ".log"
                ):
                    continue

                if not filename.startswith(
                    backup_prefix
                ):
                    continue

                full_path = os.path.join(
                    config.LOG_BACKUP_DIRECTORY,
                    filename
                )

                if os.path.isfile(
                    full_path
                ):

                    backup_files.append(
                        full_path
                    )

            backup_files.sort(
                key=lambda path: os.path.getmtime(
                    path
                ),
                reverse=True
            )

            old_files = backup_files[
                config.MAX_LOG_BACKUPS:
            ]

            for old_file in old_files:

                try:

                    os.remove(
                        old_file
                    )

                    print(
                        f"[LOG CLEANUP] Removed: "
                        f"{old_file}"
                    )

                except OSError as error:

                    print(
                        "[ERROR] Could not remove "
                        f"old backup: {old_file}"
                    )

                    print(error)

        except OSError as error:

            print(
                "[ERROR] Could not inspect "
                "log backup directory:"
            )

            print(error)


# ============================================================
# TEST ALERT MANAGER
# ============================================================

def test_alert_manager():

    print(
        "========================================"
    )

    print(
        "       ALERT MANAGER TEST"
    )

    print(
        "========================================"
    )

    manager = AlertManager()

    manager.add_alert(

        config.ALERT_TYPE_TEST,

        "127.0.0.1",

        "127.0.0.1",

        "This is a test security alert.",

        config.SEVERITY_LOW
    )

    print()

    print(
        "Current Session Alerts :",
        manager.get_session_alert_count()
    )

    print(
        "Log Alerts             :",
        manager.get_alert_count()
    )


# ============================================================
# RUN TEST DIRECTLY
# ============================================================

if __name__ == "__main__":

    test_alert_manager()