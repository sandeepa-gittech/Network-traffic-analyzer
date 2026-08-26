



# 🛡️ Network Traffic Analyzer

> **Real-time Python network traffic monitoring and security analysis with live packet inspection, IP filtering, security threat detection, alert management, telemetry, and CSV session export.**

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Capture-orange)](https://scapy.net/)
[![Rich](https://img.shields.io/badge/Rich-Terminal%20Dashboard-purple)](https://rich.readthedocs.io/)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue)](https://www.microsoft.com/windows)

## 📌 Overview

**Network Traffic Analyzer** is a Windows-based Python application for real-time network monitoring and security-focused traffic analysis.

The application captures traffic from:

- Wi-Fi
- Windows Loopback

It provides live visibility into packets, bandwidth, network sources, security alerts, and session history.

## ✨ Features

- Real-time packet capture with Scapy
- Wi-Fi and Windows Loopback monitoring
- Optional IP-based traffic filtering
- Live packet stream
- Packets-per-second telemetry
- Bandwidth monitoring
- Top network generators
- Plaintext protocol detection
- HTTP request detection
- Port scan detection
- TCP flag anomaly detection
- Alert severity classification
- Security alert logging
- Automatic security-log archiving
- Live Rich terminal dashboard
- Session CSV export
- Clean shutdown and final statistics

## 🔐 Security Detection

| Detector | Purpose | Severity |
|---|---|---|
| Plaintext Traffic | Detects plaintext services such as FTP and TELNET | MEDIUM |
| HTTP Requests | Detects plaintext HTTP requests | MEDIUM |
| Port Scan | Detects repeated TCP SYN traffic across multiple destination ports | MEDIUM |
| TCP Flag Anomaly | Detects suspicious TCP flag combinations | HIGH |

### Supported plaintext services

- HTTP
- FTP
- TELNET

### TCP flag anomalies

The detector can identify suspicious combinations including:

```text
SYN + FIN
SYN + RST
FIN + RST
```

## 🎯 IP Filtering

At startup the application asks:

```text
IP Address >
```

Press **Enter** to monitor all traffic, or enter a specific IP address.

Example:

```text
IP Address > 10.62.72.55
```

When an IP is supplied, packets are processed only when the selected IP is the source or destination.

## 🎥 Project Demo

Watch the complete **Network Traffic Analyzer** workflow:

**Startup Interface → IP Filtering → Network Capture → Live Security Dashboard → Security Detection → Shutdown → CSV Export**

### Demo Video

https://github.com/user-attachments/assets/c2bfe298-e24d-4eec-a103-2a8133529fe8

The demonstration shows:

- Custom startup interface
- IP address monitoring
- Wi-Fi and Loopback capture
- Live packet telemetry
- Packets/second monitoring
- Bandwidth monitoring
- Security alerts
- Port scan detection
- TCP flag anomaly detection
- Clean shutdown
- Security alert summary
- CSV traffic-history export

## 🔄 Application Flow

```text
python main.py
       │
       ▼
STARTUP INTERFACE
       │
       ▼
IP Address >
       │
       ├── Enter
       │     └── Monitor all traffic
       │
       └── Enter IP
             └── Monitor selected IP traffic
       │
       ▼
MAIN STATUS INTERFACE
       │
       ▼
Wi-Fi + Loopback Capture
       │
       ▼
5-Second Dashboard Loading
       │
       ▼
LIVE SECURITY DASHBOARD
       │
       ▼
Security Detection + Telemetry
       │
       ▼
Press Q
       │
       ▼
Capture Stopped
       │
       ▼
Security Alert Summary
       │
       ▼
CSV Export
       │
       ▼
Program Exited Cleanly
```

## 📊 Live Dashboard

The dashboard includes alert filtering:

```text
A → All
H → High
M → Medium
L → Low
C → Critical
```

Navigation:

```text
↑ / ↓       Scroll
PageUp      Previous page
PageDown    Next page
Home        First
End         Last
Q           Quit
```

## 💾 CSV Export

At shutdown:

```text
Do you want to save the history as a CSV file? (y/n):
```

Selecting `y` creates a timestamped file:

```text
exports/
└── traffic_history_YYYY-MM-DD_HH-MM-SS.csv
```

The traffic history contains fields such as:

```text
time
source
destination
protocol
source_port
destination_port
size_bytes
interface
```

Example:

```text
time,source,destination,protocol,source_port,destination_port,size_bytes,interface
```

The `exports/` directory is excluded from Git because it contains runtime session data.

## 📝 Security Logging

Security alerts are written to:

```text
logs/security_alerts.log
```

Existing logs can be archived into:

```text
logs/backups/
```

Runtime logs and backups are excluded from Git.

## ⚙️ Configuration

Central configuration is stored in:

```text
config.py
```

It controls items including:

- application settings
- interface configuration
- detector settings
- port-scan threshold
- port-scan time window
- alert cooldowns
- suspicious TCP flag combinations
- dashboard refresh settings
- graph settings
- log backup settings

The tested port-scan configuration is:

```text
Port threshold : 10
Time window    : 10 seconds
Alert cooldown : 10 seconds
```

## 🏗️ Project Structure

```text
NetworkTrafficAnalyzer/
│
├── main.py
├── config.py
├── alert_manager.py
├── alert_summary.py
├── live_dashboard.py
├── plaintext_detector.py
├── portscan_detector.py
├── tcp_flags_detector.py
├── requirements.txt
├── README.md
├── screenshots/
│   ├── startup-interface.png
│   ├── status-interface.png
│   ├── live-dashboard.png
│   └── shutdown-summary.png
└── .gitignore
```

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application |
| Scapy | Packet capture and inspection |
| Rich | Terminal dashboard and UI |
| PyFiglet | ASCII title |
| Threading | Concurrent interface capture |
| CSV | Traffic history export |
| Git / GitHub | Version control and hosting |

## 📦 Installation

### 1. Clone the repository

```cmd
git clone https://github.com/sandeepa-gittech/Network-traffic-analyzer.git
cd NetworkTrafficAnalyzer
```

### 2. Create a virtual environment

```cmd
python -m venv venv
```

### 3. Activate the environment

```cmd
venv\Scripts\activate
```

### 4. Install dependencies

```cmd
pip install -r requirements.txt
```

## ▶️ Run

```cmd
python main.py
```

> **Windows note:** packet capture requires a compatible packet-capture driver/environment and may require suitable permissions.

## 🧪 Local Security Testing

### Plaintext HTTP

Start a local HTTP server:

```cmd
python -m http.server 8000
```

Then generate HTTP traffic:

```cmd
curl.exe http://127.0.0.1:8000/
```

Expected detector result:

```text
PLAINTEXT HTTP
```

### Port Scan

The configured detector is tested using multiple TCP destination ports against the local machine.

Expected result:

```text
PORT SCAN
MEDIUM
```

### TCP Flag Anomaly

A controlled SYN + FIN packet can be sent to `127.0.0.1` for local testing.

Expected result:

```text
TCP FLAG ANOMALY
HIGH
```

## ✅ Validation

The project has been tested for:

```text
✅ Startup interface
✅ IP input and filtering
✅ Wi-Fi capture
✅ Loopback capture
✅ 5-second dashboard loading
✅ Live telemetry dashboard
✅ Plaintext HTTP detection
✅ Plaintext FTP detection
✅ Plaintext TELNET detection
✅ Port scan detection
✅ TCP flag anomaly detection
✅ Alert summary
✅ Security log archiving
✅ CSV export
✅ Clean shutdown
```

## 📋 Dependencies

The project uses the packages listed in `requirements.txt`, including:

```text
scapy
rich
pyfiglet
```

## 🔒 Repository Hygiene

The following runtime/development directories are intentionally excluded from Git:

```text
venv/
__pycache__/
logs/
backup/
exports/
```

This keeps the public repository focused on source code and documentation rather than generated runtime data.

## 📌 Version

```text
1.0.0
```

## 👨‍💻 Author

**Sandeepa Dilmina**

Copyright © 2026 Sandeepa Dilmina. All rights reserved.

## 📄 License

No open-source license has been selected yet.

Add a license before distributing the project under an open-source license.

## 🔗 Repository

https://github.com/sandeepa-gittech/Network-traffic-analyzer
