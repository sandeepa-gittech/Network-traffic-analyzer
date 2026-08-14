# 🛡️ Network Traffic Analyzer

A real-time Python-based network traffic monitoring and security analysis application with live packet inspection, security threat detection, alert severity classification, and a professional Rich terminal dashboard.

## 🚀 Features

- Real-time packet capture using Scapy
- Dual-interface monitoring:
  - Wi-Fi
  - Windows Loopback
- Live packet stream
- Real-time telemetry
- Packets-per-second graph
- Bandwidth graph
- Top network generators
- Security alert dashboard
- Alert severity classification
- Alert filtering
- Session and historical alert separation
- Automatic security-log archiving
- Backup retention management
- Clean application shutdown

## 🔐 Security Detectors

### Plaintext HTTP Detection

Detects plaintext HTTP traffic on configured HTTP ports and identifies HTTP requests such as:

- GET
- POST
- PUT
- DELETE
- HEAD
- OPTIONS
- PATCH

### Port Scan Detection

Detects repeated TCP SYN attempts to multiple destination ports within a configured time window.

### TCP Flag Anomaly Detection

Detects suspicious TCP flag combinations such as:

- SYN + FIN
- SYN + RST
- FIN + RST

## 🎯 Alert Severity

| Alert Type | Severity |
|---|---|
| Plaintext HTTP | MEDIUM |
| Port Scan | HIGH |
| TCP Flag Anomaly | HIGH |

## 🖥️ Dashboard

The terminal dashboard provides:

- LIVE PACKET STREAM
- TELEMETRY
- PACKETS / SECOND
- BANDWIDTH
- TOP NETWORK GENERATORS
- SECURITY SUMMARY
- RECENT SECURITY ALERTS
- SYSTEM STATUS

### Alert Filters

```text
A → All
H → High
M → Medium
L → Low
C → Critical
```

Navigation:

```text
↑ / ↓        Scroll
PageUp       Previous page
PageDown     Next page
Home         First
End          Last
Q            Quit
```

## ⚙️ Configuration

Application settings are centralized in:

```text
config.py
```

This includes:

- application name and version
- network interface names
- security log location
- detector enable/disable settings
- port scan threshold
- TCP suspicious combinations
- dashboard refresh rate
- graph settings
- log backup settings
- backup retention limit

## 📦 Installation

Clone the repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd NetworkTrafficAnalyzer
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

## ▶️ Run

Start the analyzer with:

```powershell
python main.py
```

Administrative privileges may be required for packet capture on Windows.

## 🧪 Security Testing

### HTTP Test

Start a local HTTP server:

```powershell
python -m http.server 8000
```

Then, from another terminal:

```powershell
curl.exe http://127.0.0.1:8000/
```

### Port Scan Test

The project can be tested locally using TCP SYN packets against:

```text
127.0.0.1
```

### TCP Flag Anomaly Test

The TCP anomaly detector can be tested locally using a SYN + FIN packet.

## 📁 Project Structure

```text
NetworkTrafficAnalyzer/
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
└── .gitignore
```

## 📋 Dependencies

- Python
- Scapy
- Rich

See `requirements.txt` for the exact package versions.

## 🔒 Logging

Runtime security logs are intentionally excluded from Git using `.gitignore`.

The application supports:

- current-session security logs
- timestamped historical backups
- configurable backup retention

## 📌 Version

Current version:

```text
1.0.0
```

## 📄 License

Add your preferred license before publishing the repository.
