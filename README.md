# 🛡️ M0X1 SOC Platform

<div align="center">

**A Modular Terminal-Based Security Operations Center (SOC) Platform Built with Python**

*Designed for Blue Team operations, cybersecurity learning, and SOC workflow simulation.*

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-success?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

</div>

---

# 📖 Overview

**M0X1 SOC Platform** is a modular, terminal-based Security Operations Center (SOC) project developed in Python.

The platform simulates essential Blue Team operations by combining multiple cybersecurity modules into one interactive application. It is designed to help students and cybersecurity enthusiasts understand how a SOC environment works, from monitoring systems to detecting threats and responding to incidents.

Rather than focusing on a single security task, M0X1 provides a complete workflow where different modules work together to improve visibility, detection, and incident handling.

---

# ✨ Features

- 🌐 Network Scanner
- 🖥️ Process Monitor
- 📄 Log Analyzer
- 🔍 IOC Scanner
- 🚨 Alert Manager
- 🌍 Threat Intelligence
- 📊 Live Monitoring
- 📈 Dashboard
- 📝 Report Generator
- 🛠 Incident Response
- ⚙️ Settings Management

---

# 🏗️ Architecture

```
                    +----------------------+
                    |      M0X1 Menu       |
                    +----------+-----------+
                               |
       --------------------------------------------------
       |        |          |         |         |        |
    Network  Process     Live      Log       IOC      ...
    Scanner  Monitor   Monitor   Analyzer   Scan
       |        |          |         |         |
       +--------+----------+---------+---------+
                           |
                     Alert Manager <=======> Unified Dashboard
                           |                    (Live Overview)
                   Incident Response
                           |
                     Reports Center
```

---

# 📂 Project Structure

```text
M0X1-SOC/
│
├── data/
│   ├── alerts.json
│   ├── config.json
│   ├── iocs.json
│   ├── network_scan.json
│   └── threat_db.json
│
├── logs/
│
├── modules/
│   ├── alert_manager.py
│   ├── dashboard.py
│   ├── incident_response.py
│   ├── ioc_scanner.py
│   ├── live_monitor.py
│   ├── log_analyzer.py
│   ├── network_scanner.py
│   ├── process_monitor.py
│   ├── reports.py
│   ├── settings.py
│   └── threat_intelligence.py
│
├── banner.py
├── config.py
├── menu.py
├── m0x1.py
├── requirements.txt
└── README.md
```

---

# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/M0X1-SOC.git
```

Move into the project directory:

```bash
cd M0X1-SOC
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment:

### Linux

```bash
source .venv/bin/activate
```

### Windows

```cmd
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Project

```bash
python m0x1.py
```

---

# 🛠 Technologies Used

- Python 3
- Rich
- Scapy
- Psutil
- Requests
- JSON
- Linux
- Windows

---

# 📚 Modules Overview

| Module | Description |
|----------|-------------|
| Network Scanner | Discovers hosts and scans open ports on the network. |
| Process Monitor | Monitors running system processes. |
| Log Analyzer | Analyzes log files for suspicious activities and security events. |
| IOC Scanner | Detects Indicators of Compromise (IPs, Domains, Hashes). |
| Threat Intelligence | Checks indicators against threat intelligence data. |
| Alert Manager | Stores, displays, and manages generated alerts. |
| Live Monitoring | Performs continuous monitoring of system activities. |
| Dashboard | Displays an overview of collected security information. |
| Reports | Generates security reports from collected findings. |
| Incident Response | Assists with basic incident response workflows. |
| Settings | Manages application configuration. |

---

# 🎯 Learning Objectives

This project was built to practice and demonstrate knowledge of:

- Security Operations Center (SOC)
- Blue Team Fundamentals
- Network Monitoring
- Log Analysis
- Threat Detection
- Incident Response
- IOC Analysis
- Threat Intelligence
- Python Automation
- Modular Software Design

---

# 🚀 Future Improvements

Some features planned for future versions include:

- VirusTotal API Integration
- YARA Rule Support
- Sigma Rule Support
- MITRE ATT&CK Mapping
- Email Notifications
- Web Dashboard
- SIEM Integration
- Real-Time Log Streaming
- User Authentication
- Docker Support

---


# 🤝 Contributing

Contributions, suggestions, and improvements are always welcome.

Feel free to fork the repository, open issues, or submit pull requests.

---


# 👨‍💻 Author

## Mohamed Ashraf Abdrabou

Cybersecurity Student

Blue Team | SOC | Incident Response | Python

GitHub: https://github.com/mohamedabdrabou990-web

LinkedIn: www.linkedin.com/in/mohamed-ashraf-abdrabou



---

<div align="center">

⭐ If you found this project useful, consider giving it a star.

</div>
