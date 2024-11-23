# 🔍 Advanced Port Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Scapy](https://img.shields.io/badge/scapy-latest-orange)](https://scapy.net/)

A sophisticated network security tool built with Python that combines port scanning, service detection, honeypot detection, and vulnerability assessment capabilities. Perfect for security professionals, network administrators, and ethical hackers.

![Port Scanner Demo](https://raw.githubusercontent.com/adilburaksen/port-scanner/master/docs/demo.gif)

## ✨ Key Features

- 🚀 **High-Performance Scanning**
  - Asynchronous TCP SYN scanning using Scapy
  - Multi-threaded architecture for faster results
  - Configurable timeout and worker settings

- 🔍 **Advanced Detection**
  - Service and version fingerprinting
  - Banner grabbing
  - OS detection capabilities
  - Common vulnerability checks

- 🍯 **Honeypot Detection**
  - Behavioral analysis
  - Service consistency checking
  - Response pattern analysis
  - Suspicious service detection

- 🛡️ **Security Features**
  - Basic vulnerability scanning
  - Service misconfiguration detection
  - Common security issue identification
  - CVE checking capabilities

- 📊 **User-Friendly Output**
  - Colorized terminal interface
  - Structured JSON output option
  - Detailed scan reports
  - Progress tracking

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Npcap (Windows) or libpcap (Linux/macOS)
- Administrative privileges for SYN scanning

### Installation

1. Clone the repository:
```bash
git clone https://github.com/adilburaksen/port-scanner.git
cd port-scanner
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install packet capture library:
   - Windows: [Npcap](https://npcap.com/)
   - Linux: `sudo apt-get install libpcap-dev`
   - macOS: `brew install libpcap`

### Basic Usage

Run a basic scan:
```bash
python test_scanner.py
```

## 📚 Documentation

### Module Structure

- `port_scanner.py`: Core scanning engine
- `modules/`
  - `honeypot_detector.py`: Honeypot detection logic
  - `vulnerability_scanner.py`: Vulnerability assessment
  - `service_detection.py`: Service fingerprinting
  - `distributed_scanner.py`: Distributed scanning capabilities
  - `reputation_checker.py`: IP reputation checking

### Configuration

The scanner can be configured through `config.py`:
- Port ranges
- Timeout settings
- Worker count
- Custom vulnerability rules

### Example Output

```
Starting scan of scanme.nmap.org...
Port range: 20-25

+------+--------+-----------------+---------+
| Port | Status | Service         | Latency |
+------+--------+-----------------+---------+
|   22 | OPEN   | SSH (OpenSSH)  | 125ms   |
|   23 | OPEN   | Telnet         | 130ms   |
+------+--------+-----------------+---------+

Honeypot Analysis:
Risk Score: 0.40

Vulnerabilities Found:
No critical vulnerabilities detected
```

## 🛡️ Security Considerations

This tool is intended for:
- Network administrators
- Security professionals
- Ethical hackers
- Educational purposes

**Important**: Always ensure you have explicit permission to scan any target systems.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Adil Burak Sen**

- GitHub: [@adilburaksen](https://github.com/adilburaksen)

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation
- [Nmap](https://nmap.org/) for inspiration and service fingerprints
- Open-source security community

---

⭐️ If you find this project useful, please consider giving it a star!
