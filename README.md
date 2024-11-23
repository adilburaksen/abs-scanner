# 🔍 Advanced Port Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Scapy](https://img.shields.io/badge/scapy-latest-orange)](https://scapy.net/)
[![Release](https://img.shields.io/github/v/release/adilburaksen/port-scanner)](https://github.com/adilburaksen/port-scanner/releases)
[![Last Commit](https://img.shields.io/github/last-commit/adilburaksen/port-scanner)](https://github.com/adilburaksen/port-scanner/commits/master)

> 🛡️ Advanced Port Scanner (APS) is a state-of-the-art network security tool that revolutionizes the way security professionals conduct port scanning and vulnerability assessments. Built with modern Python and powered by Scapy, it combines high performance with user-friendly features.

## About 🌟

Advanced Port Scanner emerged from the need for a more comprehensive and user-friendly network security tool. Unlike traditional port scanners, APS integrates multiple security aspects into a single, cohesive tool:

### Core Philosophy 💭

- **Simplicity**: Complex security tasks made simple through an intuitive CLI
- **Performance**: Blazing fast scans using async operations and multi-threading
- **Accuracy**: Precise service detection and vulnerability assessment
- **Ethics**: Strong focus on responsible security testing

### Key Differentiators 🚀

- 🔥 **Modern Architecture**: Built with Python 3.8+ and async programming
- 🎯 **Smart Scanning**: Intelligent port selection and service fingerprinting
- 🛡️ **Comprehensive Security**: Integrated honeypot detection and vulnerability assessment
- 📊 **Beautiful Output**: Rich CLI interface with colored, structured results
- ⚡ **Flexible Usage**: From quick scans to detailed security audits

### Perfect For 👥

- **Security Professionals**: Comprehensive security assessments
- **Network Administrators**: System monitoring and maintenance
- **Security Researchers**: Network behavior analysis
- **Ethical Hackers**: Penetration testing (with permission)
- **Educational Purposes**: Learning about network security

### Releases 📦

#### Latest Release (v1.0.0) - March 2024
- Initial public release
- Core Features:
  - High-performance port scanning
  - Service detection
  - Honeypot detection
  - Vulnerability scanning
  - Beautiful CLI interface

#### Coming Soon (v1.1.0)
- Enhanced vulnerability database
- Custom scan profiles
- JSON/XML export options
- Scan result comparison
- Performance optimizations

### Ethical Guidelines 🤝

This tool is designed for:
- Authorized security testing
- Network administration
- Educational purposes
- Security research

**Important**: Always ensure you have explicit permission before scanning any systems or networks.

#network-security #port-scanner #python #cybersecurity #ethical-hacking #penetration-testing 
#security-tools #network-monitoring #security-assessment #python3 #async-programming #scapy 
#network-tools #security-automation #infosec #netsec #security-testing #devsecops

---

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

Run the scanner with basic options:
```bash
# Scan specific ports
python nsscan.py -t scanme.nmap.org -p 22-25

# Scan common ports
python nsscan.py -t 192.168.1.1 -p common

# Full port scan (1-65535)
python nsscan.py -t example.com -p all

# Fast scan of common ports
python nsscan.py -t 192.168.1.1 -p common --fast
```

Advanced usage examples:
```bash
# Scan specific ports with more workers
python nsscan.py -t 192.168.1.1 -p 80,443 --workers 200

# Scan a range of ports with shorter timeout
python nsscan.py -t example.com -p 20-30 --timeout 0.5

# Fast scan of multiple ports without vulnerability checking
python nsscan.py -t 10.0.0.1 -p 1-1000 --fast --no-vuln-scan
```

Available options:
```
-t, --target     Target host to scan (IP or domain)
-p, --ports      Ports to scan. Can be:
                 - Specific ports: 80,443
                 - Port range: 22-25
                 - Mixed: 80,443,8080-8090
                 - "common": Scan common ports
                 - "all": Scan all ports (1-65535)
-w, --workers    Number of worker threads (default: 100)
--timeout        Timeout in seconds for each port (default: 1.0)
--fast          Fast scan mode (reduces timeout and increases workers)
--no-vuln-scan  Skip vulnerability scanning
--no-honeypot   Skip honeypot detection
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

**Adil Burak Şen**

- GitHub: [@adilburaksen](https://github.com/adilburaksen)

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation
- [Nmap](https://nmap.org/) for inspiration and service fingerprints
- Open-source security community

---

⭐️ If you find this project useful, please consider giving it a star!
