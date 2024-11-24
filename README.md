# ABS Scanner - Advanced Web Application Security Scanner

<div align="center">
  <img src="docs/images/logo.png" alt="ABS Scanner Logo" width="200"/>
  <br>
  <strong>🔒 Comprehensive Web Application Security Assessment Tool 🔍</strong>
</div>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

## 🌟 Features

### 🔍 Reconnaissance & Information Gathering
- **OSINT Module**
  - WHOIS information gathering
  - Cloud service exposure detection (AWS, Azure, GCP)
  - GitHub repository exposure analysis
  - Email breach detection (via HaveIBeenPwned)
  - Domain intelligence gathering

- **Subdomain Enumeration**
  - Brute-force subdomain discovery
  - DNS record analysis
  - HTTP/HTTPS availability checking
  - Parallel scanning support
  - Custom wordlist support

- **Technology Detection**
  - Web server fingerprinting
  - CMS detection (WordPress, Drupal, Joomla)
  - JavaScript framework identification
  - Security header analysis
  - Cookie security assessment

### 🛡️ Security Assessment
- **Port Scanning**
  - Fast port discovery
  - Service version detection
  - Banner grabbing
  - Common vulnerability checking
  - Port security recommendations

- **Directory Enumeration**
  - Recursive directory scanning
  - Sensitive file detection
  - Custom wordlist support
  - Rate limiting capabilities
  - Smart error detection

- **Vulnerability Scanning**
  - Cross-Site Scripting (XSS) detection
  - SQL Injection testing
  - Local/Remote File Inclusion checks
  - Server-Side Request Forgery (SSRF)
  - Command Injection detection
  - Security misconfiguration analysis

### 📊 Reporting
- **Comprehensive Reports**
  - Detailed HTML reports
  - PDF export functionality
  - Executive summary
  - Technical findings
  - Remediation recommendations
  - Visual charts and statistics

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git

### Quick Start
```bash
# Clone the repository
git clone https://github.com/adilburaksen/abs-scanner.git
cd abs-scanner

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Optional Dependencies
- Nmap: For enhanced port scanning
- Chromium: For JavaScript-rendered content analysis
- Tesseract: For OCR capabilities in screenshot analysis

## 💻 Usage

### Basic Scanning
```bash
# Full scan of a target
python app.py -t example.com

# Specific module scanning
python app.py -t example.com -s [port|dir|vuln]
```

### Advanced Options
```bash
# OSINT gathering only
python app.py -t example.com --osint-only

# Subdomain enumeration
python app.py -t example.com --subdomains-only

# Technology detection
python app.py -t example.com --tech-detect-only

# Custom output directory
python app.py -t example.com -o /path/to/reports
```

## 🔧 Configuration

### Config File
Edit `config.py` to customize:
```python
# Scanning configurations
MAX_THREADS = 10
TIMEOUT = 30
RATE_LIMIT = 100  # requests per minute

# Module-specific settings
PORT_SCAN_RANGE = "1-1000"
SUBDOMAIN_WORDLIST = "wordlists/subdomains.txt"
```

### Environment Variables
```bash
# API Keys (optional)
export HAVEIBEENPWNED_API_KEY="your_api_key"
export SHODAN_API_KEY="your_api_key"
```

## 🔍 Modules

### Core Modules
- **Web Scanner**: Web application security assessment
- **Port Scanner**: Network port analysis
- **Directory Enumerator**: Web content discovery
- **Vulnerability Scanner**: Security vulnerability detection
- **Report Generator**: Comprehensive report creation

### Reconnaissance Modules
- **OSINT**: Open-source intelligence gathering
- **Subdomain Enumeration**: Subdomain discovery
- **Technology Detection**: Stack identification

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and ethical testing purposes only. Always obtain proper authorization before scanning any systems or networks. The developers assume no liability for misuse or damage caused by this program.

## 🙏 Acknowledgments

- Inspired by [Rengine](https://github.com/yogeshojha/rengine)
- Thanks to all [contributors](https://github.com/adilburaksen/abs-scanner/graphs/contributors)

---

<div align="center">
  <strong>Made with ❤️ by Adil Burak ŞEN</strong>
  <br>
  <small>© 2023 ABS Scanner. All rights reserved.</small>
</div>
