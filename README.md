# ABS Scanner - Advanced Bug Bounty Scanner

ABS Scanner is a comprehensive bug bounty and security assessment tool designed to help security researchers and bug bounty hunters identify potential vulnerabilities across various attack surfaces, including web applications, APIs, and cloud resources.

## Features

### Core Modules
- **Reconnaissance Module**: Asset discovery and subdomain enumeration
- **Web Module**: Web application security testing
- **API Module**: API endpoint discovery and security testing
- **Vulnerability Module**: Common vulnerability scanning
- **Cloud Module**: Cloud resource discovery and security checks
- **CVE Module**: CVE database integration
- **Report Module**: Detailed reporting in multiple formats

### Key Capabilities
- Subdomain enumeration and asset discovery
- Web vulnerability scanning (XSS, SQLi, SSRF, etc.)
- API security testing
- Cloud resource misconfiguration detection
- CVE database integration
- Custom payload management
- Comprehensive reporting (HTML, Markdown, JSON)

### Cloud Security Features
- AWS resource discovery and security checks
- Azure resource discovery and security checks
- GCP resource discovery and security checks
- Storage bucket misconfiguration detection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/adilburaksen/abs-scanner.git
cd abs-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Optional: Configure cloud provider credentials if using cloud scanning features:
- AWS: Configure AWS credentials (`~/.aws/credentials` or environment variables)
- Azure: Set up Azure authentication
- GCP: Configure GCP service account

## Usage

### Basic Scan
```bash
python bbscanner.py --target example.com
```

### Module-Specific Scan
```bash
python bbscanner.py --target example.com --modules recon,web,api,vuln,cloud
```

### Available Modules
- `recon`: Reconnaissance and asset discovery
- `web`: Web application security testing
- `api`: API security testing
- `vuln`: Vulnerability scanning
- `cloud`: Cloud resource security testing
- `report`: Report generation

## Configuration

The scanner can be configured through command-line arguments or a configuration file. Key settings include:

- Target scope and exclusions
- Scanning intensity and timeout settings
- Custom payload definitions
- Report format preferences
- Cloud provider settings

## Output

The scanner generates detailed reports in multiple formats:
- HTML reports with interactive elements
- Markdown reports for easy sharing
- JSON output for integration with other tools

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## Security

- Please use this tool responsibly and only on systems you have permission to test
- Follow responsible disclosure practices
- Respect target system resources and rate limits

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Adil Burak ŞEN
- GitHub: [@adilburaksen](https://github.com/adilburaksen)

## Acknowledgments

Special thanks to all contributors and the bug bounty community for their valuable input and feedback.
