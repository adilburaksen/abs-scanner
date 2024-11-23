# Advanced Port Scanner

A sophisticated port scanning tool built with Python, featuring service detection, honeypot detection, and vulnerability scanning capabilities.

## Features

- TCP SYN scanning using Scapy
- Service and version detection
- Honeypot detection
- Basic vulnerability scanning
- Asynchronous scanning for improved performance
- Colorized terminal output

## Requirements

- Python 3.8+
- Scapy
- Npcap (for Windows)
- colorama
- tabulate

## Installation

1. Clone the repository:
```bash
git clone https://github.com/adilburaksen/port-scanner.git
cd port-scanner
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. For Windows users, install Npcap from: https://npcap.com/

## Usage

Run the test script to scan a target:
```bash
python test_scanner.py
```

## License

MIT License

## Author

Adil Burak Sen
