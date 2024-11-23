#!/usr/bin/env python3

import asyncio
import sys
import argparse
from port_scanner import PortScanner
from modules.honeypot_detector import HoneypotDetector
from modules.vulnerability_scanner import VulnerabilityScanner
from tabulate import tabulate
from colorama import init, Fore, Style, Back

# Initialize colorama
init()

def format_latency(latency):
    """Format latency with color based on speed"""
    if latency < 100:
        return f"{Fore.GREEN}{latency:.1f}ms{Style.RESET_ALL}"
    elif latency < 300:
        return f"{Fore.YELLOW}{latency:.1f}ms{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}{latency:.1f}ms{Style.RESET_ALL}"

def format_service(service, version):
    """Format service info with version if available"""
    if not service:
        return f"{Fore.YELLOW}unknown{Style.RESET_ALL}"
    if version:
        return f"{Fore.GREEN}{service}{Style.RESET_ALL} ({Fore.CYAN}{version}{Style.RESET_ALL})"
    return f"{Fore.GREEN}{service}{Style.RESET_ALL}"

def print_scan_results(results):
    """Print scan results in a nice table format"""
    if not results:
        print(f"{Fore.YELLOW}No open ports found{Style.RESET_ALL}")
        return

    # Prepare table data
    headers = ["Port", "Status", "Service", "Latency"]
    table_data = []
    
    for result in results:
        status = f"{Fore.GREEN}OPEN{Style.RESET_ALL}" if result.is_open else f"{Fore.RED}CLOSED{Style.RESET_ALL}"
        service_info = format_service(result.service, result.version)
        latency = format_latency(result.latency) if result.latency else "-"
        
        table_data.append([
            result.port,
            status,
            service_info,
            latency
        ])
    
    print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))

def print_honeypot_results(score, reasons):
    """Print honeypot analysis results"""
    if score < 0.3:
        score_color = Fore.GREEN
    elif score < 0.7:
        score_color = Fore.YELLOW
    else:
        score_color = Fore.RED
    
    print(f"\n{Fore.CYAN}Honeypot Analysis:{Style.RESET_ALL}")
    print(f"Risk Score: {score_color}{score:.2f}{Style.RESET_ALL}")
    
    if reasons:
        print(f"\n{Fore.CYAN}Detection Reasons:{Style.RESET_ALL}")
        for reason in reasons:
            print(f"  {Fore.YELLOW}•{Style.RESET_ALL} {reason}")

def print_vulnerability_results(vulnerabilities):
    """Print vulnerability scan results"""
    if not vulnerabilities:
        print(f"\n{Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.RED}Vulnerabilities Found:{Style.RESET_ALL}")
    for vuln in vulnerabilities:
        severity_color = {
            'CRITICAL': Back.RED + Fore.WHITE,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }.get(vuln.severity, Fore.WHITE)
        
        print(f"\n{severity_color}{vuln.name}{Style.RESET_ALL}")
        print(f"  Severity: {severity_color}{vuln.severity}{Style.RESET_ALL}")
        print(f"  Port: {vuln.port}")
        print(f"  Service: {vuln.service}")
        print(f"  Description: {vuln.description}")
        print(f"\n  {Fore.CYAN}Recommendations:{Style.RESET_ALL}")
        for rec in vuln.recommendations:
            print(f"    {Fore.YELLOW}•{Style.RESET_ALL} {rec}")

def parse_port_range(port_range):
    """Parse port range string (e.g., '80', '22-25', '80,443,8080-8090', 'common', 'all')"""
    # Önceden tanımlanmış port listeleri
    COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
    
    # Özel anahtar kelimeler
    if port_range.lower() == 'all':
        return (1, 65535)
    elif port_range.lower() == 'common':
        return (min(COMMON_PORTS), max(COMMON_PORTS))
    
    # Normal port aralığı parse etme
    ports = set()
    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            if start < 1 or end > 65535:
                raise ValueError("Port numbers must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError("Port numbers must be between 1 and 65535")
            ports.add(port)
    return min(ports), max(ports)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Network Security Scanner - Port scanning, service detection, and vulnerability assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -t scanme.nmap.org -p 22-25
  %(prog)s -t 192.168.1.1 -p common        # Scan common ports
  %(prog)s -t example.com -p all           # Scan all ports (1-65535)
  %(prog)s -t 192.168.1.1 -p 80,443 --workers 200
  %(prog)s -t example.com -p 20-30 --timeout 0.5
  %(prog)s -t 10.0.0.1 -p 1-1000 --no-vuln-scan
''')
    
    parser.add_argument('-t', '--target', required=True,
                      help='Target host to scan (IP address or domain name)')
    parser.add_argument('-p', '--ports', required=True,
                      help='Port(s) to scan. Can be:\n'
                           '- Specific ports: 80,443\n'
                           '- Port range: 22-25\n'
                           '- Mixed: 80,443,8080-8090\n'
                           '- "common": Scan common ports\n'
                           '- "all": Scan all ports (1-65535)')
    parser.add_argument('-w', '--workers', type=int, default=100,
                      help='Number of worker threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                      help='Timeout in seconds for each port (default: 1.0)')
    parser.add_argument('--no-vuln-scan', action='store_true',
                      help='Skip vulnerability scanning')
    parser.add_argument('--no-honeypot', action='store_true',
                      help='Skip honeypot detection')
    parser.add_argument('--fast', action='store_true',
                      help='Fast scan mode (reduces timeout and increases workers)')
    
    return parser.parse_args()

async def main():
    args = parse_arguments()
    
    # Fast scan mode ayarları
    if args.fast:
        args.timeout = 0.3
        args.workers = 200
    
    try:
        port_range = parse_port_range(args.ports)
    except ValueError as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return 1
    
    total_ports = port_range[1] - port_range[0] + 1
    
    print(f"\n{Fore.CYAN}Network Security Scanner{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Target:{Style.RESET_ALL} {Fore.YELLOW}{args.target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Port range:{Style.RESET_ALL} {port_range[0]}-{port_range[1]} ({total_ports} ports)")
    print(f"{Fore.CYAN}Workers:{Style.RESET_ALL} {args.workers}")
    print(f"{Fore.CYAN}Timeout:{Style.RESET_ALL} {args.timeout}s")
    if args.fast:
        print(f"{Fore.YELLOW}Fast scan mode enabled{Style.RESET_ALL}")
    
    try:
        # Port scanning
        print(f"\n{Fore.CYAN}Performing port scan...{Style.RESET_ALL}")
        scanner = PortScanner(max_workers=args.workers, timeout=args.timeout)
        results = await scanner.scan_target(args.target, port_range)
        print_scan_results(results)
        
        # Honeypot detection
        if not args.no_honeypot:
            print(f"\n{Fore.CYAN}Checking for honeypot characteristics...{Style.RESET_ALL}")
            honeypot_detector = HoneypotDetector()
            open_ports = [r.port for r in results if r.is_open]
            if open_ports:
                honeypot_score = honeypot_detector.analyze_target(args.target, open_ports)
                print_honeypot_results(honeypot_score.score, honeypot_score.reasons)
            else:
                print(f"{Fore.YELLOW}No open ports to analyze for honeypot characteristics{Style.RESET_ALL}")
        
        # Vulnerability scanning
        if not args.no_vuln_scan and open_ports:
            print(f"\n{Fore.CYAN}Scanning for vulnerabilities...{Style.RESET_ALL}")
            vuln_scanner = VulnerabilityScanner()
            port_info = [{'port': r.port, 'service': r.service} for r in results if r.is_open]
            vulnerabilities = vuln_scanner.scan_target(args.target, port_info)
            print_vulnerability_results(vulnerabilities)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}Error during scan: {e}{Style.RESET_ALL}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
