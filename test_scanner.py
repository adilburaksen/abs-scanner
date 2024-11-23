#!/usr/bin/env python3

import asyncio
import sys
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
    # Score color based on risk level
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
        # Set color based on severity
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

async def main():
    target = "scanme.nmap.org"
    port_range = (22, 23)  # Daha dar bir port aralığı
    
    print(f"\n{Fore.CYAN}Starting scan of {Fore.YELLOW}{target}{Style.RESET_ALL}")
    print(f"Port range: {port_range[0]}-{port_range[1]}")
    
    try:
        # Port taraması
        print(f"\n{Fore.CYAN}Performing port scan...{Style.RESET_ALL}")
        scanner = PortScanner(max_workers=200, timeout=0.5)  # Daha fazla worker ve daha kısa timeout
        results = await scanner.scan_target(target, port_range)
        print_scan_results(results)
        
        # Honeypot kontrolü
        print(f"\n{Fore.CYAN}Checking for honeypot characteristics...{Style.RESET_ALL}")
        honeypot_detector = HoneypotDetector()
        open_ports = [r.port for r in results if r.is_open]
        if open_ports:
            honeypot_score = honeypot_detector.analyze_target(target, open_ports)
            print_honeypot_results(honeypot_score.score, honeypot_score.reasons)
        else:
            print(f"{Fore.YELLOW}No open ports to analyze for honeypot characteristics{Style.RESET_ALL}")
            
        # Güvenlik açığı taraması
        if open_ports:
            print(f"\n{Fore.CYAN}Scanning for vulnerabilities...{Style.RESET_ALL}")
            vuln_scanner = VulnerabilityScanner()
            port_info = [{'port': r.port, 'service': r.service} for r in results if r.is_open]
            vulnerabilities = vuln_scanner.scan_target(target, port_info)
            print_vulnerability_results(vulnerabilities)
        else:
            print(f"{Fore.YELLOW}No open ports to scan for vulnerabilities{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error during scan: {e}{Style.RESET_ALL}", file=sys.stderr)
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
