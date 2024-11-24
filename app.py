import os
import sys
import argparse
from datetime import datetime
from modules.web_scanner import WebScanner
from modules.port_scanner import PortScanner
from modules.dir_enum import DirectoryEnumerator
from modules.vuln_scanner import VulnerabilityScanner
from modules.report_generator import ReportGenerator
from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.osint import OSINTGatherer
from modules.recon.tech_detect import TechnologyDetector
from config import Config

class SecurityScanner:
    def __init__(self):
        self.config = Config()
        self.web_scanner = WebScanner()
        self.port_scanner = PortScanner()
        self.dir_enumerator = DirectoryEnumerator()
        self.vuln_scanner = VulnerabilityScanner()
        self.report_generator = ReportGenerator()
        self.subdomain_enumerator = SubdomainEnumerator("")
        self.osint_gatherer = OSINTGatherer("")
        self.tech_detector = TechnologyDetector()
        
    def start_scan(self, target_url, scan_type="full"):
        """
        Start a security scan with specified parameters
        """
        print(f"\n[+] Starting security scan for {target_url}")
        print(f"[+] Scan type: {scan_type}")
        print(f"[+] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        results = {
            "target_url": target_url,
            "scan_type": scan_type,
            "start_time": datetime.now(),
            "findings": []
        }

        try:
            # OSINT Gathering
            print("[+] Starting OSINT gathering...")
            self.osint_gatherer.target_domain = target_url
            results["osint"] = self.osint_gatherer.gather_all()

            # Subdomain Enumeration
            print("[+] Starting subdomain enumeration...")
            self.subdomain_enumerator.target_domain = target_url
            results["subdomains"] = self.subdomain_enumerator.enumerate()

            # Technology Detection
            print("[+] Starting technology detection...")
            results["technologies"] = self.tech_detector.detect_technologies(f"https://{target_url}")

            # Web technology detection
            print("[+] Starting web application scanning...")
            tech_results = self.web_scanner.scan(target_url)
            results["web_technologies"] = tech_results

            # Port scanning
            if scan_type in ["full", "port"]:
                print("[+] Starting port scanning...")
                port_results = self.port_scanner.scan(target_url)
                results["open_ports"] = port_results

            # Directory enumeration
            if scan_type in ["full", "dir"]:
                print("[+] Starting directory enumeration...")
                dir_results = self.dir_enumerator.scan(target_url)
                results["directories"] = dir_results

            # Vulnerability scanning
            if scan_type in ["full", "vuln"]:
                print("[+] Starting vulnerability scanning...")
                vuln_results = self.vuln_scanner.scan(target_url)
                results["vulnerabilities"] = vuln_results

            # Generate report
            print("[+] Generating report...")
            report_path = self.report_generator.generate(results)
            print(f"\n[+] Scan completed successfully!")
            print(f"[+] Report generated: {report_path}")
            print(f"[+] End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            return results

        except Exception as e:
            print(f"\n[-] Error during scan: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(
        description="Python Web Application Security Scanner",
        epilog="Example: python app.py -t example.com -s full"
    )
    parser.add_argument("-t", "--target", help="Target URL to scan", required=True)
    parser.add_argument("-s", "--scan-type", help="Scan type (full/port/dir/vuln)", default="full")
    parser.add_argument("-o", "--output", help="Output directory for reports", default="reports")
    parser.add_argument("--osint-only", help="Perform OSINT gathering only", action="store_true")
    parser.add_argument("--subdomains-only", help="Perform subdomain enumeration only", action="store_true")
    parser.add_argument("--tech-detect-only", help="Perform technology detection only", action="store_true")
    
    args = parser.parse_args()

    # Create scanner instance
    scanner = SecurityScanner()
    
    # Start scan
    if args.osint_only:
        scanner.osint_gatherer.target_domain = args.target
        results = scanner.osint_gatherer.gather_all()
    elif args.subdomains_only:
        scanner.subdomain_enumerator.target_domain = args.target
        results = scanner.subdomain_enumerator.enumerate()
    elif args.tech_detect_only:
        results = scanner.tech_detector.detect_technologies(f"https://{args.target}")
    else:
        results = scanner.start_scan(args.target, args.scan_type)
    
    if results:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
