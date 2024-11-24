#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import Dict, Any
from modules import (
    Config,
    ScopeManager,
    ReconModule,
    WebModule,
    APIModule,
    VulnerabilityModule,
    ReportModule,
    CloudModule
)

class BugBountyScanner:
    def __init__(self):
        self.config = Config()
        self.scope_manager = ScopeManager()
        self.modules = {
            'recon': ReconModule(),
            'web': WebModule(),
            'api': APIModule(),
            'vuln': VulnerabilityModule(),
            'cloud': CloudModule(),
            'report': ReportModule()
        }
        self.results: Dict[str, Any] = {}
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('BugBountyScanner')
    
    def scan(self, target: str, options: Dict[str, Any]):
        """Run all scanning modules on target"""
        self.logger.info(f"Starting scan on {target}")
        
        try:
            # Add target to scope
            self.scope_manager.add_scope(target)
            
            # Run each module
            for module_name, module in self.modules.items():
                if options.get(module_name, True):
                    self.logger.info(f"Running {module_name} module")
                    self.results[module_name] = module.run(target, options)
            
            # Generate report
            if options.get('report', True):
                self.generate_report(target, options)
                
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            raise
    
    def generate_report(self, target: str, options: Dict[str, Any]):
        """Generate scan report"""
        findings = []
        
        # Collect findings from all modules
        for module_name, result in self.results.items():
            if 'vulnerabilities' in result:
                findings.extend(result['vulnerabilities'])
        
        # Generate report using report module
        report_options = {
            'findings': findings,
            'format': options.get('report_format', 'html')
        }
        
        self.modules['report'].run(target, report_options)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Bug Bounty Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t example.com --fast
  %(prog)s -t example.com --modules recon,web
  %(prog)s -t example.com --report-format markdown
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target domain to scan')
    parser.add_argument('--modules',
                       help='Comma-separated list of modules to run (default: all)')
    parser.add_argument('--fast', action='store_true',
                       help='Fast scan with reduced checks')
    parser.add_argument('--report-format', choices=['html', 'markdown', 'json'],
                       default='html', help='Report format (default: html)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)
    
    # Prepare scan options
    options = {
        'report_format': args.report_format,
        'fast': args.fast
    }
    
    # Enable only specified modules if provided
    if args.modules:
        modules = args.modules.split(',')
        for module in ['recon', 'web', 'api', 'vuln', 'cloud', 'report']:
            options[module] = module in modules
    
    # Create and run scanner
    scanner = BugBountyScanner()
    
    try:
        scanner.scan(args.target, options)
        print(f"\nScan completed. Check the report_{args.target}.{args.report_format} file for results.")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
