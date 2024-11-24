import os
import json
import logging
from typing import Dict, Any, List
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import matplotlib.pyplot as plt
import seaborn as sns
from .base import BaseModule

class ReportGenerator(BaseModule):
    def __init__(self, scan_results: Dict[str, Any], options: Dict[str, Any] = None):
        self.scan_results = scan_results
        self.options = options or {}
        self.report_dir = self.options.get('report_dir', 'reports')
        self.company_name = self.options.get('company_name', 'ABS Scanner Report')
        self.report_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Ensure report directory exists
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def _generate_charts(self) -> Dict[str, str]:
        """Generate charts for the report."""
        charts = {}
        
        # Set style
        plt.style.use('seaborn')
        
        # Severity Distribution Chart
        severity_counts = self.scan_results.get('analysis', {}).get('severity_counts', {})
        if severity_counts:
            plt.figure(figsize=(10, 6))
            sns.barplot(
                x=list(severity_counts.keys()),
                y=list(severity_counts.values()),
                palette=['darkred', 'red', 'orange', 'yellow']
            )
            plt.title('Vulnerability Severity Distribution')
            plt.xlabel('Severity Level')
            plt.ylabel('Number of Vulnerabilities')
            
            # Save chart
            severity_chart_path = os.path.join(self.report_dir, f'severity_dist_{self.report_id}.png')
            plt.savefig(severity_chart_path)
            plt.close()
            
            charts['severity_distribution'] = severity_chart_path
        
        # Vulnerability Types Chart
        vuln_types = self.scan_results.get('analysis', {}).get('vulnerability_types', {})
        if vuln_types:
            plt.figure(figsize=(12, 6))
            sns.barplot(
                x=list(vuln_types.keys()),
                y=list(vuln_types.values()),
                palette='husl'
            )
            plt.title('Vulnerability Types Distribution')
            plt.xlabel('Vulnerability Type')
            plt.ylabel('Count')
            plt.xticks(rotation=45)
            
            # Save chart
            types_chart_path = os.path.join(self.report_dir, f'vuln_types_{self.report_id}.png')
            plt.savefig(types_chart_path)
            plt.close()
            
            charts['vulnerability_types'] = types_chart_path
        
        return charts

    def _prepare_report_data(self) -> Dict[str, Any]:
        """Prepare data for the report template."""
        return {
            'company_name': self.company_name,
            'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'report_id': self.report_id,
            'target_url': self.scan_results.get('target_url'),
            'scan_results': self.scan_results,
            'charts': self._generate_charts(),
            'summary': {
                'total_vulnerabilities': len(self.scan_results.get('findings', [])),
                'critical_count': self.scan_results.get('analysis', {}).get('severity_counts', {}).get('critical', 0),
                'high_count': self.scan_results.get('analysis', {}).get('severity_counts', {}).get('high', 0),
                'medium_count': self.scan_results.get('analysis', {}).get('severity_counts', {}).get('medium', 0),
                'low_count': self.scan_results.get('analysis', {}).get('severity_counts', {}).get('low', 0)
            }
        }

    def generate_html_report(self) -> str:
        """Generate HTML report."""
        try:
            template = self.env.get_template('report_template.html')
            report_data = self._prepare_report_data()
            
            html_content = template.render(**report_data)
            
            # Save HTML report
            html_path = os.path.join(self.report_dir, f'report_{self.report_id}.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return html_path
        except Exception as e:
            logging.error(f"Error generating HTML report: {str(e)}")
            raise

    def generate_pdf_report(self) -> str:
        """Generate PDF report from HTML."""
        try:
            html_path = self.generate_html_report()
            pdf_path = os.path.join(self.report_dir, f'report_{self.report_id}.pdf')
            
            # Convert HTML to PDF
            HTML(filename=html_path).write_pdf(pdf_path)
            
            return pdf_path
        except Exception as e:
            logging.error(f"Error generating PDF report: {str(e)}")
            raise

    def generate_json_report(self) -> str:
        """Generate JSON report."""
        try:
            report_data = self._prepare_report_data()
            json_path = os.path.join(self.report_dir, f'report_{self.report_id}.json')
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            
            return json_path
        except Exception as e:
            logging.error(f"Error generating JSON report: {str(e)}")
            raise

    def run(self) -> Dict[str, Any]:
        """Generate all report formats."""
        try:
            results = {
                'report_id': self.report_id,
                'html_report': None,
                'pdf_report': None,
                'json_report': None
            }
            
            # Generate reports in all formats
            results['html_report'] = self.generate_html_report()
            results['pdf_report'] = self.generate_pdf_report()
            results['json_report'] = self.generate_json_report()
            
            return results
        except Exception as e:
            logging.error(f"Error generating reports: {str(e)}")
            return {
                'error': str(e)
            }
