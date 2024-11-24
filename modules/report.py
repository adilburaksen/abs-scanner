from typing import Dict, Any, List
import json
import markdown
from datetime import datetime
from .base import BaseModule

class ReportModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.report_data: Dict[str, Any] = {}
        
    def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Generating report for {target}")
        
        self.report_data = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'findings': options.get('findings', []),
            'summary': self._generate_summary(options.get('findings', [])),
            'recommendations': self._generate_recommendations(options.get('findings', []))
        }
        
        if options.get('format') == 'html':
            self.generate_html_report()
        elif options.get('format') == 'markdown':
            self.generate_markdown_report()
        else:
            self.generate_json_report()
            
        return self.report_data
    
    def generate_html_report(self):
        """Generate HTML report"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .severity-high {{ color: #d9534f; }}
                .severity-medium {{ color: #f0ad4e; }}
                .severity-low {{ color: #5bc0de; }}
                .finding {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <h2>Target: {target}</h2>
            <p>Scan Date: {scan_date}</p>
            
            <h3>Summary</h3>
            {summary_html}
            
            <h3>Findings</h3>
            {findings_html}
            
            <h3>Recommendations</h3>
            {recommendations_html}
        </body>
        </html>
        """
        
        findings_html = self._generate_findings_html()
        summary_html = self._generate_summary_html()
        recommendations_html = self._generate_recommendations_html()
        
        html = template.format(
            target=self.report_data['target'],
            scan_date=self.report_data['scan_date'],
            summary_html=summary_html,
            findings_html=findings_html,
            recommendations_html=recommendations_html
        )
        
        with open(f"report_{self.report_data['target']}.html", 'w') as f:
            f.write(html)
    
    def generate_markdown_report(self):
        """Generate Markdown report"""
        template = """
# Security Scan Report

## Target: {target}
Scan Date: {scan_date}

## Summary
{summary}

## Findings
{findings}

## Recommendations
{recommendations}
        """
        
        markdown_content = template.format(
            target=self.report_data['target'],
            scan_date=self.report_data['scan_date'],
            summary=self._generate_summary_markdown(),
            findings=self._generate_findings_markdown(),
            recommendations=self._generate_recommendations_markdown()
        )
        
        with open(f"report_{self.report_data['target']}.md", 'w') as f:
            f.write(markdown_content)
    
    def generate_json_report(self):
        """Generate JSON report"""
        with open(f"report_{self.report_data['target']}.json", 'w') as f:
            json.dump(self.report_data, f, indent=4)
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Generate summary statistics"""
        summary = {
            'total_findings': len(findings),
            'high_severity': len([f for f in findings if f.get('severity') == 'high']),
            'medium_severity': len([f for f in findings if f.get('severity') == 'medium']),
            'low_severity': len([f for f in findings if f.get('severity') == 'low'])
        }
        return summary
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Add general recommendations
        if any(f.get('type') == 'xss' for f in findings):
            recommendations.append("Implement proper input validation and output encoding")
        
        if any(f.get('type') == 'sql_injection' for f in findings):
            recommendations.append("Use parameterized queries or ORM")
        
        if any(f.get('type') == 'open_redirect' for f in findings):
            recommendations.append("Implement whitelist validation for redirects")
        
        return recommendations
    
    def _generate_findings_html(self) -> str:
        """Generate HTML for findings section"""
        html = ""
        for finding in self.report_data['findings']:
            html += f"""
            <div class="finding severity-{finding.get('severity', 'low')}">
                <h4>{finding.get('title', 'Untitled Finding')}</h4>
                <p><strong>Type:</strong> {finding.get('type', 'Unknown')}</p>
                <p><strong>Severity:</strong> {finding.get('severity', 'low')}</p>
                <p><strong>Description:</strong> {finding.get('description', '')}</p>
                <p><strong>URL:</strong> {finding.get('url', '')}</p>
                <pre><code>{finding.get('payload', '')}</code></pre>
            </div>
            """
        return html
    
    def _generate_summary_html(self) -> str:
        """Generate HTML for summary section"""
        summary = self.report_data['summary']
        return f"""
        <div class="summary">
            <p>Total Findings: {summary['total_findings']}</p>
            <p class="severity-high">High Severity: {summary['high_severity']}</p>
            <p class="severity-medium">Medium Severity: {summary['medium_severity']}</p>
            <p class="severity-low">Low Severity: {summary['low_severity']}</p>
        </div>
        """
    
    def _generate_recommendations_html(self) -> str:
        """Generate HTML for recommendations section"""
        html = "<ul>"
        for rec in self.report_data['recommendations']:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        return html
    
    def _generate_findings_markdown(self) -> str:
        """Generate Markdown for findings section"""
        md = ""
        for finding in self.report_data['findings']:
            md += f"""
### {finding.get('title', 'Untitled Finding')}
- **Type:** {finding.get('type', 'Unknown')}
- **Severity:** {finding.get('severity', 'low')}
- **Description:** {finding.get('description', '')}
- **URL:** {finding.get('url', '')}
- **Payload:** `{finding.get('payload', '')}`

"""
        return md
    
    def _generate_summary_markdown(self) -> str:
        """Generate Markdown for summary section"""
        summary = self.report_data['summary']
        return f"""
- Total Findings: {summary['total_findings']}
- High Severity: {summary['high_severity']}
- Medium Severity: {summary['medium_severity']}
- Low Severity: {summary['low_severity']}
"""
    
    def _generate_recommendations_markdown(self) -> str:
        """Generate Markdown for recommendations section"""
        return "\n".join(f"- {rec}" for rec in self.report_data['recommendations'])
