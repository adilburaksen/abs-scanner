from typing import Dict, Any, List
import requests
import json
import os
from datetime import datetime, timedelta
from .base import BaseModule

class CVEModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.cve_database: Dict[str, Any] = {}
        self.last_update = None
        self.cve_file = "data/cve_database.json"
        self.nvd_api_key = os.getenv("NVD_API_KEY", "")
        
    def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Starting CVE check for {target}")
        
        if self._should_update_database():
            self._update_cve_database()
        
        findings = self._check_vulnerabilities(target, options)
        
        return {
            'cve_findings': findings,
            'last_update': self.last_update.isoformat() if self.last_update else None
        }
    
    def _should_update_database(self) -> bool:
        """Check if CVE database needs updating"""
        if not os.path.exists(self.cve_file):
            return True
            
        if not self.last_update:
            with open(self.cve_file, 'r') as f:
                data = json.load(f)
                self.last_update = datetime.fromisoformat(data.get('last_update', '2000-01-01'))
        
        # Update if database is older than 24 hours
        return datetime.now() - self.last_update > timedelta(hours=24)
    
    def _update_cve_database(self):
        """Update local CVE database from NVD"""
        self.logger.info("Updating CVE database...")
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(self.cve_file), exist_ok=True)
        
        try:
            # Use NVD API if key is available
            if self.nvd_api_key:
                self._update_from_nvd_api()
            else:
                self._update_from_nvd_feeds()
            
            self.last_update = datetime.now()
            
            # Save database
            with open(self.cve_file, 'w') as f:
                json.dump({
                    'last_update': self.last_update.isoformat(),
                    'cves': self.cve_database
                }, f, indent=4)
                
        except Exception as e:
            self.logger.error(f"Error updating CVE database: {str(e)}")
    
    def _update_from_nvd_api(self):
        """Update CVE database using NVD API"""
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {
            'apiKey': self.nvd_api_key
        }
        
        # Get last 30 days of CVEs
        start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000")
        
        params = {
            'lastModStartDate': start_date,
            'resultsPerPage': 2000
        }
        
        try:
            response = requests.get(api_url, headers=headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            for cve in data.get('vulnerabilities', []):
                cve_id = cve['cve']['id']
                self.cve_database[cve_id] = {
                    'description': cve['cve'].get('descriptions', [{}])[0].get('value', ''),
                    'severity': self._get_cvss_severity(cve),
                    'affected_products': self._get_affected_products(cve),
                    'references': self._get_references(cve)
                }
        
        except Exception as e:
            self.logger.error(f"Error fetching from NVD API: {str(e)}")
            raise
    
    def _update_from_nvd_feeds(self):
        """Update CVE database using NVD data feeds"""
        feed_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
        
        try:
            response = requests.get(feed_url)
            response.raise_for_status()
            
            data = response.json()
            for cve_item in data.get('CVE_Items', []):
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                self.cve_database[cve_id] = {
                    'description': cve_item['cve']['description']['description_data'][0]['value'],
                    'severity': self._get_cvss_severity(cve_item),
                    'affected_products': self._get_affected_products(cve_item),
                    'references': self._get_references(cve_item)
                }
        
        except Exception as e:
            self.logger.error(f"Error fetching from NVD feed: {str(e)}")
            raise
    
    def _check_vulnerabilities(self, target: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check target against CVE database"""
        findings = []
        
        # Get target software and versions
        software_info = self._get_software_info(target)
        
        # Check each piece of software against CVE database
        for software in software_info:
            for cve_id, cve_data in self.cve_database.items():
                if self._is_vulnerable(software, cve_data):
                    findings.append({
                        'cve_id': cve_id,
                        'software': software['name'],
                        'version': software['version'],
                        'severity': cve_data['severity'],
                        'description': cve_data['description'],
                        'references': cve_data['references']
                    })
        
        return findings
    
    def _get_software_info(self, target: str) -> List[Dict[str, str]]:
        """Get software and version information from target"""
        software_info = []
        
        try:
            # Get server header
            response = requests.get(f"https://{target}")
            server = response.headers.get('Server', '')
            if server:
                name, version = self._parse_server_string(server)
                software_info.append({
                    'name': name,
                    'version': version
                })
            
            # Get other technology information
            # TODO: Implement technology detection (e.g., using Wappalyzer-like detection)
            
        except Exception as e:
            self.logger.error(f"Error getting software info: {str(e)}")
        
        return software_info
    
    def _parse_server_string(self, server: str) -> tuple:
        """Parse server string into name and version"""
        parts = server.split('/')
        if len(parts) > 1:
            return parts[0], parts[1]
        return server, ""
    
    def _is_vulnerable(self, software: Dict[str, str], cve_data: Dict[str, Any]) -> bool:
        """Check if software is vulnerable to CVE"""
        for product in cve_data['affected_products']:
            if (software['name'].lower() in product['name'].lower() and
                self._version_in_range(software['version'], product.get('version_range', ''))):
                return True
        return False
    
    def _version_in_range(self, version: str, version_range: str) -> bool:
        """Check if version is in vulnerable range"""
        # TODO: Implement version comparison logic
        return True
    
    def _get_cvss_severity(self, cve_data: Dict) -> str:
        """Extract CVSS severity from CVE data"""
        try:
            metrics = cve_data.get('impact', {}).get('baseMetricV3', {})
            return metrics.get('cvssV3', {}).get('baseSeverity', 'UNKNOWN')
        except:
            return 'UNKNOWN'
    
    def _get_affected_products(self, cve_data: Dict) -> List[Dict[str, str]]:
        """Extract affected products from CVE data"""
        products = []
        try:
            for node in cve_data['configurations']['nodes']:
                for cpe in node.get('cpe_match', []):
                    products.append({
                        'name': cpe['cpe23Uri'].split(':')[4],
                        'version_range': cpe.get('versionStartIncluding', '')
                    })
        except:
            pass
        return products
    
    def _get_references(self, cve_data: Dict) -> List[str]:
        """Extract references from CVE data"""
        try:
            return [ref['url'] for ref in cve_data['references']['reference_data']]
        except:
            return []
