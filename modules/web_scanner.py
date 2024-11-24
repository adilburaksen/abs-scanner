import requests
import json
import logging
from typing import Dict, List, Any
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from .base import BaseModule

class WebScannerModule(BaseModule):
    def __init__(self, target_url: str, options: Dict[str, Any] = None):
        self.target_url = target_url
        self.options = options or {}
        self.findings = []
        self.headers = {
            'User-Agent': 'ABS-Scanner/1.0',
            'Accept': '*/*'
        }
        self.session = requests.Session()
        self.timeout = options.get('timeout', 10)

    def scan_security_headers(self, url: str) -> Dict[str, Any]:
        """Analyze security headers of the target."""
        try:
            response = self.session.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            headers = response.headers

            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy')
            }

            missing_headers = [header for header, value in security_headers.items() if not value]
            
            return {
                'security_headers': security_headers,
                'missing_headers': missing_headers,
                'score': 10 - len(missing_headers)
            }
        except Exception as e:
            logging.error(f"Error scanning security headers: {str(e)}")
            return {'error': str(e)}

    def detect_technologies(self, url: str) -> Dict[str, Any]:
        """Detect technologies used by the target website."""
        technologies = {
            'server': None,
            'frameworks': [],
            'cms': None,
            'javascript_libraries': []
        }

        try:
            response = self.session.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            
            # Server detection
            technologies['server'] = response.headers.get('Server')
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Framework detection
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                if tag.get('name') == 'generator':
                    technologies['cms'] = tag.get('content')
            
            # JavaScript library detection
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if 'jquery' in src.lower():
                    technologies['javascript_libraries'].append('jQuery')
                elif 'react' in src.lower():
                    technologies['javascript_libraries'].append('React')
                elif 'vue' in src.lower():
                    technologies['javascript_libraries'].append('Vue.js')
                elif 'angular' in src.lower():
                    technologies['javascript_libraries'].append('Angular')

            return technologies
        except Exception as e:
            logging.error(f"Error detecting technologies: {str(e)}")
            return {'error': str(e)}

    def scan_endpoints(self, url: str) -> Dict[str, Any]:
        """Discover and analyze endpoints."""
        endpoints = {
            'discovered': [],
            'vulnerable': []
        }

        try:
            response = self.session.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            links = soup.find_all(['a', 'form'])
            for link in links:
                if link.name == 'a' and link.get('href'):
                    endpoint = urljoin(url, link['href'])
                    if url in endpoint:
                        endpoints['discovered'].append({
                            'url': endpoint,
                            'method': 'GET',
                            'type': 'link'
                        })
                elif link.name == 'form':
                    action = link.get('action', '')
                    method = link.get('method', 'GET').upper()
                    endpoint = urljoin(url, action)
                    if url in endpoint:
                        endpoints['discovered'].append({
                            'url': endpoint,
                            'method': method,
                            'type': 'form'
                        })

            # Basic security checks
            for endpoint in endpoints['discovered']:
                # Check for open redirects
                if 'redirect' in endpoint['url'].lower() or 'url' in endpoint['url'].lower():
                    endpoints['vulnerable'].append({
                        'url': endpoint['url'],
                        'type': 'potential_open_redirect',
                        'severity': 'medium'
                    })

                # Check for potential IDOR
                id_pattern = r'[?&](id|user_id|account_id)=\d+'
                if re.search(id_pattern, endpoint['url']):
                    endpoints['vulnerable'].append({
                        'url': endpoint['url'],
                        'type': 'potential_idor',
                        'severity': 'high'
                    })

            return endpoints
        except Exception as e:
            logging.error(f"Error scanning endpoints: {str(e)}")
            return {'error': str(e)}

    def check_ssl_security(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Check SSL/TLS configuration."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'version': ssock.version(),
                        'cipher_suite': cipher,
                        'certificate': {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert.get('version'),
                            'serialNumber': cert.get('serialNumber'),
                            'notBefore': cert.get('notBefore'),
                            'notAfter': cert.get('notAfter')
                        }
                    }
        except Exception as e:
            logging.error(f"Error checking SSL security: {str(e)}")
            return {'error': str(e)}

    def run(self) -> Dict[str, Any]:
        """Run all web scanning modules."""
        results = {
            'target_url': self.target_url,
            'security_headers': None,
            'technologies': None,
            'endpoints': None,
            'ssl_security': None
        }

        # Security Headers Analysis
        results['security_headers'] = self.scan_security_headers(self.target_url)

        # Technology Detection
        results['technologies'] = self.detect_technologies(self.target_url)

        # Endpoint Discovery and Analysis
        results['endpoints'] = self.scan_endpoints(self.target_url)

        # SSL/TLS Security Check
        hostname = self.target_url.split('://')[1].split('/')[0]
        results['ssl_security'] = self.check_ssl_security(hostname)

        return results
