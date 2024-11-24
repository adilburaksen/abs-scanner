import aiohttp
import asyncio
import logging
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, parse_qs, urlparse
from bs4 import BeautifulSoup
from .base import BaseModule

class VulnerabilityScanner(BaseModule):
    def __init__(self, target_url: str, options: Dict[str, Any] = None):
        self.target_url = target_url.rstrip('/')
        self.options = options or {}
        self.findings = []
        self.session = None
        
        # Default options
        self.threads = self.options.get('threads', 20)
        self.timeout = self.options.get('timeout', 10)
        self.user_agent = self.options.get('user_agent', 'ABS-Scanner/1.0')
        self.max_depth = self.options.get('max_depth', 3)
        self.rate_limit = self.options.get('rate_limit', 50)
        
        # Rate limiting
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        
        # Load vulnerability patterns
        self.patterns = self._load_patterns()
        
        # Track scanned URLs
        self.scanned_urls = set()

    def _load_patterns(self) -> Dict[str, Any]:
        """Load vulnerability patterns and payloads."""
        return {
            'xss': {
                'patterns': [
                    '<script>alert(1)</script>',
                    '"><script>alert(1)</script>',
                    '"><img src=x onerror=alert(1)>',
                    '\'><img src=x onerror=alert(1)>',
                ],
                'indicators': [
                    '<script>alert(1)</script>',
                    'onerror=alert(1)',
                ]
            },
            'sqli': {
                'patterns': [
                    '\'',
                    '"',
                    ' OR \'1\'=\'1',
                    ' OR 1=1--',
                    '\' OR \'x\'=\'x',
                ],
                'indicators': [
                    'SQL syntax',
                    'mysql_fetch',
                    'ORA-',
                    'PostgreSQL',
                    'SQLite3::'
                ]
            },
            'lfi': {
                'patterns': [
                    '../../../etc/passwd',
                    '..%2f..%2f..%2fetc%2fpasswd',
                    '/etc/passwd%00',
                    'c:\\windows\\win.ini',
                ],
                'indicators': [
                    'root:x:',
                    '[extension]',
                    'for 16-bit app support'
                ]
            },
            'rce': {
                'patterns': [
                    '|id',
                    ';id;',
                    '`id`',
                    '$(id)',
                    '& ping -c 1 127.0.0.1 &'
                ],
                'indicators': [
                    'uid=',
                    'gid=',
                    'groups=',
                    'TTL='
                ]
            },
            'ssrf': {
                'patterns': [
                    'http://127.0.0.1',
                    'http://localhost',
                    'http://169.254.169.254',
                    'http://[::1]'
                ],
                'indicators': [
                    'AWS_',
                    'AZURE_',
                    'internal server',
                    'private network'
                ]
            }
        }

    async def _create_session(self):
        """Create aiohttp session with custom options."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        )

    async def _close_session(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()

    async def _test_vulnerability(self, url: str, param: str, pattern: str, vuln_type: str) -> Optional[Dict[str, Any]]:
        """Test a specific vulnerability pattern on a parameter."""
        async with self._rate_limiter:
            try:
                # Prepare test URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [pattern]
                
                # Make request
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                async with self.session.get(test_url, params=params, allow_redirects=False) as response:
                    content = await response.text()
                    
                    # Check for vulnerability indicators
                    for indicator in self.patterns[vuln_type]['indicators']:
                        if indicator.lower() in content.lower():
                            return {
                                'type': vuln_type,
                                'url': url,
                                'parameter': param,
                                'payload': pattern,
                                'evidence': indicator,
                                'severity': self._get_severity(vuln_type),
                                'response_code': response.status
                            }
                    
                    # Special checks for specific vulnerability types
                    if vuln_type == 'xss' and pattern in content:
                        return {
                            'type': 'xss',
                            'url': url,
                            'parameter': param,
                            'payload': pattern,
                            'evidence': 'Reflected payload found in response',
                            'severity': 'high',
                            'response_code': response.status
                        }
                    
                    return None
            except Exception as e:
                logging.debug(f"Error testing {vuln_type} on {url}: {str(e)}")
                return None

    def _get_severity(self, vuln_type: str) -> str:
        """Determine vulnerability severity."""
        severity_map = {
            'rce': 'critical',
            'sqli': 'high',
            'xss': 'high',
            'lfi': 'high',
            'ssrf': 'high',
            'open_redirect': 'medium',
            'information_disclosure': 'medium'
        }
        return severity_map.get(vuln_type, 'low')

    async def _extract_parameters(self, url: str, content: str) -> List[str]:
        """Extract parameters from URL and content."""
        params = set()
        
        # URL parameters
        parsed = urlparse(url)
        params.update(parse_qs(parsed.query).keys())
        
        # Form parameters
        soup = BeautifulSoup(content, 'html.parser')
        for form in soup.find_all('form'):
            for input_field in form.find_all(['input', 'textarea']):
                name = input_field.get('name')
                if name:
                    params.add(name)
        
        return list(params)

    async def _scan_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Scan a single endpoint for vulnerabilities."""
        if url in self.scanned_urls:
            return []
        
        self.scanned_urls.add(url)
        findings = []
        
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                parameters = await self._extract_parameters(url, content)
                
                # Test each parameter for each vulnerability type
                for param in parameters:
                    for vuln_type, config in self.patterns.items():
                        for pattern in config['patterns']:
                            result = await self._test_vulnerability(url, param, pattern, vuln_type)
                            if result:
                                findings.append(result)
                                # Break on first finding for this param/vuln_type combination
                                break
                
                # Extract and scan new URLs
                if len(self.scanned_urls) < self.max_depth:
                    soup = BeautifulSoup(content, 'html.parser')
                    for link in soup.find_all(['a', 'form']):
                        href = link.get('href') or link.get('action')
                        if href:
                            new_url = urljoin(url, href)
                            if new_url.startswith(self.target_url) and new_url not in self.scanned_urls:
                                sub_findings = await self._scan_endpoint(new_url)
                                findings.extend(sub_findings)
        
        except Exception as e:
            logging.error(f"Error scanning endpoint {url}: {str(e)}")
        
        return findings

    def _analyze_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability findings and generate report."""
        analysis = {
            'total_vulnerabilities': len(findings),
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'vulnerability_types': {},
            'affected_endpoints': set(),
            'recommendations': []
        }
        
        for finding in findings:
            # Update severity counts
            severity = finding['severity']
            analysis['severity_counts'][severity] = analysis['severity_counts'].get(severity, 0) + 1
            
            # Update vulnerability type counts
            vuln_type = finding['type']
            analysis['vulnerability_types'][vuln_type] = analysis['vulnerability_types'].get(vuln_type, 0) + 1
            
            # Track affected endpoints
            analysis['affected_endpoints'].add(finding['url'])
        
        # Generate recommendations
        if analysis['severity_counts']['critical'] > 0:
            analysis['recommendations'].append(
                "Critical vulnerabilities found! Immediate attention required. "
                "Consider taking affected components offline until fixed."
            )
        
        for vuln_type, count in analysis['vulnerability_types'].items():
            if count > 0:
                analysis['recommendations'].append(
                    f"Found {count} {vuln_type} vulnerabilities. "
                    f"Implement proper input validation and output encoding for {vuln_type}."
                )
        
        # Convert affected_endpoints to list for JSON serialization
        analysis['affected_endpoints'] = list(analysis['affected_endpoints'])
        
        return analysis

    async def run(self) -> Dict[str, Any]:
        """Run the vulnerability scanner."""
        try:
            await self._create_session()
            
            # Start scanning from the target URL
            findings = await self._scan_endpoint(self.target_url)
            
            # Analyze findings
            analysis = self._analyze_findings(findings)
            
            return {
                'target_url': self.target_url,
                'findings': findings,
                'analysis': analysis,
                'scanned_urls': list(self.scanned_urls)
            }
        finally:
            await self._close_session()

    @staticmethod
    def run_sync(target_url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Synchronous wrapper for running the scanner."""
        scanner = VulnerabilityScanner(target_url, options)
        return asyncio.run(scanner.run())
