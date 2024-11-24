import aiohttp
import asyncio
import logging
from typing import Dict, List, Any, Set
from urllib.parse import urljoin
import re
from .base import BaseModule

class DirectoryEnumModule(BaseModule):
    def __init__(self, target_url: str, options: Dict[str, Any] = None):
        self.target_url = target_url.rstrip('/')
        self.options = options or {}
        self.findings = []
        self.session = None
        
        # Default options
        self.wordlist = self.options.get('wordlist', 'common.txt')
        self.extensions = self.options.get('extensions', ['.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.txt'])
        self.exclude_codes = self.options.get('exclude_codes', [404, 400, 500, 501, 502, 503])
        self.threads = self.options.get('threads', 30)
        self.recursive = self.options.get('recursive', True)
        self.max_depth = self.options.get('max_depth', 2)
        self.timeout = self.options.get('timeout', 10)
        
        # Rate limiting
        self.rate_limit = self.options.get('rate_limit', 50)  # requests per second
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        
        # Results tracking
        self.discovered_paths: Set[str] = set()
        self.interesting_files: List[Dict[str, Any]] = []
        self.potential_vulns: List[Dict[str, Any]] = []

    async def _load_wordlist(self) -> List[str]:
        """Load wordlist from file."""
        wordlist_path = f"wordlists/{self.wordlist}"
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error(f"Error loading wordlist: {str(e)}")
            return []

    async def _create_session(self):
        """Create aiohttp session with custom options."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)

    async def _close_session(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()

    async def _check_path(self, path: str, depth: int = 0) -> Dict[str, Any]:
        """Check if a path exists on the target server."""
        async with self._rate_limiter:
            url = urljoin(self.target_url, path)
            if url in self.discovered_paths:
                return None
            
            try:
                async with self.session.get(url, allow_redirects=True) as response:
                    status = response.status
                    if status not in self.exclude_codes:
                        content_type = response.headers.get('Content-Type', '')
                        content_length = response.headers.get('Content-Length', '0')
                        
                        result = {
                            'url': url,
                            'status': status,
                            'content_type': content_type,
                            'content_length': content_length,
                            'depth': depth
                        }
                        
                        # Check for potential sensitive files
                        if any(pattern in path.lower() for pattern in [
                            'admin', 'backup', 'config', 'db', 'debug', 'test',
                            'dev', 'api', '.git', '.env', 'wp-config'
                        ]):
                            result['sensitive'] = True
                            self.interesting_files.append(result)
                        
                        # Check for potential vulnerabilities
                        await self._check_vulnerabilities(url, path, result)
                        
                        self.discovered_paths.add(url)
                        return result
                    return None
            except Exception as e:
                logging.debug(f"Error checking path {url}: {str(e)}")
                return None

    async def _check_vulnerabilities(self, url: str, path: str, result: Dict[str, Any]):
        """Check for common vulnerabilities in discovered paths."""
        # Check for potential file inclusion
        if re.search(r'[?&](file|page|include|doc)=', url):
            self.potential_vulns.append({
                'url': url,
                'type': 'potential_lfi',
                'severity': 'high',
                'description': 'Potential Local File Inclusion vulnerability'
            })
        
        # Check for potential SQL injection
        if re.search(r'[?&]\w+=(.*?)[\'"\(\)]', url):
            self.potential_vulns.append({
                'url': url,
                'type': 'potential_sqli',
                'severity': 'high',
                'description': 'Potential SQL Injection vulnerability'
            })
        
        # Check for exposed sensitive files
        sensitive_files = [
            '.git/HEAD', '.env', 'wp-config.php', 'config.php',
            'database.yml', 'settings.py', 'web.config'
        ]
        if any(sf in path for sf in sensitive_files):
            self.potential_vulns.append({
                'url': url,
                'type': 'sensitive_file',
                'severity': 'medium',
                'description': f'Potentially sensitive file exposed: {path}'
            })

    async def _enumerate_directory(self, base_path: str = '', depth: int = 0) -> List[Dict[str, Any]]:
        """Enumerate directories and files recursively."""
        if depth > self.max_depth:
            return []
        
        wordlist = await self._load_wordlist()
        tasks = []
        results = []
        
        # Generate paths with extensions
        paths = []
        for word in wordlist:
            # Add directory
            paths.append(f"{base_path}/{word}/")
            # Add files with extensions
            for ext in self.extensions:
                paths.append(f"{base_path}/{word}{ext}")
        
        # Create tasks for checking paths
        async with asyncio.TaskGroup() as tg:
            for path in paths:
                task = tg.create_task(self._check_path(path, depth))
                tasks.append(task)
        
        # Collect results
        for task in tasks:
            result = await task
            if result:
                results.append(result)
                # If recursive scanning is enabled and it's a directory
                if self.recursive and result['url'].endswith('/'):
                    sub_results = await self._enumerate_directory(
                        result['url'].replace(self.target_url, ''),
                        depth + 1
                    )
                    results.extend(sub_results)
        
        return results

    def analyze_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze enumeration results."""
        analysis = {
            'total_discovered': len(self.discovered_paths),
            'interesting_files': self.interesting_files,
            'potential_vulnerabilities': self.potential_vulns,
            'directory_structure': {},
            'file_types': {},
            'response_codes': {},
            'recommendations': []
        }
        
        # Analyze directory structure and file types
        for result in results:
            # Update directory structure
            path_parts = result['url'].replace(self.target_url, '').split('/')
            current_dict = analysis['directory_structure']
            for part in path_parts:
                if part:
                    if part not in current_dict:
                        current_dict[part] = {}
                    current_dict = current_dict[part]
            
            # Update file type statistics
            if '.' in result['url']:
                ext = result['url'].split('.')[-1]
                analysis['file_types'][ext] = analysis['file_types'].get(ext, 0) + 1
            
            # Update response code statistics
            status = result['status']
            analysis['response_codes'][status] = analysis['response_codes'].get(status, 0) + 1
        
        # Generate recommendations
        if self.interesting_files:
            analysis['recommendations'].append(
                "Several potentially sensitive files were discovered. "
                "Review access controls and consider restricting access."
            )
        
        if self.potential_vulns:
            analysis['recommendations'].append(
                "Potential vulnerabilities were identified. "
                "Conduct thorough security testing on the identified endpoints."
            )
        
        return analysis

    async def run(self) -> Dict[str, Any]:
        """Run the directory enumeration module."""
        try:
            await self._create_session()
            
            results = await self._enumerate_directory()
            analysis = self.analyze_results(results)
            
            return {
                'target_url': self.target_url,
                'discovered_paths': list(self.discovered_paths),
                'interesting_files': self.interesting_files,
                'potential_vulnerabilities': self.potential_vulns,
                'analysis': analysis
            }
        finally:
            await self._close_session()

    @staticmethod
    def run_sync(target_url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Synchronous wrapper for running the module."""
        scanner = DirectoryEnumModule(target_url, options)
        return asyncio.run(scanner.run())
