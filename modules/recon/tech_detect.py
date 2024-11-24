import requests
import json
import re
from bs4 import BeautifulSoup
from modules.utils.logger import get_logger

logger = get_logger(__name__)

class TechnologyDetector:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = {}

    def detect_web_server(self, headers):
        """Detect web server from headers"""
        server = headers.get('Server', '')
        if server:
            self.results['web_server'] = server
        else:
            self.results['web_server'] = 'Unknown'

    def detect_cms(self, response):
        """Detect Content Management System"""
        content = response.text.lower()
        
        cms_patterns = {
            'wordpress': [
                r'wp-content',
                r'wp-includes',
                r'wordpress'
            ],
            'drupal': [
                r'drupal.js',
                r'drupal.min.js',
                r'/sites/default/'
            ],
            'joomla': [
                r'joomla!',
                r'/components/com_',
                r'/media/jui/'
            ]
        }

        detected_cms = []
        for cms, patterns in cms_patterns.items():
            if any(re.search(pattern, content) for pattern in patterns):
                detected_cms.append(cms)

        self.results['cms'] = detected_cms if detected_cms else ['Unknown']

    def detect_javascript_frameworks(self, soup):
        """Detect JavaScript frameworks and libraries"""
        frameworks = []
        
        # Check script tags
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            
            # Common frameworks
            if 'react' in src:
                frameworks.append('React')
            elif 'vue' in src:
                frameworks.append('Vue.js')
            elif 'angular' in src:
                frameworks.append('Angular')
            elif 'jquery' in src:
                frameworks.append('jQuery')
            elif 'bootstrap' in src:
                frameworks.append('Bootstrap')

        # Check meta tags for frameworks
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('name') == 'generator':
                content = tag.get('content', '').lower()
                if 'next.js' in content:
                    frameworks.append('Next.js')
                elif 'nuxt' in content:
                    frameworks.append('Nuxt.js')

        self.results['javascript_frameworks'] = list(set(frameworks))

    def detect_security_headers(self, headers):
        """Analyze security headers"""
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS',
            'Content-Security-Policy': 'Missing CSP',
            'X-Frame-Options': 'Missing X-Frame-Options',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-XSS-Protection': 'Missing X-XSS-Protection',
            'Referrer-Policy': 'Missing Referrer-Policy'
        }

        for header, message in security_headers.items():
            if header in headers:
                security_headers[header] = headers[header]

        self.results['security_headers'] = security_headers

    def detect_technologies(self, url):
        """Detect technologies used by the target website"""
        logger.info(f"Starting technology detection for {url}")
        
        try:
            response = requests.get(url, headers=self.headers, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Detect various technologies
            self.detect_web_server(response.headers)
            self.detect_cms(response)
            self.detect_javascript_frameworks(soup)
            self.detect_security_headers(response.headers)

            # Additional information
            self.results['status_code'] = response.status_code
            self.results['response_time'] = response.elapsed.total_seconds()
            self.results['cookies'] = [
                {'name': cookie.name, 'secure': cookie.secure, 'httponly': cookie.has_nonstandard_attr('httponly')}
                for cookie in response.cookies
            ]

            logger.info("Technology detection complete")
            return self.results

        except Exception as e:
            logger.error(f"Error during technology detection: {str(e)}")
            return {'error': str(e)}
