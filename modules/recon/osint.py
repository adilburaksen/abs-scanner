import whois
import requests
import json
from datetime import datetime
from modules.utils.logger import get_logger

logger = get_logger(__name__)

class OSINTGatherer:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.results = {}

    def gather_whois(self):
        """Gather WHOIS information"""
        try:
            w = whois.whois(self.target_domain)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date.strftime('%Y-%m-%d') if isinstance(w.creation_date, datetime) else str(w.creation_date),
                'expiration_date': w.expiration_date.strftime('%Y-%m-%d') if isinstance(w.expiration_date, datetime) else str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org
            }
        except Exception as e:
            logger.error(f"Error gathering WHOIS info: {str(e)}")
            self.results['whois'] = {}

    def check_cloud_exposure(self):
        """Check for cloud storage exposure"""
        cloud_services = {
            'aws': [
                f'http://{self.target_domain}.s3.amazonaws.com',
                f'https://{self.target_domain}.s3.amazonaws.com'
            ],
            'azure': [
                f'https://{self.target_domain}.blob.core.windows.net',
                f'https://{self.target_domain}.file.core.windows.net'
            ],
            'gcp': [
                f'https://storage.googleapis.com/{self.target_domain}',
                f'https://{self.target_domain}.storage.googleapis.com'
            ]
        }

        exposed_services = []
        for provider, urls in cloud_services.items():
            for url in urls:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code in [200, 403]:  # 403 might indicate existence
                        exposed_services.append({
                            'provider': provider,
                            'url': url,
                            'status_code': response.status_code
                        })
                except:
                    continue

        self.results['cloud_exposure'] = exposed_services

    def check_email_exposure(self):
        """Check for email exposure using HaveIBeenPwned API"""
        # Note: This requires an API key from HaveIBeenPwned
        # Implement if API key is available
        pass

    def check_github_exposure(self):
        """Check for sensitive information exposure on GitHub"""
        try:
            # GitHub search for domain
            query = f'"{self.target_domain}" in:file'
            headers = {'Accept': 'application/vnd.github.v3+json'}
            response = requests.get(
                f'https://api.github.com/search/code?q={query}',
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                self.results['github_exposure'] = {
                    'total_count': data['total_count'],
                    'items': [{
                        'repository': item['repository']['full_name'],
                        'path': item['path'],
                        'url': item['html_url']
                    } for item in data['items'][:10]]  # Limit to 10 results
                }
            else:
                self.results['github_exposure'] = {'total_count': 0, 'items': []}
                
        except Exception as e:
            logger.error(f"Error checking GitHub exposure: {str(e)}")
            self.results['github_exposure'] = {'total_count': 0, 'items': []}

    def gather_all(self):
        """Gather all OSINT information"""
        logger.info(f"Starting OSINT gathering for {self.target_domain}")
        
        self.gather_whois()
        self.check_cloud_exposure()
        self.check_github_exposure()
        # self.check_email_exposure()  # Requires API key
        
        logger.info("OSINT gathering complete")
        return self.results
