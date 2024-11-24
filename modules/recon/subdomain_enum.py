import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils.logger import get_logger

logger = get_logger(__name__)

class SubdomainEnumerator:
    def __init__(self, target_domain, wordlist_path=None, max_threads=10):
        self.target_domain = target_domain
        self.wordlist_path = wordlist_path or "wordlists/subdomains.txt"
        self.max_threads = max_threads
        self.results = set()
        
    def load_wordlist(self):
        """Load subdomain wordlist"""
        try:
            with open(self.wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error loading wordlist: {str(e)}")
            return []

    def check_subdomain(self, subdomain):
        """Check if a subdomain exists"""
        full_domain = f"{subdomain}.{self.target_domain}"
        try:
            # DNS resolution check
            dns.resolver.resolve(full_domain, 'A')
            
            # HTTP/HTTPS check
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{full_domain}"
                    response = requests.get(url, timeout=5, verify=False)
                    if response.status_code < 500:
                        self.results.add({
                            'subdomain': full_domain,
                            'ip': dns.resolver.resolve(full_domain, 'A')[0].to_text(),
                            'status_code': response.status_code,
                            'protocol': protocol,
                            'title': self._get_page_title(response.text)
                        })
                        return
                except requests.RequestException:
                    continue
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            logger.debug(f"Error checking {full_domain}: {str(e)}")

    def _get_page_title(self, html_content):
        """Extract page title from HTML content"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.title.string.strip() if soup.title else ''
        except:
            return ''

    def enumerate(self):
        """Start subdomain enumeration"""
        logger.info(f"Starting subdomain enumeration for {self.target_domain}")
        
        wordlist = self.load_wordlist()
        if not wordlist:
            logger.error("No wordlist loaded, aborting enumeration")
            return []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, subdomain): subdomain 
                for subdomain in wordlist
            }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error processing {subdomain}: {str(e)}")

        logger.info(f"Enumeration complete. Found {len(self.results)} subdomains")
        return list(self.results)
