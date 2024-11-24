from typing import Dict, Any, List
import dns.resolver
import requests
import json
import os
import logging
from .base import BaseModule

class SubdomainEnumModule(BaseModule):
    def __init__(self, target_domain, api_keys=None):
        self.target_domain = target_domain
        self.api_keys = api_keys or {}
        self.subdomains = set()
        self.dns_resolver = dns.resolver.Resolver()
        self.wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists', 'subdomains.txt')
        self.dns_records_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists', 'dns_records.txt')

    def passive_enumeration(self):
        """Perform passive subdomain enumeration using various sources."""
        sources = [
            self._enumerate_crtsh,
            self._enumerate_virustotal,
            self._enumerate_alienvault,
            self._enumerate_securitytrails,
            self._enumerate_threatcrowd
        ]
        
        for source in sources:
            try:
                source()
            except Exception as e:
                logging.error(f"Error in {source.__name__}: {str(e)}")

    def active_enumeration(self):
        """Perform active subdomain enumeration using DNS queries."""
        if not os.path.exists(self.wordlist_path):
            logging.error(f"Wordlist not found at {self.wordlist_path}")
            return

        with open(self.wordlist_path, 'r') as f:
            wordlist = [line.strip() for line in f.readlines()]

        for subdomain in wordlist:
            full_domain = f"{subdomain}.{self.target_domain}"
            try:
                answers = self.dns_resolver.resolve(full_domain, 'A')
                if answers:
                    self.subdomains.add(full_domain)
                    logging.info(f"Found subdomain: {full_domain}")
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                logging.debug(f"Error resolving {full_domain}: {str(e)}")

    def permutation_scanning(self):
        """Perform permutation scanning for subdomain variations."""
        base_subdomains = list(self.subdomains)
        permutations = []
        
        # Common prefixes and suffixes
        affixes = ['dev', 'stage', 'prod', 'test', 'uat', 'qa', 'admin', 'api', 'app']
        
        for subdomain in base_subdomains:
            subdomain_parts = subdomain.split('.')
            base = subdomain_parts[0]
            
            # Add prefix permutations
            for affix in affixes:
                permutations.append(f"{affix}-{base}.{self.target_domain}")
                permutations.append(f"{affix}.{base}.{self.target_domain}")
                
            # Add suffix permutations
            for affix in affixes:
                permutations.append(f"{base}-{affix}.{self.target_domain}")
                
        for permutation in permutations:
            try:
                answers = self.dns_resolver.resolve(permutation, 'A')
                if answers:
                    self.subdomains.add(permutation)
                    logging.info(f"Found permutation: {permutation}")
            except Exception:
                continue

    def zone_transfer(self):
        """Attempt zone transfer for the domain."""
        try:
            ns_records = self.dns_resolver.resolve(self.target_domain, 'NS')
            for ns in ns_records:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(str(ns), self.target_domain))
                    if z:
                        for name, node in z.nodes.items():
                            name = str(name)
                            if name != '@':
                                full_domain = f"{name}.{self.target_domain}"
                                self.subdomains.add(full_domain)
                                logging.info(f"Found subdomain via zone transfer: {full_domain}")
                except Exception as e:
                    logging.debug(f"Zone transfer failed for {ns}: {str(e)}")
        except Exception as e:
            logging.error(f"Error getting NS records: {str(e)}")

    def cert_transparency(self):
        """Check certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        domains = name_value.split('\n')
                        for domain in domains:
                            domain = domain.strip()
                            if domain.endswith(self.target_domain):
                                self.subdomains.add(domain)
                                logging.info(f"Found subdomain via CT logs: {domain}")
        except Exception as e:
            logging.error(f"Error checking CT logs: {str(e)}")

    def dns_records_enum(self):
        """Enumerate various DNS record types for discovered subdomains."""
        if not os.path.exists(self.dns_records_path):
            logging.error(f"DNS records list not found at {self.dns_records_path}")
            return

        with open(self.dns_records_path, 'r') as f:
            record_types = [line.strip() for line in f.readlines()]

        results = {}
        for subdomain in self.subdomains:
            results[subdomain] = {}
            for record_type in record_types:
                try:
                    answers = self.dns_resolver.resolve(subdomain, record_type)
                    results[subdomain][record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    continue

        return results

    def _enumerate_crtsh(self):
        """Enumerate subdomains using crt.sh."""
        url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        domains = name_value.split('\n')
                        for domain in domains:
                            domain = domain.strip()
                            if domain.endswith(self.target_domain):
                                self.subdomains.add(domain)
        except Exception as e:
            logging.error(f"Error enumerating crt.sh: {str(e)}")

    def _enumerate_virustotal(self):
        """Enumerate subdomains using VirusTotal API."""
        if 'VIRUSTOTAL_API_KEY' not in self.api_keys:
            logging.warning("VirusTotal API key not provided")
            return

        headers = {
            'x-apikey': self.api_keys['VIRUSTOTAL_API_KEY']
        }
        url = f"https://www.virustotal.com/api/v3/domains/{self.target_domain}/subdomains"
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain:
                        self.subdomains.add(subdomain)
        except Exception as e:
            logging.error(f"Error enumerating VirusTotal: {str(e)}")

    def _enumerate_alienvault(self):
        """Enumerate subdomains using AlienVault OTX."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target_domain}/passive_dns"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(self.target_domain):
                        self.subdomains.add(hostname)
        except Exception as e:
            logging.error(f"Error enumerating AlienVault: {str(e)}")

    def _enumerate_securitytrails(self):
        """Enumerate subdomains using SecurityTrails API."""
        if 'SECURITYTRAILS_API_KEY' not in self.api_keys:
            logging.warning("SecurityTrails API key not provided")
            return

        headers = {
            'APIKEY': self.api_keys['SECURITYTRAILS_API_KEY']
        }
        url = f"https://api.securitytrails.com/v1/domain/{self.target_domain}/subdomains"
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                for subdomain in data.get('subdomains', []):
                    full_domain = f"{subdomain}.{self.target_domain}"
                    self.subdomains.add(full_domain)
        except Exception as e:
            logging.error(f"Error enumerating SecurityTrails: {str(e)}")

    def _enumerate_threatcrowd(self):
        """Enumerate subdomains using ThreatCrowd."""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target_domain}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for subdomain in data.get('subdomains', []):
                    if subdomain.endswith(self.target_domain):
                        self.subdomains.add(subdomain)
        except Exception as e:
            logging.error(f"Error enumerating ThreatCrowd: {str(e)}")

    def run(self):
        """Run all enumeration methods."""
        logging.info(f"Starting subdomain enumeration for {self.target_domain}")
        
        # Passive enumeration
        logging.info("Starting passive enumeration...")
        self.passive_enumeration()
        
        # Active enumeration
        logging.info("Starting active enumeration...")
        self.active_enumeration()
        
        # Permutation scanning
        logging.info("Starting permutation scanning...")
        self.permutation_scanning()
        
        # Zone transfer
        logging.info("Attempting zone transfer...")
        self.zone_transfer()
        
        # Certificate transparency
        logging.info("Checking certificate transparency logs...")
        self.cert_transparency()
        
        # DNS records enumeration
        logging.info("Enumerating DNS records...")
        dns_records = self.dns_records_enum()
        
        return {
            'subdomains': list(self.subdomains),
            'dns_records': dns_records
        }
