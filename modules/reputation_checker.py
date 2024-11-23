import dns.resolver
import ipaddress
import socket
from typing import Dict, List, Optional, Union
import logging

class ReputationChecker:
    def __init__(self):
        self.dnsbl_servers = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
            'cbl.abuseat.org',
            'b.barracudacentral.org',
            'dnsbl-1.uceprotect.net',
            'spam.dnsbl.sorbs.net',
        ]

    def check_reputation(self, target: str) -> Dict:
        """Check reputation of a target using DNSBL"""
        try:
            ip = self._resolve_ip(target)
            dnsbl_results = self.check_dnsbl(ip)
            
            return {
                'target': target,
                'ip': ip,
                'dnsbl': dnsbl_results,
                'risk_score': self._calculate_risk_score(dnsbl_results)
            }
            
        except Exception as e:
            logging.error(f"Error checking reputation for {target}: {e}")
            return {
                'target': target,
                'error': str(e)
            }

    def check_dnsbl(self, ip: str) -> Dict:
        """Check IP against multiple DNSBL servers"""
        results = {
            'listed_count': 0,
            'total_checked': len(self.dnsbl_servers),
            'listings': []
        }
        
        try:
            # Reverse the IP address for DNSBL lookups
            reversed_ip = '.'.join(reversed(ip.split('.')))
            
            for dnsbl in self.dnsbl_servers:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    answers = dns.resolver.resolve(query, 'A')
                    
                    if answers:
                        results['listed_count'] += 1
                        results['listings'].append({
                            'dnsbl': dnsbl,
                            'type': 'blacklisted'
                        })
                except dns.resolver.NXDOMAIN:
                    # Not listed
                    continue
                except Exception as e:
                    logging.debug(f"DNSBL lookup failed for {dnsbl}: {e}")
                    continue
                    
        except Exception as e:
            logging.error(f"DNSBL check failed: {e}")
            
        return results

    def _resolve_ip(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            # Check if target is already an IP
            ipaddress.ip_address(target)
            return target
        except ValueError:
            # Resolve hostname to IP
            return socket.gethostbyname(target)

    def _calculate_risk_score(self, dnsbl_results: Dict) -> float:
        """Calculate risk score based on DNSBL results"""
        if dnsbl_results.get('error'):
            return 0.0
            
        listed_count = dnsbl_results.get('listed_count', 0)
        total_checked = dnsbl_results.get('total_checked', 1)
        
        # Calculate percentage of blacklists that listed the IP
        return min(listed_count / total_checked, 1.0)
