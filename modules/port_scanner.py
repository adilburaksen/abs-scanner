import nmap
import socket
import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from .base import BaseModule

class PortScannerModule(BaseModule):
    def __init__(self, target: str, options: Dict[str, Any] = None):
        self.target = target
        self.options = options or {}
        self.nm = nmap.PortScanner()
        self.findings = []
        
        # Default scanning options
        self.port_range = self.options.get('port_range', '1-1000')
        self.scan_type = self.options.get('scan_type', 'syn')  # syn, tcp, udp
        self.threads = self.options.get('threads', 10)
        self.timeout = self.options.get('timeout', 3)
        self.aggressive = self.options.get('aggressive', False)

    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port using basic socket connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                    
                # Try banner grabbing
                banner = self._grab_banner(sock)
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
            return None
        except Exception as e:
            logging.debug(f"Error scanning port {port}: {str(e)}")
            return None
        finally:
            try:
                sock.close()
            except:
                pass

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None

    def quick_scan(self) -> Dict[str, Any]:
        """Perform a quick scan of common ports."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                       993, 995, 1723, 3306, 3389, 5900, 8080]
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port 
                            for port in common_ports}
            
            for future in future_to_port:
                result = future.result()
                if result:
                    results.append(result)
        
        return {
            'target': self.target,
            'scan_type': 'quick',
            'ports': results
        }

    def full_scan(self) -> Dict[str, Any]:
        """Perform a full port scan using nmap."""
        try:
            arguments = f'-p{self.port_range}'
            
            if self.scan_type == 'syn':
                arguments += ' -sS'
            elif self.scan_type == 'udp':
                arguments += ' -sU'
            
            if self.aggressive:
                arguments += ' -A'  # Enable OS detection, version detection, script scanning, and traceroute
            
            self.nm.scan(self.target, arguments=arguments)
            
            results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        results.append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', '')
                        })
            
            return {
                'target': self.target,
                'scan_type': 'full',
                'os_matches': self.nm[self.target].get('osmatch', []) if self.aggressive else [],
                'ports': results
            }
        except Exception as e:
            logging.error(f"Error in full scan: {str(e)}")
            return {
                'target': self.target,
                'scan_type': 'full',
                'error': str(e)
            }

    def service_scan(self, ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform detailed service scan on open ports."""
        try:
            port_list = ','.join([str(p['port']) for p in ports])
            arguments = f'-p{port_list} -sV'
            
            self.nm.scan(self.target, arguments=arguments)
            
            results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        port_info = self.nm[host][proto][port]
                        results.append({
                            'port': port,
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', '')
                        })
            
            return {
                'target': self.target,
                'scan_type': 'service',
                'services': results
            }
        except Exception as e:
            logging.error(f"Error in service scan: {str(e)}")
            return {
                'target': self.target,
                'scan_type': 'service',
                'error': str(e)
            }

    def analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results and identify potential vulnerabilities."""
        analysis = {
            'high_risk_ports': [],
            'medium_risk_ports': [],
            'info_ports': [],
            'recommendations': []
        }
        
        high_risk_ports = {21: 'FTP', 23: 'Telnet', 445: 'SMB', 3389: 'RDP'}
        medium_risk_ports = {22: 'SSH', 25: 'SMTP', 53: 'DNS', 3306: 'MySQL'}
        
        for port_info in results.get('ports', []):
            port = port_info['port']
            
            # Check for high-risk ports
            if port in high_risk_ports:
                analysis['high_risk_ports'].append({
                    'port': port,
                    'service': high_risk_ports[port],
                    'recommendation': f'Consider restricting access to {high_risk_ports[port]} service'
                })
                analysis['recommendations'].append(
                    f'Port {port} ({high_risk_ports[port]}) is considered high risk. '
                    'Ensure it is properly secured or disabled if not needed.'
                )
            
            # Check for medium-risk ports
            elif port in medium_risk_ports:
                analysis['medium_risk_ports'].append({
                    'port': port,
                    'service': medium_risk_ports[port],
                    'recommendation': f'Review security configuration of {medium_risk_ports[port]} service'
                })
            
            # Add information about other open ports
            else:
                analysis['info_ports'].append({
                    'port': port,
                    'service': port_info.get('service', 'unknown')
                })
        
        return analysis

    def run(self) -> Dict[str, Any]:
        """Run the port scanner with configured options."""
        results = {
            'target': self.target,
            'quick_scan': None,
            'full_scan': None,
            'service_scan': None,
            'analysis': None
        }
        
        # Start with quick scan
        quick_results = self.quick_scan()
        results['quick_scan'] = quick_results
        
        # If open ports found, do service scan
        open_ports = quick_results.get('ports', [])
        if open_ports:
            results['service_scan'] = self.service_scan(open_ports)
        
        # If aggressive scanning is enabled, do full scan
        if self.aggressive:
            results['full_scan'] = self.full_scan()
            
        # Analyze results
        results['analysis'] = self.analyze_results(results['full_scan'] or results['quick_scan'])
        
        return results
