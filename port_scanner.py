#!/usr/bin/env python3

import logging
import asyncio
import socket
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from scapy.all import IP, TCP, sr1, ICMP
import time
import json

@dataclass
class ScanResult:
    port: int
    is_open: bool
    service: Optional[str] = None
    version: Optional[str] = None
    latency: Optional[float] = None

class PortScanner:
    """Advanced Port Scanner with service detection"""
    
    def __init__(self, max_workers: int = 100, timeout: int = 1):  
        self.logger = logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.timeout = timeout
        self.chunk_size = 25  # Her worker için maksimum port sayısı
        self._initialize_service_signatures()
        
    def _initialize_service_signatures(self):
        """Initialize known service signatures"""
        self.service_signatures = {
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB'
        }
        
    async def scan_target(self, target: str, port_range: Tuple[int, int] = (1, 1024)) -> List[ScanResult]:
        """Scan target for open ports and detect services"""
        try:
            # First check if host is alive
            if not self._is_host_alive(target):
                self.logger.warning(f"Host {target} appears to be down")
                return []
                
            start_port, end_port = port_range
            ports = list(range(start_port, end_port + 1))
            
            # Portları chunk'lara böl
            chunks = [ports[i:i + self.chunk_size] for i in range(0, len(ports), self.chunk_size)]
            
            all_results = []
            for chunk in chunks:
                results = await self.scan_chunk(target, chunk)
                all_results.extend(results)
            
            # Sadece açık portları döndür ve port numarasına göre sırala
            open_ports = [result for result in all_results if result.is_open]
            return sorted(open_ports, key=lambda x: x.port)
            
        except Exception as e:
            self.logger.error(f"Error scanning target {target}: {e}")
            return []
            
    def _is_host_alive(self, target: str) -> bool:
        """Check if host is alive using ICMP ping"""
        try:
            # Send ICMP echo request with shorter timeout
            ping = IP(dst=target)/ICMP()
            reply = sr1(ping, timeout=1, verbose=0)  
            return bool(reply and reply.haslayer(ICMP))
        except Exception:
            return False
            
    async def scan_chunk(self, target: str, ports: List[int]) -> List[ScanResult]:
        tasks = [self.scan_port(target, port) for port in ports]
        return await asyncio.gather(*tasks)

    async def scan_port(self, target: str, port: int) -> ScanResult:
        try:
            start_time = time.time()
            # TCP SYN taraması için Scapy kullan
            syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
            
            # Timeout süresini düşür ve hızlı yanıt al
            response = await asyncio.wait_for(
                self._send_packet(syn_packet),
                timeout=self.timeout
            )
            
            latency = (time.time() - start_time) * 1000  # ms cinsinden
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                
                # SYN-ACK yanıtı geldi mi kontrol et (port açık)
                if tcp_layer.flags & 0x12:  # 0x12 = SYN-ACK
                    # RST paketi gönder
                    rst = IP(dst=target)/TCP(dport=port, flags="R")
                    await self._send_packet(rst)
                    
                    # Servis tespiti yap
                    service, version = await self._detect_service(target, port)
                    return ScanResult(port=port, is_open=True, service=service, version=version, latency=latency)
            
            return ScanResult(port=port, is_open=False, latency=latency)
            
        except asyncio.TimeoutError:
            return ScanResult(port=port, is_open=False, latency=None)
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            return ScanResult(port=port, is_open=False, latency=None)

    async def _send_packet(self, packet):
        # Scapy'nin sr1 fonksiyonunu asenkron olarak çalıştır
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: sr1(packet, timeout=self.timeout, verbose=0))

    async def _detect_service(self, target: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        """Detect service and version running on port"""
        try:
            # First check known services
            service = self.service_signatures.get(port)
            if service:
                return service, None
            
            # Try to grab banner with shorter timeout
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  
                s.connect((target, port))
                
                # Send protocol-specific probes
                if port == 22:  # SSH
                    s.send(b"SSH-2.0-OpenSSH_8.0\r\n")
                elif port == 80:  # HTTP
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                elif port == 21:  # FTP
                    s.send(b"USER anonymous\r\n")
                
                banner = s.recv(1024)
                if banner:
                    # Try to extract version information
                    version = self._parse_version_from_banner(banner)
                    if version:
                        return service, version
                        
        except Exception as e:
            print(f"Error detecting service on port {port}: {e}")
            return None, None
            
    def _parse_version_from_banner(self, banner: bytes) -> Optional[str]:
        """Parse version information from service banner"""
        try:
            # Convert banner to string and clean it
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            # Look for common version patterns
            version = None
            
            # SSH pattern: SSH-2.0-OpenSSH_8.2p1
            if b'SSH-2.0-' in banner:
                version = banner_str.split('SSH-2.0-')[1]
            
            # HTTP pattern: Server: nginx/1.18.0
            elif b'Server:' in banner:
                for line in banner_str.split('\n'):
                    if 'Server:' in line:
                        version = line.split('Server:')[1].strip()
                        break
            
            # FTP pattern: 220 (vsFTPd 3.0.3)
            elif b'220' in banner and b'FTP' in banner:
                version = banner_str.split('220')[1].strip()
            
            return version
            
        except Exception:
            return None
            
    def to_json(self, results: List[ScanResult]) -> str:
        """Convert scan results to JSON format"""
        return json.dumps([{
            'port': r.port,
            'is_open': r.is_open,
            'service': r.service,
            'version': r.version,
            'latency': r.latency
        } for r in results], indent=2)

async def main():
    scanner = PortScanner()
    target = "example.com"
    results = await scanner.scan_target(target)
    print(scanner.to_json(results))

if __name__ == "__main__":
    asyncio.run(main())
