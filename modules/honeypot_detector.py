#!/usr/bin/env python3

import logging
from typing import Dict, List, Optional
import time
import socket
import random
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, UDP, Raw, sr1

@dataclass
class HoneypotScore:
    score: float
    reasons: List[str]
    confidence: float

class HoneypotDetector:
    """Advanced Honeypot Detection System"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=10)
        self._initialize_detection_patterns()
        
    def _initialize_detection_patterns(self):
        """Initialize known honeypot patterns and behaviors"""
        self.suspicious_patterns = {
            'response_patterns': [
                b'HoneyPot',
                b'honeyd',
                b'kippo',
                b'cowrie'
            ],
            'suspicious_services': {
                22: ['OpenSSH 6.7p1'],  # Common honeypot SSH versions
                23: ['Welcome to HoneyPot'],
                2222: ['SSH-2.0-OpenSSH']  # Non-standard SSH ports
            }
        }
        
    def analyze_target(self, target: str, open_ports: List[int]) -> HoneypotScore:
        """Analyze a target for honeypot characteristics"""
        score = 0.0
        reasons = []
        
        # Check for suspicious ports
        suspicious_ports = 0
        for port in open_ports:
            if port in self.suspicious_patterns['suspicious_services']:
                suspicious_ports += 1
                reasons.append(f"Suspicious service on port {port}")
        
        if suspicious_ports > 0:
            score += min(suspicious_ports / len(open_ports), 0.5)
        
        # Check for response consistency and protocol behavior
        for port in open_ports:
            try:
                # TCP SYN scan for service detection
                syn_packet = IP(dst=target)/TCP(dport=port, flags='S')
                response = sr1(syn_packet, timeout=2, verbose=0)
                
                if response and response.haslayer(TCP):
                    # Check TCP flags
                    tcp_flags = response.getlayer(TCP).flags
                    if tcp_flags & 0x12:  # SYN-ACK
                        # Try to grab banner
                        banner = self._grab_banner(target, port)
                        if banner:
                            # Check for suspicious patterns
                            for pattern in self.suspicious_patterns['response_patterns']:
                                if pattern in banner:
                                    score += 0.3
                                    reasons.append(f"Suspicious pattern in banner on port {port}")
                            
                            # Check response consistency
                            if self._check_response_consistency(target, port, banner):
                                score += 0.2
                                reasons.append(f"Suspicious response consistency on port {port}")
                            
                            # Check protocol behavior
                            if self._check_protocol_behavior(target, port):
                                score += 0.2
                                reasons.append(f"Suspicious protocol behavior on port {port}")
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing port {port}: {e}")
        
        # Calculate confidence based on number of checks performed
        confidence = min((len(reasons) + 1) / 5, 1.0)
        
        return HoneypotScore(
            score=min(score, 1.0),
            reasons=reasons,
            confidence=confidence
        )
    
    def _grab_banner(self, target: str, port: int) -> Optional[bytes]:
        """Attempt to grab service banner"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((target, port))
                # Send common protocol-specific probes
                if port == 22:  # SSH
                    s.send(b"SSH-2.0-OpenSSH_8.0\r\n")
                elif port == 80:  # HTTP
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                elif port == 21:  # FTP
                    s.send(b"USER anonymous\r\n")
                return s.recv(1024)
        except Exception:
            return None
            
    def _check_response_consistency(self, target: str, port: int, initial_banner: bytes) -> bool:
        """Check if responses are suspiciously consistent"""
        try:
            # Make multiple requests
            responses = []
            for _ in range(3):
                banner = self._grab_banner(target, port)
                if banner:
                    responses.append(banner)
                time.sleep(random.uniform(0.1, 0.3))
            
            # Check if all responses are identical
            return all(response == initial_banner for response in responses)
            
        except Exception:
            return False
            
    def _check_protocol_behavior(self, target: str, port: int) -> bool:
        """Check for suspicious protocol behavior"""
        try:
            # Send invalid protocol data
            syn_packet = IP(dst=target)/TCP(dport=port, flags='S')
            response = sr1(syn_packet, timeout=1, verbose=0)
            
            if response and response.haslayer(TCP):
                # Send malformed packet
                malformed = IP(dst=target)/TCP(dport=port, flags='FSRPAU')
                mal_response = sr1(malformed, timeout=1, verbose=0)
                
                # Check if responses are suspiciously accommodating
                if mal_response and mal_response.haslayer(TCP):
                    return True
            
            return False
            
        except Exception:
            return False
