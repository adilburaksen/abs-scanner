import socket
import struct
import asyncio
import json
import logging
from typing import Dict, List, Tuple, Optional
import nmap
from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
import joblib
import aiohttp
import config
import numpy as np
import re
import time

class ServiceDetector:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.ml_model = self._load_ml_model()
        self.fingerprints = self._load_fingerprints()
        self.session = None
        self.version_classifier = self._load_version_classifier()
        self._initialize_async_session()

    def _load_ml_model(self) -> RandomForestClassifier:
        """Load the pre-trained machine learning model"""
        try:
            return joblib.load(config.ML_MODEL_PATH)
        except Exception as e:
            logging.warning(f"Could not load ML model: {e}")
            return None

    def _load_fingerprints(self) -> Dict:
        """Load service fingerprint database"""
        try:
            with open(config.FINGERPRINT_DB, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Could not load fingerprints: {e}")
            return {}

    async def _initialize_async_session(self):
        """Initialize aiohttp session for async requests"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(limit=50)
            )

    def _load_version_classifier(self) -> RandomForestClassifier:
        """Load the version detection classifier"""
        try:
            return joblib.load(config.VERSION_MODEL_PATH)
        except FileNotFoundError:
            logging.warning("Version classifier model not found")
            return None
        except Exception as e:
            logging.error(f"Error loading version classifier: {str(e)}")
            return None

    async def detect_service(self, target: str, port: int, protocol: str = 'tcp') -> Dict:
        """Detect service using multiple methods with enhanced error handling"""
        result = {
            'port': port,
            'protocol': protocol,
            'service': None,
            'version': None,
            'banner': None,
            'confidence': 0,
            'cpe': None,
            'error': None
        }

        try:
            # Initialize async session if needed
            await self._initialize_async_session()

            # Try multiple detection methods in parallel
            detection_tasks = [
                self._detect_with_nmap(target, port),
                self._detect_with_banner(target, port),
                self._detect_with_ml(target, port),
                self._detect_with_fingerprints(target, port)
            ]

            detection_results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            
            # Process results with error handling
            valid_results = [r for r in detection_results if isinstance(r, dict) and not r.get('error')]
            
            if valid_results:
                # Combine results with confidence weighting
                result = self._combine_detection_results(valid_results)
                
                # Attempt version detection if service was identified
                if result['service'] and self.version_classifier:
                    version_info = await self._detect_version(target, port, result['service'])
                    result.update(version_info)
            else:
                result['error'] = "No valid detection results"
                
        except Exception as e:
            result['error'] = f"Service detection error: {str(e)}"
            logging.error(f"Error in service detection for {target}:{port} - {str(e)}")
        
        return result

    async def _detect_with_nmap(self, target: str, port: int) -> Optional[Dict]:
        """Service detection using Nmap"""
        try:
            args = f'-sV -p{port} -Pn --version-intensity 5'
            self.nmap_scanner.scan(target, arguments=args)
            
            if target in self.nmap_scanner.all_hosts():
                service_info = self.nmap_scanner[target]['tcp'][port]
                return {
                    'service': service_info['name'],
                    'version': service_info['version'],
                    'confidence': float(service_info['conf']),
                    'cpe': service_info.get('cpe', None)
                }
        except Exception as e:
            logging.debug(f"Nmap detection failed: {e}")
        return None

    async def _detect_with_ml(self, target: str, port: int, protocol: str = 'tcp') -> Optional[Dict]:
        """Service detection using machine learning"""
        if not self.ml_model:
            return None

        try:
            # Extract features from the service
            features = await self._extract_service_features(target, port, protocol)
            
            # Make prediction
            prediction = self.ml_model.predict_proba([features])[0]
            best_match_idx = np.argmax(prediction)
            confidence = prediction[best_match_idx] * 100

            return {
                'service': self.ml_model.classes_[best_match_idx],
                'confidence': confidence
            }
        except Exception as e:
            logging.debug(f"ML detection failed: {e}")
        return None

    async def _detect_with_banner(self, target: str, port: int, protocol: str = 'tcp') -> Optional[Dict]:
        """Service detection using banner grabbing"""
        if protocol != 'tcp':
            return None

        try:
            reader, writer = await asyncio.open_connection(target, port)
            writer.write(b'\r\n')
            await writer.drain()
            
            banner = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            if banner:
                # Match banner against fingerprint database
                for service, patterns in self.fingerprints.items():
                    for pattern in patterns:
                        if pattern.encode() in banner:
                            return {
                                'service': service,
                                'banner': banner.decode(errors='ignore'),
                                'confidence': 85
                            }
        except Exception as e:
            logging.debug(f"Banner grabbing failed: {e}")
        return None

    async def _detect_with_fingerprints(self, target: str, port: int, protocol: str = 'tcp') -> Optional[Dict]:
        """Service detection using custom probes"""
        probes = {
            80: b'GET / HTTP/1.0\r\n\r\n',
            21: b'USER anonymous\r\n',
            23: b'\r\n',
            25: b'HELO test\r\n',
            110: b'USER test\r\n',
            143: b'A001 CAPABILITY\r\n'
        }

        if port not in probes:
            return None

        try:
            reader, writer = await asyncio.open_connection(target, port)
            writer.write(probes[port])
            await writer.drain()
            
            response = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            if response:
                # Analyze response for service identification
                return self._analyze_probe_response(response, port)
        except Exception as e:
            logging.debug(f"Probe detection failed: {e}")
        return None

    async def _extract_service_features(self, target: str, port: int, protocol: str) -> List[float]:
        """Extract features for machine learning model"""
        features = []
        try:
            # Connection timing
            start_time = time.time()
            reader, writer = await asyncio.open_connection(target, port)
            connect_time = time.time() - start_time

            # Send probe and measure response time
            writer.write(b'\r\n')
            await writer.drain()
            response = await reader.read(1024)
            response_time = time.time() - start_time

            writer.close()
            await writer.wait_closed()

            # Feature extraction
            features = [
                connect_time,
                response_time,
                len(response) if response else 0,
                port,
                1 if protocol == 'tcp' else 0
            ]
        except Exception:
            features = [0, 0, 0, port, 1 if protocol == 'tcp' else 0]

        return features

    def _combine_detection_results(self, results: List[Dict]) -> Dict:
        """Combine detection results with confidence weighting"""
        combined_result = {
            'service': None,
            'version': None,
            'banner': None,
            'confidence': 0,
            'cpe': None
        }

        for result in results:
            if result['confidence'] > combined_result['confidence']:
                combined_result = result

        return combined_result

    async def _detect_version(self, target: str, port: int, service: str) -> Dict:
        """Detect service version using ML and fingerprint matching"""
        version_info = {
            'version': None,
            'version_confidence': 0
        }
        
        try:
            # Get service banner and characteristics
            banner = await self._get_banner(target, port)
            if not banner:
                return version_info
                
            # Extract features for ML prediction
            features = self._extract_version_features(banner, service)
            
            # Make version prediction
            if self.version_classifier and features:
                version_pred = self.version_classifier.predict_proba([features])[0]
                best_version_idx = version_pred.argmax()
                version_info['version'] = self.version_classifier.classes_[best_version_idx]
                version_info['version_confidence'] = float(version_pred[best_version_idx])
                
        except Exception as e:
            logging.error(f"Version detection error: {str(e)}")
            
        return version_info

    async def _get_banner(self, target: str, port: int) -> Optional[bytes]:
        """Get service banner"""
        try:
            reader, writer = await asyncio.open_connection(target, port)
            writer.write(b'\r\n')
            await writer.drain()
            
            banner = await reader.read(1024)
            writer.close()
            await writer.wait_closed()

            return banner
        except Exception as e:
            logging.debug(f"Banner grabbing failed: {e}")
        return None

    def _extract_version_features(self, banner: bytes, service: str) -> List[float]:
        """Extract features for version detection"""
        features = []
        try:
            # Feature extraction
            features = [
                len(banner),
                service,
                banner.decode(errors='ignore')
            ]
        except Exception:
            features = [0, service, '']

        return features

    def _analyze_probe_response(self, response: bytes, port: int) -> Optional[Dict]:
        """Analyze probe response for service identification"""
        response_str = response.decode(errors='ignore')
        
        # Common response patterns
        patterns = {
            'HTTP': (r'HTTP/\d\.\d', 'http'),
            'FTP': (r'^220.*FTP', 'ftp'),
            'SMTP': (r'^220.*SMTP', 'smtp'),
            'POP3': (r'^\+OK', 'pop3'),
            'IMAP': (r'^\* OK.*IMAP', 'imap')
        }

        for name, (pattern, service) in patterns.items():
            if re.search(pattern, response_str):
                version = self._extract_version(response_str, service)
                return {
                    'service': service,
                    'version': version,
                    'banner': response_str[:100],
                    'confidence': 90
                }
        return None

    def _extract_version(self, response: str, service: str) -> Optional[str]:
        """Extract version information from service response"""
        version_patterns = {
            'http': r'Server: ([^\r\n]+)',
            'ftp': r'220.*?(\d+\.\d+\.\d+)',
            'smtp': r'220.*?(\d+\.\d+\.\d+)',
            'ssh': r'SSH-\d\.\d-([^\r\n]+)',
        }

        if service in version_patterns:
            match = re.search(version_patterns[service], response)
            if match:
                return match.group(1)
        return None
