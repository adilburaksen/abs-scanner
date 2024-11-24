from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging

class BaseModule(ABC):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.results: Dict[str, Any] = {}
    
    @abstractmethod
    def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run the module's main functionality"""
        pass

    def validate_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        # TODO: Implement scope validation
        return True

class ScopeManager:
    def __init__(self):
        self.in_scope: List[str] = []
        self.out_of_scope: List[str] = []
        self.rules: Dict[str, Any] = {}
    
    def add_scope(self, target: str):
        self.in_scope.append(target)
    
    def is_in_scope(self, target: str) -> bool:
        return any(scope in target for scope in self.in_scope)

class Config:
    def __init__(self):
        self.settings: Dict[str, Any] = {
            'threads': 10,
            'timeout': 30,
            'user_agent': 'BugBountyScanner/1.0',
            'proxy': None,
            'rate_limit': 100,  # requests per minute
            'stealth_mode': False
        }
    
    def update(self, new_settings: Dict[str, Any]):
        self.settings.update(new_settings)
    
    def get(self, key: str) -> Any:
        return self.settings.get(key)
