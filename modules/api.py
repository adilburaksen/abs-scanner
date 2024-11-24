from typing import Dict, Any, List
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from .base import BaseModule

class APIModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.endpoints: Dict[str, Any] = {}
        self.vulnerabilities: List[Dict[str, Any]] = []
        
    def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Starting API scanning on {target}")
        
        if options.get('discover_endpoints', True):
            self.discover_endpoints(target)
        
        if options.get('test_auth', True):
            self.test_auth(target)
            
        return {
            'endpoints': self.endpoints,
            'vulnerabilities': self.vulnerabilities
        }
    
    def discover_endpoints(self, target: str):
        """Discover API endpoints"""
        self._scan_swagger(target)
        self._scan_graphql(target)
        self._scan_common_endpoints(target)
    
    def test_auth(self, target: str):
        """Test API authentication"""
        self._test_missing_auth()
        self._test_jwt_vulnerabilities()
        self._test_api_keys()
    
    def _scan_swagger(self, target: str):
        """Scan for Swagger/OpenAPI documentation"""
        swagger_paths = [
            '/swagger/v1/swagger.json',
            '/api-docs',
            '/swagger.json',
            '/openapi.json'
        ]
        
        for path in swagger_paths:
            try:
                resp = requests.get(f"https://{target}{path}", timeout=5)
                if resp.status_code == 200:
                    try:
                        swagger_doc = resp.json()
                        self.endpoints['swagger'] = {
                            'url': resp.url,
                            'version': swagger_doc.get('swagger') or swagger_doc.get('openapi'),
                            'endpoints': self._parse_swagger(swagger_doc)
                        }
                    except json.JSONDecodeError:
                        continue
            except:
                continue
    
    def _scan_graphql(self, target: str):
        """Scan for GraphQL endpoints"""
        graphql_paths = [
            '/graphql',
            '/api/graphql',
            '/graphiql'
        ]
        
        introspection_query = '''
        query {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        '''
        
        for path in graphql_paths:
            try:
                resp = requests.post(
                    f"https://{target}{path}",
                    json={'query': introspection_query},
                    timeout=5
                )
                
                if resp.status_code == 200:
                    self.endpoints['graphql'] = {
                        'url': resp.url,
                        'introspection_enabled': True,
                        'schema': resp.json()
                    }
            except:
                continue
    
    def _scan_common_endpoints(self, target: str):
        """Scan for common API endpoints"""
        common_paths = [
            '/api/v1',
            '/api/v2',
            '/rest/v1',
            '/rest/v2'
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self._check_endpoint, target, path)
                      for path in common_paths]
            
            for future in futures:
                if result := future.result():
                    self.endpoints[result['path']] = result
    
    def _test_missing_auth(self):
        """Test for endpoints missing authentication"""
        # TODO: Implement missing auth tests
        pass
    
    def _test_jwt_vulnerabilities(self):
        """Test for JWT-related vulnerabilities"""
        # TODO: Implement JWT vulnerability tests
        pass
    
    def _test_api_keys(self):
        """Test for API key vulnerabilities"""
        # TODO: Implement API key tests
        pass
    
    def _parse_swagger(self, swagger_doc: Dict) -> List[Dict[str, Any]]:
        """Parse Swagger documentation for endpoints"""
        endpoints = []
        
        if 'paths' in swagger_doc:
            for path, methods in swagger_doc['paths'].items():
                for method, details in methods.items():
                    endpoints.append({
                        'path': path,
                        'method': method.upper(),
                        'description': details.get('description', ''),
                        'parameters': details.get('parameters', []),
                        'responses': details.get('responses', {})
                    })
        
        return endpoints
    
    def _check_endpoint(self, target: str, path: str) -> Dict[str, Any]:
        try:
            url = f"https://{target}{path}"
            resp = requests.get(url, timeout=5)
            return {
                'path': path,
                'status': resp.status_code,
                'length': len(resp.content),
                'headers': dict(resp.headers)
            }
        except:
            return {}
