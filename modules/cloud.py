from typing import Dict, Any, List
import requests
import boto3
import azure.mgmt.compute
import google.cloud.compute_v1
from .base import BaseModule

class CloudModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.findings: List[Dict[str, Any]] = []
        
    def run(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info(f"Starting cloud security scan for {target}")
        
        if options.get('scan_aws', True):
            self._scan_aws(target)
        
        if options.get('scan_azure', True):
            self._scan_azure(target)
        
        if options.get('scan_gcp', True):
            self._scan_gcp(target)
            
        return {
            'findings': self.findings
        }
    
    def _scan_aws(self, target: str):
        """Scan AWS resources"""
        try:
            # Check for common AWS endpoints
            endpoints = [
                's3.amazonaws.com',
                'dynamodb.amazonaws.com',
                'lambda.amazonaws.com',
                'ec2.amazonaws.com'
            ]
            
            for endpoint in endpoints:
                try:
                    response = requests.head(f"https://{target}.{endpoint}", timeout=5)
                    if response.status_code != 404:
                        self.findings.append({
                            'type': 'aws_endpoint',
                            'service': endpoint,
                            'url': f"https://{target}.{endpoint}",
                            'status_code': response.status_code
                        })
                except:
                    continue
            
            # Check for S3 bucket misconfiguration
            self._check_s3_buckets(target)
            
        except Exception as e:
            self.logger.error(f"Error scanning AWS resources: {str(e)}")
    
    def _scan_azure(self, target: str):
        """Scan Azure resources"""
        try:
            # Check for common Azure endpoints
            endpoints = [
                'blob.core.windows.net',
                'database.windows.net',
                'azurewebsites.net',
                'scm.azurewebsites.net'
            ]
            
            for endpoint in endpoints:
                try:
                    response = requests.head(f"https://{target}.{endpoint}", timeout=5)
                    if response.status_code != 404:
                        self.findings.append({
                            'type': 'azure_endpoint',
                            'service': endpoint,
                            'url': f"https://{target}.{endpoint}",
                            'status_code': response.status_code
                        })
                except:
                    continue
            
            # Check for Azure Storage misconfiguration
            self._check_azure_storage(target)
            
        except Exception as e:
            self.logger.error(f"Error scanning Azure resources: {str(e)}")
    
    def _scan_gcp(self, target: str):
        """Scan Google Cloud resources"""
        try:
            # Check for common GCP endpoints
            endpoints = [
                'appspot.com',
                'cloudfunctions.net',
                'run.app',
                'storage.googleapis.com'
            ]
            
            for endpoint in endpoints:
                try:
                    response = requests.head(f"https://{target}.{endpoint}", timeout=5)
                    if response.status_code != 404:
                        self.findings.append({
                            'type': 'gcp_endpoint',
                            'service': endpoint,
                            'url': f"https://{target}.{endpoint}",
                            'status_code': response.status_code
                        })
                except:
                    continue
            
            # Check for GCS bucket misconfiguration
            self._check_gcs_buckets(target)
            
        except Exception as e:
            self.logger.error(f"Error scanning GCP resources: {str(e)}")
    
    def _check_s3_buckets(self, target: str):
        """Check for misconfigured S3 buckets"""
        bucket_names = [
            target,
            f"{target}-prod",
            f"{target}-stage",
            f"{target}-dev",
            f"{target}-backup",
            f"{target}-data"
        ]
        
        for bucket_name in bucket_names:
            try:
                response = requests.get(f"https://{bucket_name}.s3.amazonaws.com", timeout=5)
                
                if response.status_code != 404:
                    self.findings.append({
                        'type': 'aws_s3_bucket',
                        'bucket': bucket_name,
                        'url': f"https://{bucket_name}.s3.amazonaws.com",
                        'status_code': response.status_code,
                        'public': response.status_code == 200
                    })
            except:
                continue
    
    def _check_azure_storage(self, target: str):
        """Check for misconfigured Azure Storage accounts"""
        account_names = [
            target,
            f"{target}prod",
            f"{target}stage",
            f"{target}dev",
            f"{target}backup",
            f"{target}data"
        ]
        
        for account_name in account_names:
            try:
                response = requests.get(
                    f"https://{account_name}.blob.core.windows.net",
                    timeout=5
                )
                
                if response.status_code != 404:
                    self.findings.append({
                        'type': 'azure_storage',
                        'account': account_name,
                        'url': f"https://{account_name}.blob.core.windows.net",
                        'status_code': response.status_code,
                        'public': response.status_code == 200
                    })
            except:
                continue
    
    def _check_gcs_buckets(self, target: str):
        """Check for misconfigured Google Cloud Storage buckets"""
        bucket_names = [
            target,
            f"{target}-prod",
            f"{target}-stage",
            f"{target}-dev",
            f"{target}-backup",
            f"{target}-data"
        ]
        
        for bucket_name in bucket_names:
            try:
                response = requests.get(
                    f"https://storage.googleapis.com/{bucket_name}",
                    timeout=5
                )
                
                if response.status_code != 404:
                    self.findings.append({
                        'type': 'gcp_storage',
                        'bucket': bucket_name,
                        'url': f"https://storage.googleapis.com/{bucket_name}",
                        'status_code': response.status_code,
                        'public': response.status_code == 200
                    })
            except:
                continue
