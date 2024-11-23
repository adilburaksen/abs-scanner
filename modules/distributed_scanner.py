import redis
import json
import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime
import config
from .service_detection import ServiceDetector
from .vulnerability_scanner import VulnerabilityScanner
import uuid
import time

class DistributedScanner:
    def __init__(self, redis_host='localhost', redis_port=6379):
        self.redis = redis.Redis(host=redis_host, port=redis_port)
        self.task_queue = 'scan_tasks'
        self.result_queue = 'scan_results'
        self.metrics_key = 'scanner_metrics'
        self.network_stats = {}
        self.adaptive_config = {
            'min_delay': 0.1,
            'max_delay': 2.0,
            'initial_delay': 0.5,
            'backoff_factor': 1.5,
            'success_threshold': 0.8
        }

    async def monitor_queues(self) -> Dict:
        """Monitor Redis queues and return metrics"""
        try:
            task_length = self.redis.llen(self.task_queue)
            result_length = self.redis.llen(self.result_queue)
            processing_time = float(self.redis.get('avg_processing_time') or 0)
            success_rate = float(self.redis.get('success_rate') or 0)

            metrics = {
                'queue_status': {
                    'tasks_pending': task_length,
                    'results_pending': result_length,
                    'processing_time': processing_time,
                    'success_rate': success_rate
                },
                'worker_status': self._get_worker_status(),
                'network_metrics': self._get_network_metrics()
            }

            # Update metrics in Redis for historical tracking
            self.redis.hset(self.metrics_key, mapping={
                'timestamp': time.time(),
                'metrics': json.dumps(metrics)
            })

            return metrics
        except Exception as e:
            logging.error(f"Queue monitoring error: {e}")
            return {}

    def _get_worker_status(self) -> Dict:
        """Get status of all worker nodes"""
        workers = {}
        for key in self.redis.scan_iter("worker:*"):
            worker_data = self.redis.hgetall(key)
            worker_id = key.decode().split(':')[1]
            workers[worker_id] = {
                'status': worker_data.get(b'status', b'unknown').decode(),
                'last_heartbeat': float(worker_data.get(b'heartbeat', 0)),
                'tasks_processed': int(worker_data.get(b'tasks_processed', 0)),
                'success_rate': float(worker_data.get(b'success_rate', 0))
            }
        return workers

    def _get_network_metrics(self) -> Dict:
        """Get network performance metrics"""
        return {
            'avg_latency': self.redis.get('avg_latency') or 0,
            'bandwidth_usage': self.redis.get('bandwidth_usage') or 0,
            'connection_errors': self.redis.get('connection_errors') or 0
        }

    async def distribute_scan(self, targets: List[str], ports: List[int]) -> None:
        """Distribute scanning tasks with adaptive scheduling"""
        try:
            chunks = self._create_adaptive_chunks(targets, ports)
            
            for chunk in chunks:
                # Calculate optimal delay based on network conditions
                delay = self._calculate_adaptive_delay(chunk['target'])
                
                task = {
                    'id': str(uuid.uuid4()),
                    'target': chunk['target'],
                    'ports': chunk['ports'],
                    'scan_delay': delay,
                    'retry_policy': self._get_retry_policy(chunk['target']),
                    'timestamp': time.time()
                }
                
                await self._enqueue_task(task)
                
        except Exception as e:
            logging.error(f"Task distribution error: {e}")

    def _create_adaptive_chunks(self, targets: List[str], ports: List[int]) -> List[Dict]:
        """Create chunks based on network conditions and target characteristics"""
        chunks = []
        for target in targets:
            target_stats = self.network_stats.get(target, {})
            
            # Adjust chunk size based on target's response characteristics
            base_chunk_size = self._calculate_chunk_size(target_stats)
            
            # Split ports into appropriate chunks
            for i in range(0, len(ports), base_chunk_size):
                chunk_ports = ports[i:i + base_chunk_size]
                chunks.append({
                    'target': target,
                    'ports': chunk_ports
                })
                
        return chunks

    def _calculate_chunk_size(self, target_stats: Dict) -> int:
        """Calculate optimal chunk size based on target statistics"""
        base_size = 100  # Default chunk size
        
        if not target_stats:
            return base_size
            
        # Adjust based on response time
        avg_response_time = target_stats.get('avg_response_time', 0.5)
        if avg_response_time > 1.0:
            base_size = max(20, base_size // 2)
        elif avg_response_time < 0.1:
            base_size = min(500, base_size * 2)
            
        # Adjust based on error rate
        error_rate = target_stats.get('error_rate', 0)
        if error_rate > 0.2:  # More than 20% errors
            base_size = max(20, base_size // 2)
            
        return base_size

    def _calculate_adaptive_delay(self, target: str) -> float:
        """Calculate adaptive delay based on target's network conditions"""
        stats = self.network_stats.get(target, {})
        
        if not stats:
            return self.adaptive_config['initial_delay']
            
        # Start with base delay
        delay = self.adaptive_config['initial_delay']
        
        # Adjust based on error rate
        error_rate = stats.get('error_rate', 0)
        if error_rate > 0.2:
            delay *= self.adaptive_config['backoff_factor']
            
        # Adjust based on response time
        avg_response_time = stats.get('avg_response_time', 0.5)
        if avg_response_time > 1.0:
            delay *= self.adaptive_config['backoff_factor']
            
        # Keep within bounds
        return min(max(delay, self.adaptive_config['min_delay']), 
                  self.adaptive_config['max_delay'])

    def _get_retry_policy(self, target: str) -> Dict:
        """Get retry policy based on target characteristics"""
        stats = self.network_stats.get(target, {})
        
        base_policy = {
            'max_retries': 3,
            'backoff_factor': 1.5,
            'max_delay': 10
        }
        
        if stats.get('error_rate', 0) > 0.3:
            base_policy['max_retries'] = 5
            base_policy['backoff_factor'] = 2.0
            
        return base_policy

    async def update_network_stats(self, target: str, scan_result: Dict) -> None:
        """Update network statistics for a target"""
        if target not in self.network_stats:
            self.network_stats[target] = {
                'avg_response_time': 0,
                'error_rate': 0,
                'success_count': 0,
                'error_count': 0
            }
            
        stats = self.network_stats[target]
        
        # Update response time
        if scan_result.get('response_time'):
            stats['avg_response_time'] = (stats['avg_response_time'] * stats['success_count'] + 
                                        scan_result['response_time']) / (stats['success_count'] + 1)
            
        # Update error statistics
        if scan_result.get('error'):
            stats['error_count'] += 1
        else:
            stats['success_count'] += 1
            
        total_attempts = stats['success_count'] + stats['error_count']
        stats['error_rate'] = stats['error_count'] / total_attempts if total_attempts > 0 else 0

    async def _enqueue_task(self, task: Dict) -> None:
        """Enqueue a task in Redis"""
        self.redis.lpush(self.task_queue, json.dumps(task))

    async def collect_results(self, scan_id: str, timeout: int = 3600) -> Dict:
        """Collect and aggregate results from workers"""
        start_time = datetime.utcnow()
        results = []
        
        while True:
            # Check if scan is complete
            completed_chunks = int(self.redis.hget(f'scan:{scan_id}', 'completed_chunks') or 0)
            total_chunks = int(self.redis.hget(f'scan:{scan_id}', 'total_chunks') or 0)
            
            if completed_chunks >= total_chunks:
                break
                
            # Check for timeout
            if (datetime.utcnow() - start_time).seconds > timeout:
                self.redis.hset(f'scan:{scan_id}', 'status', 'timeout')
                break
                
            # Get any new results
            result = self.redis.brpop(f'results:{scan_id}', timeout=1)
            if result:
                results.append(json.loads(result[1]))
            
            await asyncio.sleep(1)
        
        return self._aggregate_results(results)

    async def start_worker(self):
        """Start a worker to process scanning tasks"""
        logging.info("Starting distributed scanner worker")
        
        while True:
            try:
                # Get task from queue
                task_data = self.redis.brpop(self.task_queue, timeout=1)
                if not task_data:
                    await asyncio.sleep(1)
                    continue
                
                task = json.loads(task_data[1])
                scan_id = task['id']
                
                # Process the task
                results = await self._process_task(task)
                
                # Store results
                self.redis.lpush(f'results:{scan_id}', json.dumps(results))
                
                # Update progress
                self.redis.hincrby(f'scan:{scan_id}', 'completed_chunks', 1)
                
            except Exception as e:
                logging.error(f"Worker error: {e}")
                await asyncio.sleep(1)

    async def _process_task(self, task: Dict) -> Dict:
        """Process a single scanning task"""
        results = {
            'scan_id': task['id'],
            'targets': {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        async with VulnerabilityScanner() as vuln_scanner:
            for target in [task['target']]:
                try:
                    # Perform service detection
                    services = await self.service_detector.detect_services(
                        target,
                        task['ports'],
                        {}
                    )
                    
                    # Scan for vulnerabilities
                    target_results = {
                        'services': services,
                        'vulnerabilities': {}
                    }
                    
                    for port, service_info in services.items():
                        if service_info.get('service') and service_info.get('version'):
                            vulns = await vuln_scanner.scan_service(
                                service_info['service'],
                                service_info['version'],
                                service_info.get('cpe')
                            )
                            target_results['vulnerabilities'][port] = vulns
                    
                    results['targets'][target] = target_results
                    
                except Exception as e:
                    logging.error(f"Error processing target {target}: {e}")
                    results['targets'][target] = {'error': str(e)}
        
        return results

    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        return f"scan_{timestamp}_{self.redis.incr('scan_counter')}"

    def _chunk_targets(self, targets: List[str], chunk_size: int) -> List[List[str]]:
        """Split targets into chunks for distribution"""
        return [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]

    def _aggregate_results(self, results: List[Dict]) -> Dict:
        """Aggregate results from multiple workers"""
        aggregated = {
            'targets': {},
            'summary': {
                'total_targets': 0,
                'total_services': 0,
                'total_vulnerabilities': 0,
                'high_severity_vulns': 0,
                'medium_severity_vulns': 0,
                'low_severity_vulns': 0
            }
        }
        
        for result in results:
            for target, target_data in result['targets'].items():
                aggregated['targets'][target] = target_data
                
                if 'error' not in target_data:
                    aggregated['summary']['total_targets'] += 1
                    aggregated['summary']['total_services'] += len(target_data['services'])
                    
                    for port_vulns in target_data.get('vulnerabilities', {}).values():
                        aggregated['summary']['total_vulnerabilities'] += len(port_vulns)
                        
                        for vuln in port_vulns:
                            if vuln.get('cvss'):
                                if vuln['cvss'] >= 7.0:
                                    aggregated['summary']['high_severity_vulns'] += 1
                                elif vuln['cvss'] >= 4.0:
                                    aggregated['summary']['medium_severity_vulns'] += 1
                                else:
                                    aggregated['summary']['low_severity_vulns'] += 1
        
        return aggregated
