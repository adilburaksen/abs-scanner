from flask import Blueprint, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timedelta
from modules.vuln_scanner import VulnerabilityScanner
from modules.engines.cve_manager import CVEManager
from modules.engines.custom_vuln_manager import CustomVulnerabilityManager
from modules.engines.scheduler import ScanScheduler
from modules.engines.webhook_manager import WebhookManager
from modules.engines.ml_analyzer import MLAnalyzer
from models.database import db, Target, Finding, Vulnerability, ScheduledScan, Webhook
import os

api = Blueprint('api', __name__)

# Initialize components
scanner = VulnerabilityScanner(db.session)
cve_manager = CVEManager(db.session)
custom_vuln_manager = CustomVulnerabilityManager(db.session)
scheduler = ScanScheduler(db.session, scanner)
webhook_manager = WebhookManager(db.session)
ml_analyzer = MLAnalyzer(db.session)

# Start the scheduler
scheduler.start()

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.getenv('API_KEY'):
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

# Scan Management Endpoints
@api.route('/scans', methods=['POST'])
@require_api_key
def start_scan():
    """Start a new scan"""
    try:
        data = request.get_json()
        target_url = data.get('target_url')
        scan_type = data.get('scan_type', 'full')
        options = data.get('options', {})

        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400

        scan_id = scanner.start_scan(target_url, scan_type, options)
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/scans/<scan_id>', methods=['GET'])
@require_api_key
def get_scan_status(scan_id):
    """Get scan status and results"""
    try:
        status = scanner.get_scan_status(scan_id)
        if not status:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(status)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/scans/<scan_id>', methods=['DELETE'])
@require_api_key
def stop_scan(scan_id):
    """Stop a running scan"""
    try:
        if scanner.stop_scan(scan_id):
            return jsonify({'message': 'Scan stopped successfully'})
        return jsonify({'error': 'Scan not found or already completed'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Target Management Endpoints
@api.route('/targets', methods=['GET'])
@require_api_key
def list_targets():
    """List all targets"""
    try:
        targets = Target.query.all()
        return jsonify([{
            'id': t.id,
            'url': t.url,
            'name': t.name,
            'last_scan': t.last_scan.isoformat() if t.last_scan else None
        } for t in targets])

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/targets', methods=['POST'])
@require_api_key
def add_target():
    """Add a new target"""
    try:
        data = request.get_json()
        target = Target(
            url=data['url'],
            name=data.get('name', data['url'])
        )
        db.session.add(target)
        db.session.commit()
        return jsonify({
            'id': target.id,
            'message': 'Target added successfully'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Vulnerability Management Endpoints
@api.route('/vulnerabilities', methods=['GET'])
@require_api_key
def list_vulnerabilities():
    """List vulnerabilities"""
    try:
        query = Vulnerability.query
        severity = request.args.get('severity')
        cve_id = request.args.get('cve_id')

        if severity:
            query = query.filter_by(severity=severity)
        if cve_id:
            query = query.filter_by(cve_id=cve_id)

        vulns = query.all()
        return jsonify([{
            'id': v.id,
            'name': v.name,
            'severity': v.severity,
            'cve_id': v.cve_id
        } for v in vulns])

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Scheduled Scan Endpoints
@api.route('/scheduled-scans', methods=['POST'])
@require_api_key
def schedule_scan():
    """Schedule a new scan"""
    try:
        data = request.get_json()
        scan_id = scheduler.add_scheduled_scan(
            target_id=data['target_id'],
            frequency=data['frequency'],
            scan_config=data.get('scan_config', {})
        )
        return jsonify({
            'id': scan_id,
            'message': 'Scan scheduled successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Webhook Management Endpoints
@api.route('/webhooks', methods=['POST'])
@require_api_key
def add_webhook():
    """Add a new webhook"""
    try:
        data = request.get_json()
        webhook_id = webhook_manager.add_webhook(
            url=data['url'],
            name=data['name'],
            events=data['events'],
            headers=data.get('headers')
        )
        return jsonify({
            'id': webhook_id,
            'message': 'Webhook added successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ML Analysis Endpoints
@api.route('/ml/analyze', methods=['POST'])
@require_api_key
def analyze_findings():
    """Analyze findings for false positives"""
    try:
        data = request.get_json()
        finding_ids = data.get('finding_ids', [])
        findings = Finding.query.filter(Finding.id.in_(finding_ids)).all()
        
        results = ml_analyzer.analyze_finding_batch(findings)
        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/ml/train', methods=['POST'])
@require_api_key
def train_model():
    """Train the ML model"""
    try:
        success = ml_analyzer.train_model()
        if success:
            return jsonify({'message': 'Model trained successfully'})
        return jsonify({'error': 'Insufficient training data'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# CVE Management Endpoints
@api.route('/cve/update', methods=['POST'])
@require_api_key
def update_cve_database():
    """Update the CVE database"""
    try:
        days_back = request.json.get('days_back', 30)
        success = cve_manager.update_cve_database(days_back)
        if success:
            return jsonify({'message': 'CVE database updated successfully'})
        return jsonify({'error': 'Failed to update CVE database'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500
