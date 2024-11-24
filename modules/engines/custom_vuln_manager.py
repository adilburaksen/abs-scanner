import json
import os
import re
from datetime import datetime
from modules.utils.logger import get_logger
from models.database import Vulnerability

logger = get_logger(__name__)

class CustomVulnerabilityManager:
    def __init__(self, db_session):
        self.db_session = db_session
        self.custom_rules_dir = "data/custom_rules"
        self.ensure_rules_directory()

    def ensure_rules_directory(self):
        """Ensure the custom rules directory exists"""
        if not os.path.exists(self.custom_rules_dir):
            os.makedirs(self.custom_rules_dir)

    def add_custom_vulnerability(self, vuln_data):
        """Add a new custom vulnerability definition"""
        try:
            # Validate required fields
            required_fields = ['name', 'description', 'severity', 'detection_pattern']
            for field in required_fields:
                if field not in vuln_data:
                    raise ValueError(f"Missing required field: {field}")

            # Create vulnerability object
            vuln = Vulnerability(
                name=vuln_data['name'],
                description=vuln_data['description'],
                severity=vuln_data['severity'],
                cvss_score=vuln_data.get('cvss_score', 0.0),
                cve_id=vuln_data.get('cve_id'),
                detection_module='custom',
                detection_pattern=json.dumps(vuln_data['detection_pattern'])
            )

            # Save to database
            self.db_session.add(vuln)
            self.db_session.commit()

            # Save to file system
            self._save_rule_to_file(vuln_data)

            logger.info(f"Successfully added custom vulnerability: {vuln_data['name']}")
            return True

        except Exception as e:
            logger.error(f"Error adding custom vulnerability: {str(e)}")
            return False

    def _save_rule_to_file(self, vuln_data):
        """Save vulnerability rule to file"""
        rule_file = os.path.join(
            self.custom_rules_dir,
            f"{self._sanitize_filename(vuln_data['name'])}.json"
        )
        
        with open(rule_file, 'w') as f:
            json.dump({
                **vuln_data,
                'created_at': datetime.utcnow().isoformat(),
                'last_modified': datetime.utcnow().isoformat()
            }, f, indent=4)

    def _sanitize_filename(self, filename):
        """Sanitize the filename for safe file system usage"""
        return re.sub(r'[^\w\-_.]', '_', filename)

    def update_custom_vulnerability(self, vuln_id, updates):
        """Update an existing custom vulnerability"""
        try:
            vuln = self.db_session.query(Vulnerability).filter_by(id=vuln_id).first()
            if not vuln or vuln.detection_module != 'custom':
                return False

            # Update database record
            for key, value in updates.items():
                if key == 'detection_pattern':
                    setattr(vuln, key, json.dumps(value))
                elif hasattr(vuln, key):
                    setattr(vuln, key, value)

            self.db_session.commit()

            # Update rule file
            rule_file = os.path.join(
                self.custom_rules_dir,
                f"{self._sanitize_filename(vuln.name)}.json"
            )
            
            if os.path.exists(rule_file):
                with open(rule_file, 'r') as f:
                    rule_data = json.load(f)
                
                rule_data.update(updates)
                rule_data['last_modified'] = datetime.utcnow().isoformat()

                with open(rule_file, 'w') as f:
                    json.dump(rule_data, f, indent=4)

            logger.info(f"Successfully updated custom vulnerability: {vuln.name}")
            return True

        except Exception as e:
            logger.error(f"Error updating custom vulnerability: {str(e)}")
            return False

    def delete_custom_vulnerability(self, vuln_id):
        """Delete a custom vulnerability"""
        try:
            vuln = self.db_session.query(Vulnerability).filter_by(id=vuln_id).first()
            if not vuln or vuln.detection_module != 'custom':
                return False

            # Delete from database
            self.db_session.delete(vuln)
            self.db_session.commit()

            # Delete rule file
            rule_file = os.path.join(
                self.custom_rules_dir,
                f"{self._sanitize_filename(vuln.name)}.json"
            )
            
            if os.path.exists(rule_file):
                os.remove(rule_file)

            logger.info(f"Successfully deleted custom vulnerability: {vuln.name}")
            return True

        except Exception as e:
            logger.error(f"Error deleting custom vulnerability: {str(e)}")
            return False

    def load_custom_rules(self):
        """Load all custom vulnerability rules from files"""
        try:
            rules = []
            for filename in os.listdir(self.custom_rules_dir):
                if filename.endswith('.json'):
                    with open(os.path.join(self.custom_rules_dir, filename), 'r') as f:
                        rules.append(json.load(f))
            return rules

        except Exception as e:
            logger.error(f"Error loading custom rules: {str(e)}")
            return []

    def validate_detection_pattern(self, pattern):
        """Validate a detection pattern format"""
        required_keys = ['type', 'pattern']
        if not all(key in pattern for key in required_keys):
            return False

        valid_types = ['regex', 'keyword', 'header', 'response_code']
        if pattern['type'] not in valid_types:
            return False

        if pattern['type'] == 'regex':
            try:
                re.compile(pattern['pattern'])
            except re.error:
                return False

        return True
