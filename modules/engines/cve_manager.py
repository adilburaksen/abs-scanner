import requests
import json
import os
from datetime import datetime, timedelta
from modules.utils.logger import get_logger
from models.database import Vulnerability

logger = get_logger(__name__)

class CVEManager:
    def __init__(self, db_session):
        self.db_session = db_session
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.local_cve_cache = "data/cve_cache.json"

    def update_cve_database(self, days_back=30):
        """Update local CVE database with recent vulnerabilities"""
        try:
            start_date = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            params = {
                'pubStartDate': start_date,
                'resultsPerPage': 2000
            }

            response = requests.get(
                self.base_url,
                headers=headers,
                params=params
            )

            if response.status_code == 200:
                cves = response.json().get('vulnerabilities', [])
                self._process_cves(cves)
                self._update_cache(cves)
                logger.info(f"Successfully updated CVE database with {len(cves)} vulnerabilities")
                return True
            else:
                logger.error(f"Failed to fetch CVEs: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error updating CVE database: {str(e)}")
            return False

    def _process_cves(self, cves):
        """Process and store CVEs in the database"""
        for cve_data in cves:
            try:
                cve = cve_data.get('cve', {})
                cve_id = cve.get('id')
                
                # Skip if CVE already exists
                if self.db_session.query(Vulnerability).filter_by(cve_id=cve_id).first():
                    continue

                metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})
                
                vuln = Vulnerability(
                    name=cve_id,
                    description=cve.get('descriptions', [{}])[0].get('value', ''),
                    severity=self._get_severity(metrics.get('baseScore', 0)),
                    cvss_score=metrics.get('baseScore'),
                    cve_id=cve_id,
                    detection_module='nvd',
                    detection_pattern=json.dumps({
                        'attack_vector': metrics.get('attackVector'),
                        'attack_complexity': metrics.get('attackComplexity'),
                        'privileges_required': metrics.get('privilegesRequired'),
                        'user_interaction': metrics.get('userInteraction'),
                        'scope': metrics.get('scope'),
                        'impact': {
                            'confidentiality': metrics.get('confidentialityImpact'),
                            'integrity': metrics.get('integrityImpact'),
                            'availability': metrics.get('availabilityImpact')
                        }
                    })
                )

                self.db_session.add(vuln)
                self.db_session.commit()

            except Exception as e:
                logger.error(f"Error processing CVE {cve_id}: {str(e)}")
                continue

    def _get_severity(self, base_score):
        """Convert CVSS base score to severity rating"""
        if base_score >= 9.0:
            return "critical"
        elif base_score >= 7.0:
            return "high"
        elif base_score >= 4.0:
            return "medium"
        elif base_score > 0:
            return "low"
        return "info"

    def _update_cache(self, cves):
        """Update local CVE cache file"""
        try:
            cache_dir = os.path.dirname(self.local_cve_cache)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)

            with open(self.local_cve_cache, 'w') as f:
                json.dump({
                    'last_update': datetime.utcnow().isoformat(),
                    'cves': cves
                }, f)

        except Exception as e:
            logger.error(f"Error updating CVE cache: {str(e)}")

    def get_cve_details(self, cve_id):
        """Get detailed information about a specific CVE"""
        try:
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            response = requests.get(
                f"{self.base_url}",
                headers=headers,
                params={'cveId': cve_id}
            )

            if response.status_code == 200:
                return response.json().get('vulnerabilities', [{}])[0].get('cve', {})
            return None

        except Exception as e:
            logger.error(f"Error fetching CVE details for {cve_id}: {str(e)}")
            return None

    def search_cves(self, keyword=None, severity=None, score_range=None):
        """Search CVEs based on criteria"""
        query = self.db_session.query(Vulnerability)

        if keyword:
            query = query.filter(
                (Vulnerability.name.ilike(f"%{keyword}%")) |
                (Vulnerability.description.ilike(f"%{keyword}%"))
            )

        if severity:
            query = query.filter(Vulnerability.severity == severity)

        if score_range:
            min_score, max_score = score_range
            query = query.filter(
                Vulnerability.cvss_score.between(min_score, max_score)
            )

        return query.all()
