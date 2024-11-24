import os
import json
import subprocess
from datetime import datetime
from modules.utils.logger import get_logger
from models.database import Finding, Vulnerability

logger = get_logger(__name__)

class NucleiScanner:
    def __init__(self, target, db_session):
        self.target = target
        self.db_session = db_session
        self.nuclei_path = "nuclei"  # Assuming nuclei is in PATH
        self.templates_dir = "nuclei-templates"
        self.results = []

    def update_templates(self):
        """Update nuclei templates"""
        try:
            subprocess.run([self.nuclei_path, "-update-templates"], check=True)
            logger.info("Successfully updated nuclei templates")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update nuclei templates: {str(e)}")
            return False

    def run_scan(self, scan_id, severity=None, tags=None):
        """Run nuclei scan with specified parameters"""
        try:
            cmd = [self.nuclei_path, "-target", self.target, "-json"]

            if severity:
                cmd.extend(["-severity", severity])
            if tags:
                cmd.extend(["-tags", tags])

            # Add rate limiting and other configurations
            cmd.extend([
                "-rate-limit", "150",
                "-bulk-size", "25",
                "-concurrency", "10",
                "-timeout", "5"
            ])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Process results in real-time
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    self._process_finding(line.strip(), scan_id)

            return_code = process.poll()
            if return_code != 0:
                logger.error(f"Nuclei scan failed with return code {return_code}")
                return False

            logger.info(f"Nuclei scan completed successfully for {self.target}")
            return True

        except Exception as e:
            logger.error(f"Error during nuclei scan: {str(e)}")
            return False

    def _process_finding(self, json_line, scan_id):
        """Process and store nuclei finding"""
        try:
            result = json.loads(json_line)
            
            # Create finding object
            finding = Finding(
                scan_id=scan_id,
                type="vulnerability",
                severity=result.get("info", {}).get("severity", "unknown"),
                title=result.get("info", {}).get("name"),
                description=result.get("info", {}).get("description"),
                proof_of_concept=result.get("matched-at"),
                cvss_score=self._extract_cvss(result),
                cve_ids=self._extract_cves(result),
                discovered_date=datetime.utcnow()
            )

            # Add to database
            self.db_session.add(finding)
            self.db_session.commit()

            # Update vulnerability statistics
            self._update_vulnerability_stats(finding)

        except json.JSONDecodeError:
            logger.error(f"Failed to parse nuclei output: {json_line}")
        except Exception as e:
            logger.error(f"Error processing nuclei finding: {str(e)}")

    def _extract_cvss(self, result):
        """Extract CVSS score from nuclei result"""
        try:
            cvss = result.get("info", {}).get("classification", {}).get("cvss-score")
            return float(cvss) if cvss else None
        except:
            return None

    def _extract_cves(self, result):
        """Extract CVE IDs from nuclei result"""
        try:
            cves = result.get("info", {}).get("classification", {}).get("cve-id", [])
            if isinstance(cves, list):
                return ",".join(cves)
            return cves if cves else None
        except:
            return None

    def _update_vulnerability_stats(self, finding):
        """Update vulnerability statistics for machine learning"""
        try:
            vuln = self.db_session.query(Vulnerability).filter_by(
                name=finding.title
            ).first()

            if not vuln:
                vuln = Vulnerability(
                    name=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    cvss_score=finding.cvss_score,
                    cve_id=finding.cve_ids.split(",")[0] if finding.cve_ids else None,
                    detection_module="nuclei",
                    detection_pattern=json.dumps({
                        "type": "nuclei",
                        "template": finding.proof_of_concept
                    })
                )
                self.db_session.add(vuln)
            
            self.db_session.commit()

        except Exception as e:
            logger.error(f"Error updating vulnerability stats: {str(e)}")

    def get_template_stats(self):
        """Get statistics about available nuclei templates"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-tl"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get template stats: {str(e)}")
            return None
