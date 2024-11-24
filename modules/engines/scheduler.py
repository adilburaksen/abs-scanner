import schedule
import time
import threading
from datetime import datetime
from modules.utils.logger import get_logger
from models.database import ScheduledScan, Target
from sqlalchemy import and_

logger = get_logger(__name__)

class ScanScheduler:
    def __init__(self, db_session, scanner_instance):
        self.db_session = db_session
        self.scanner = scanner_instance
        self.running = False
        self.schedule_thread = None

    def start(self):
        """Start the scheduler"""
        if not self.running:
            self.running = True
            self.schedule_thread = threading.Thread(target=self._run_scheduler)
            self.schedule_thread.daemon = True
            self.schedule_thread.start()
            logger.info("Scan scheduler started")

    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.schedule_thread:
            self.schedule_thread.join()
            logger.info("Scan scheduler stopped")

    def _run_scheduler(self):
        """Run the scheduler loop"""
        while self.running:
            schedule.run_pending()
            self._check_scheduled_scans()
            time.sleep(60)  # Check every minute

    def _check_scheduled_scans(self):
        """Check and execute scheduled scans"""
        try:
            current_time = datetime.utcnow()
            scheduled_scans = self.db_session.query(ScheduledScan).filter(
                and_(
                    ScheduledScan.next_run <= current_time,
                    ScheduledScan.active == True
                )
            ).all()

            for scan in scheduled_scans:
                self._execute_scheduled_scan(scan)

        except Exception as e:
            logger.error(f"Error checking scheduled scans: {str(e)}")

    def _execute_scheduled_scan(self, scheduled_scan):
        """Execute a scheduled scan"""
        try:
            target = self.db_session.query(Target).filter_by(
                id=scheduled_scan.target_id
            ).first()

            if not target:
                logger.error(f"Target not found for scheduled scan {scheduled_scan.id}")
                return

            # Start the scan
            scan_config = json.loads(scheduled_scan.scan_config)
            self.scanner.start_scan(
                target=target.url,
                scan_type=scan_config.get('scan_type', 'full'),
                options=scan_config.get('options', {})
            )

            # Update next run time based on frequency
            scheduled_scan.last_run = datetime.utcnow()
            scheduled_scan.next_run = self._calculate_next_run(
                scheduled_scan.frequency,
                scheduled_scan.last_run
            )
            
            self.db_session.commit()
            logger.info(f"Successfully executed scheduled scan {scheduled_scan.id}")

        except Exception as e:
            logger.error(f"Error executing scheduled scan {scheduled_scan.id}: {str(e)}")

    def _calculate_next_run(self, frequency, last_run):
        """Calculate the next run time based on frequency"""
        if frequency == 'hourly':
            return last_run + timedelta(hours=1)
        elif frequency == 'daily':
            return last_run + timedelta(days=1)
        elif frequency == 'weekly':
            return last_run + timedelta(weeks=1)
        elif frequency == 'monthly':
            return last_run + timedelta(days=30)
        return None

    def add_scheduled_scan(self, target_id, frequency, scan_config):
        """Add a new scheduled scan"""
        try:
            scheduled_scan = ScheduledScan(
                target_id=target_id,
                frequency=frequency,
                scan_config=json.dumps(scan_config),
                active=True,
                created_at=datetime.utcnow(),
                next_run=self._calculate_next_run(
                    frequency,
                    datetime.utcnow()
                )
            )

            self.db_session.add(scheduled_scan)
            self.db_session.commit()
            logger.info(f"Added new scheduled scan for target {target_id}")
            return scheduled_scan.id

        except Exception as e:
            logger.error(f"Error adding scheduled scan: {str(e)}")
            return None

    def update_scheduled_scan(self, scan_id, updates):
        """Update an existing scheduled scan"""
        try:
            scheduled_scan = self.db_session.query(ScheduledScan).filter_by(
                id=scan_id
            ).first()

            if not scheduled_scan:
                return False

            for key, value in updates.items():
                if key == 'scan_config':
                    setattr(scheduled_scan, key, json.dumps(value))
                elif hasattr(scheduled_scan, key):
                    setattr(scheduled_scan, key, value)

            if 'frequency' in updates:
                scheduled_scan.next_run = self._calculate_next_run(
                    updates['frequency'],
                    datetime.utcnow()
                )

            self.db_session.commit()
            logger.info(f"Updated scheduled scan {scan_id}")
            return True

        except Exception as e:
            logger.error(f"Error updating scheduled scan: {str(e)}")
            return False

    def delete_scheduled_scan(self, scan_id):
        """Delete a scheduled scan"""
        try:
            scheduled_scan = self.db_session.query(ScheduledScan).filter_by(
                id=scan_id
            ).first()

            if not scheduled_scan:
                return False

            self.db_session.delete(scheduled_scan)
            self.db_session.commit()
            logger.info(f"Deleted scheduled scan {scan_id}")
            return True

        except Exception as e:
            logger.error(f"Error deleting scheduled scan: {str(e)}")
            return False

    def get_scheduled_scans(self, target_id=None):
        """Get all scheduled scans or scans for a specific target"""
        try:
            query = self.db_session.query(ScheduledScan)
            if target_id:
                query = query.filter_by(target_id=target_id)
            return query.all()

        except Exception as e:
            logger.error(f"Error retrieving scheduled scans: {str(e)}")
            return []
