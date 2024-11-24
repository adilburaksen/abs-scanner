import requests
import json
from datetime import datetime
from modules.utils.logger import get_logger
from models.database import Webhook

logger = get_logger(__name__)

class WebhookManager:
    def __init__(self, db_session):
        self.db_session = db_session

    def add_webhook(self, url, name, events, headers=None, enabled=True):
        """Add a new webhook configuration"""
        try:
            webhook = Webhook(
                name=name,
                url=url,
                events=json.dumps(events),
                headers=json.dumps(headers) if headers else None,
                enabled=enabled,
                created_at=datetime.utcnow()
            )
            
            self.db_session.add(webhook)
            self.db_session.commit()
            logger.info(f"Added new webhook: {name}")
            return webhook.id

        except Exception as e:
            logger.error(f"Error adding webhook: {str(e)}")
            return None

    def update_webhook(self, webhook_id, updates):
        """Update an existing webhook"""
        try:
            webhook = self.db_session.query(Webhook).filter_by(id=webhook_id).first()
            if not webhook:
                return False

            for key, value in updates.items():
                if key in ['events', 'headers']:
                    setattr(webhook, key, json.dumps(value))
                elif hasattr(webhook, key):
                    setattr(webhook, key, value)

            self.db_session.commit()
            logger.info(f"Updated webhook: {webhook.name}")
            return True

        except Exception as e:
            logger.error(f"Error updating webhook: {str(e)}")
            return False

    def delete_webhook(self, webhook_id):
        """Delete a webhook"""
        try:
            webhook = self.db_session.query(Webhook).filter_by(id=webhook_id).first()
            if not webhook:
                return False

            self.db_session.delete(webhook)
            self.db_session.commit()
            logger.info(f"Deleted webhook: {webhook.name}")
            return True

        except Exception as e:
            logger.error(f"Error deleting webhook: {str(e)}")
            return False

    def get_webhooks(self, event_type=None):
        """Get all webhooks or webhooks for a specific event type"""
        try:
            webhooks = self.db_session.query(Webhook).filter_by(enabled=True).all()
            if event_type:
                return [
                    webhook for webhook in webhooks 
                    if event_type in json.loads(webhook.events)
                ]
            return webhooks

        except Exception as e:
            logger.error(f"Error retrieving webhooks: {str(e)}")
            return []

    def notify(self, event_type, payload):
        """Send notifications to all webhooks registered for the event type"""
        webhooks = self.get_webhooks(event_type)
        results = []

        for webhook in webhooks:
            try:
                headers = json.loads(webhook.headers) if webhook.headers else {
                    'Content-Type': 'application/json'
                }

                notification_data = {
                    'event': event_type,
                    'timestamp': datetime.utcnow().isoformat(),
                    'webhook_name': webhook.name,
                    'data': payload
                }

                response = requests.post(
                    webhook.url,
                    json=notification_data,
                    headers=headers,
                    timeout=10
                )

                success = 200 <= response.status_code < 300
                results.append({
                    'webhook_id': webhook.id,
                    'success': success,
                    'status_code': response.status_code,
                    'response': response.text if not success else None
                })

                if not success:
                    logger.warning(
                        f"Webhook {webhook.name} returned status {response.status_code}"
                    )

            except Exception as e:
                logger.error(f"Error sending webhook {webhook.name}: {str(e)}")
                results.append({
                    'webhook_id': webhook.id,
                    'success': False,
                    'error': str(e)
                })

        return results

    def test_webhook(self, webhook_id):
        """Test a webhook configuration"""
        try:
            webhook = self.db_session.query(Webhook).filter_by(id=webhook_id).first()
            if not webhook:
                return False

            test_payload = {
                'event': 'test',
                'message': 'This is a test notification',
                'timestamp': datetime.utcnow().isoformat()
            }

            headers = json.loads(webhook.headers) if webhook.headers else {
                'Content-Type': 'application/json'
            }

            response = requests.post(
                webhook.url,
                json=test_payload,
                headers=headers,
                timeout=10
            )

            return {
                'success': 200 <= response.status_code < 300,
                'status_code': response.status_code,
                'response': response.text
            }

        except Exception as e:
            logger.error(f"Error testing webhook: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
