"""
Alert Manager Module for BTIS
Manages alert generation, notification, and response workflows
"""

import logging
from datetime import datetime
from flask_mail import Message

logger = logging.getLogger(__name__)

class AlertManager:
    """
    Manages security alerts and incident response
    Handles notifications, escalations, and SOC workflows
    """
    
    def __init__(self, mail, socketio):
        self.mail = mail
        self.socketio = socketio
        
        # Alert severity configuration
        self.severity_config = {
            'low': {
                'color': '#22c55e',
                'notify': False,
                'escalation_time': None,
                'auto_action': None
            },
            'medium': {
                'color': '#eab308',
                'notify': True,
                'escalation_time': 60,  # minutes
                'auto_action': 'log'
            },
            'high': {
                'color': '#f97316',
                'notify': True,
                'escalation_time': 30,
                'auto_action': 'notify_admin'
            },
            'critical': {
                'color': '#ef4444',
                'notify': True,
                'escalation_time': 15,
                'auto_action': 'block_account'
            }
        }
        
        logger.info("Alert Manager initialized")
    
    def create_alert(self, user_id, alert_type, severity, title, description, 
                     risk_score, details=None, evidence=None, related_logs=None):
        """
        Create a new security alert
        
        Args:
            user_id: User ID
            alert_type: Type of alert
            severity: low, medium, high, critical
            title: Alert title
            description: Alert description
            risk_score: Risk score (0-100)
            details: Additional details dict
            evidence: Evidence list
            related_logs: Related behavior log IDs
        
        Returns:
            Created Alert object
        """
        from app import app, db
        from models.alert import Alert
        from models.user import User
        
        with app.app_context():
            try:
                # Generate alert ID
                alert_id = Alert.generate_alert_id()
                
                # Determine category
                category = self._determine_category(alert_type)
                
                # Create alert
                alert = Alert(
                    alert_id=alert_id,
                    user_id=user_id,
                    severity=severity,
                    category=category,
                    alert_type=alert_type,
                    title=title,
                    description=description,
                    details=details or {},
                    risk_score=risk_score,
                    risk_factors=self._extract_risk_factors(details),
                    evidence=evidence or [],
                    related_logs=related_logs or [],
                    status='new',
                    detected_at=datetime.utcnow()
                )
                
                db.session.add(alert)
                db.session.commit()
                
                logger.info(f"Created alert {alert_id} for user {user_id}")
                
                # Process alert
                self._process_alert(alert)
                
                return alert
                
            except Exception as e:
                logger.error(f"Error creating alert: {str(e)}")
                db.session.rollback()
                return None
    
    def _determine_category(self, alert_type):
        """Determine alert category from type"""
        category_map = {
            'login_anomaly': 'insider_threat',
            'file_spike': 'insider_threat',
            'privilege_escalation': 'insider_threat',
            'data_exfiltration': 'insider_threat',
            'after_hours_access': 'anomaly',
            'sensitive_access': 'policy_violation',
            'failed_login_spike': 'zero_day',
            'ml_anomaly': 'anomaly',
            'behavior_deviation': 'insider_threat'
        }
        return category_map.get(alert_type, 'anomaly')
    
    def _extract_risk_factors(self, details):
        """Extract risk factors from alert details"""
        if not details:
            return []
        
        factors = []
        if 'risk_factors' in details:
            factors = details['risk_factors']
        elif 'anomaly_features' in details:
            factors = [{'type': k, 'value': v} for k, v in details['anomaly_features'].items()]
        
        return factors
    
    def _process_alert(self, alert):
        """Process newly created alert"""
        config = self.severity_config.get(alert.severity, {})
        
        # Emit real-time notification
        self._emit_alert_notification(alert)
        
        # Send email if configured
        if config.get('notify', False):
            self._send_email_notification(alert)
        
        # Execute auto-action if configured
        auto_action = config.get('auto_action')
        if auto_action:
            self._execute_auto_action(alert, auto_action)
    
    def _emit_alert_notification(self, alert):
        """Emit real-time alert notification via WebSocket"""
        try:
            notification = {
                'type': 'new_alert',
                'alert': alert.to_dict(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.socketio.emit('alert', notification, broadcast=True, namespace='/')
            logger.info(f"Emitted alert notification for {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error emitting alert notification: {str(e)}")
    
    def _send_email_notification(self, alert):
        """Send email notification for alert"""
        try:
            import os
            
            # Check if email alerts are enabled globally
            email_enabled = os.getenv('ALERT_EMAIL_ENABLED', 'False').lower() == 'true'
            if not email_enabled:
                logger.info(f"Email alerts disabled - skipping notification for {alert.alert_id}")
                return
            
            from models.user import User
            
            # Get recipients
            recipients = []
            
            # Check for configured recipient
            env_recipient = os.getenv('ALERT_RECIPIENT_EMAIL', os.getenv('MAIL_USERNAME'))
            if env_recipient:
                recipients.append(env_recipient)
                
            # Also notify admins
            admins = User.query.filter_by(role='admin', is_active=True).all()
            for admin in admins:
                if admin.email and admin.email not in recipients:
                    recipients.append(admin.email)
            
            if not recipients:
                logger.warning("No email recipients found (checked env and admins)")
                return
            
            # Create email
            subject = f"[BTIS Alert - {alert.severity.upper()}] {alert.title}"
            
            body = f"""
Security Alert - Behavioral Threat Intelligence System

Alert ID: {alert.alert_id}
Severity: {alert.severity.upper()}
Category: {alert.category}
Type: {alert.alert_type}

User: {alert.user.username if alert.user else 'Unknown'} (ID: {alert.user_id})
Risk Score: {alert.risk_score}

Description:
{alert.description}

Detected at: {alert.detected_at}

Please log in to the BTIS dashboard to investigate.

---
This is an automated alert from the AI-Driven Behavioral Threat Intelligence System.
            """
            
            msg = Message(
                subject=subject,
                recipients=recipients,
                body=body
            )
            
            self.mail.send(msg)
            
            # Update alert
            alert.email_sent = True
            alert.email_sent_at = datetime.utcnow()
            from app import db
            db.session.commit()
            
            logger.info(f"Sent email notification for alert {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
    
    def _execute_auto_action(self, alert, action):
        """Execute automated action based on alert severity"""
        from app import db
        
        try:
            if action == 'log':
                # Just log the alert
                logger.info(f"Auto-action: Logged alert {alert.alert_id}")
                
            elif action == 'notify_admin':
                # Already handled by email notification
                logger.info(f"Auto-action: Notified admins for alert {alert.alert_id}")
                
            elif action == 'block_account':
                # Flag user account
                from models.user import User
                user = User.query.get(alert.user_id)
                if user:
                    user.is_flagged = True
                    user.flag_reason = f"Auto-flagged due to critical alert: {alert.alert_id}"
                    db.session.commit()
                    logger.info(f"Auto-action: Flagged user {alert.user_id}")
                    
                    # Add to alert actions
                    alert.actions_taken.append({
                        'action': 'flag_account',
                        'timestamp': datetime.utcnow().isoformat(),
                        'reason': 'Critical severity alert'
                    })
                    db.session.commit()
            
        except Exception as e:
            logger.error(f"Error executing auto-action: {str(e)}")
    
    def acknowledge_alert(self, alert_id, user_id):
        """Acknowledge an alert"""
        from app import app
        from models.alert import Alert
        from app import db
        
        with app.app_context():
            try:
                alert = Alert.query.filter_by(alert_id=alert_id).first()
                if not alert:
                    return {'success': False, 'error': 'Alert not found'}
                
                alert.acknowledge(user_id)
                
                # Emit update
                self._emit_alert_update(alert)
                
                return {'success': True, 'alert': alert.to_dict()}
                
            except Exception as e:
                logger.error(f"Error acknowledging alert: {str(e)}")
                return {'success': False, 'error': str(e)}
    
    def resolve_alert(self, alert_id, resolution, resolution_type='confirmed_threat'):
        """Resolve an alert"""
        from app import app
        from models.alert import Alert
        
        with app.app_context():
            try:
                alert = Alert.query.filter_by(alert_id=alert_id).first()
                if not alert:
                    return {'success': False, 'error': 'Alert not found'}
                
                alert.resolve(resolution, resolution_type)
                
                # Emit update
                self._emit_alert_update(alert)
                
                return {'success': True, 'alert': alert.to_dict()}
                
            except Exception as e:
                logger.error(f"Error resolving alert: {str(e)}")
                return {'success': False, 'error': str(e)}
    
    def _emit_alert_update(self, alert):
        """Emit alert status update via WebSocket"""
        try:
            notification = {
                'type': 'alert_update',
                'alert': alert.to_dict(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.socketio.emit('alert_update', notification, broadcast=True, namespace='/')
            
        except Exception as e:
            logger.error(f"Error emitting alert update: {str(e)}")
    
    def escalate_alert(self, alert_id):
        """Escalate an alert to higher severity"""
        from app import app
        from models.alert import Alert
        from app import db
        
        with app.app_context():
            try:
                alert = Alert.query.filter_by(alert_id=alert_id).first()
                if not alert:
                    return {'success': False, 'error': 'Alert not found'}
                
                # Escalate severity
                severity_order = ['low', 'medium', 'high', 'critical']
                current_idx = severity_order.index(alert.severity)
                
                if current_idx < len(severity_order) - 1:
                    alert.severity = severity_order[current_idx + 1]
                    db.session.commit()
                    
                    # Re-process with new severity
                    self._process_alert(alert)
                    
                    logger.info(f"Escalated alert {alert_id} to {alert.severity}")
                    
                    return {'success': True, 'alert': alert.to_dict()}
                else:
                    return {'success': False, 'error': 'Alert already at maximum severity'}
                    
            except Exception as e:
                logger.error(f"Error escalating alert: {str(e)}")
                return {'success': False, 'error': str(e)}
    
    def create_incident(self, alert_id):
        """Create an incident from a high-severity alert"""
        from app import app
        from models.alert import Alert, Incident
        from app import db
        
        with app.app_context():
            try:
                alert = Alert.query.filter_by(alert_id=alert_id).first()
                if not alert:
                    return {'success': False, 'error': 'Alert not found'}
                
                # Check if incident already exists
                if alert.incident:
                    return {'success': False, 'error': 'Incident already exists', 'incident_id': alert.incident.incident_id}
                
                # Create incident
                incident = Incident(
                    incident_id=Incident.generate_incident_id(),
                    alert_id=alert.id,
                    user_id=alert.user_id,
                    title=f"Incident from {alert.alert_id}: {alert.title}",
                    description=alert.description,
                    impact_level='high' if alert.severity in ['high', 'critical'] else 'medium',
                    status='open',
                    detected_at=datetime.utcnow()
                )
                
                db.session.add(incident)
                db.session.commit()
                
                logger.info(f"Created incident {incident.incident_id} from alert {alert_id}")
                
                return {'success': True, 'incident': incident.to_dict()}
                
            except Exception as e:
                logger.error(f"Error creating incident: {str(e)}")
                return {'success': False, 'error': str(e)}
    
    def get_alert_stats(self, hours=24):
        """Get alert statistics"""
        from app import app
        from models.alert import Alert
        from sqlalchemy import func
        
        with app.app_context():
            try:
                since = datetime.utcnow() - __import__('datetime').timedelta(hours=hours)
                
                # Count by severity
                severity_counts = db.session.query(
                    Alert.severity,
                    func.count(Alert.id).label('count')
                ).filter(Alert.detected_at >= since).group_by(Alert.severity).all()
                
                # Count by status
                status_counts = db.session.query(
                    Alert.status,
                    func.count(Alert.id).label('count')
                ).filter(Alert.detected_at >= since).group_by(Alert.status).all()
                
                # Count by category
                category_counts = db.session.query(
                    Alert.category,
                    func.count(Alert.id).label('count')
                ).filter(Alert.detected_at >= since).group_by(Alert.category).all()
                
                return {
                    'period_hours': hours,
                    'by_severity': {s.severity: s.count for s in severity_counts},
                    'by_status': {s.status: s.count for s in status_counts},
                    'by_category': {c.category: c.count for c in category_counts},
                    'total': sum(s.count for s in severity_counts)
                }
                
            except Exception as e:
                logger.error(f"Error getting alert stats: {str(e)}")
                return {}
    
    def check_alert_rules(self, user_id, behavior_data):
        """Check behavior data against alert rules"""
        from app import app
        from models.alert import AlertRule
        
        with app.app_context():
            try:
                rules = AlertRule.query.filter_by(is_active=True).all()
                triggered_rules = []
                
                for rule in rules:
                    if self._evaluate_rule(rule, behavior_data):
                        triggered_rules.append(rule)
                
                return triggered_rules
                
            except Exception as e:
                logger.error(f"Error checking alert rules: {str(e)}")
                return []
    
    def _evaluate_rule(self, rule, behavior_data):
        """Evaluate a single alert rule"""
        conditions = rule.conditions
        
        # Simple threshold-based evaluation
        if rule.condition_type == 'threshold':
            metric = conditions.get('metric')
            threshold = conditions.get('threshold')
            operator = conditions.get('operator', 'gt')
            
            value = behavior_data.get(metric, 0)
            
            if operator == 'gt':
                return value > threshold
            elif operator == 'lt':
                return value < threshold
            elif operator == 'eq':
                return value == threshold
            elif operator == 'gte':
                return value >= threshold
            elif operator == 'lte':
                return value <= threshold
        
        return False
