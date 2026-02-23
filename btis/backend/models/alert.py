"""
Alert and Incident Models for BTIS
Manages security alerts and incident response
"""

from datetime import datetime
from app import db

class Alert(db.Model):
    """Security alert model"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    # Format: ALT-YYYYMMDD-XXXX
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Alert classification
    severity = db.Column(db.String(20), nullable=False, index=True)  # low, medium, high, critical
    category = db.Column(db.String(50), nullable=False)  # insider_threat, zero_day, anomaly, policy_violation
    alert_type = db.Column(db.String(50), nullable=False)  # login_anomaly, file_spike, privilege_escalation, etc.
    
    # Alert details
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    details = db.Column(db.JSON, default=dict)  # Structured alert details
    
    # Risk information
    risk_score = db.Column(db.Float, nullable=False)  # 0-100
    risk_factors = db.Column(db.JSON, default=list)  # Contributing factors
    
    # Evidence
    evidence = db.Column(db.JSON, default=list)  # List of evidence items
    related_logs = db.Column(db.JSON, default=list)  # Related behavior log IDs
    
    # Status workflow
    status = db.Column(db.String(20), default='new', index=True)  # new, acknowledged, investigating, resolved, false_positive
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Resolution
    resolution = db.Column(db.Text, nullable=True)
    resolution_type = db.Column(db.String(50), nullable=True)  # confirmed_threat, false_positive, benign
    
    # Notifications
    email_sent = db.Column(db.Boolean, default=False)
    email_sent_at = db.Column(db.DateTime, nullable=True)
    
    # SOC actions
    actions_taken = db.Column(db.JSON, default=list)  # List of actions
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], back_populates='alerts')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_alerts')
    incident = db.relationship('Incident', backref='alert', uselist=False)
    
    def to_dict(self, include_details=False):
        """Convert alert to dictionary"""
        data = {
            'id': self.id,
            'alert_id': self.alert_id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'severity': self.severity,
            'category': self.category,
            'alert_type': self.alert_type,
            'title': self.title,
            'description': self.description,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'assignee_name': self.assignee.username if self.assignee else None,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolution': self.resolution,
            'resolution_type': self.resolution_type,
            'email_sent': self.email_sent,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_details:
            data['details'] = self.details
            data['evidence'] = self.evidence
            data['related_logs'] = self.related_logs
            data['actions_taken'] = self.actions_taken
        
        return data
    
    @staticmethod
    def generate_alert_id():
        """Generate unique alert ID"""
        from datetime import date
        import random
        
        date_str = date.today().strftime('%Y%m%d')
        random_num = random.randint(1000, 9999)
        return f"ALT-{date_str}-{random_num}"
    
    @staticmethod
    def get_stats(hours=24):
        """Get alert statistics"""
        from sqlalchemy import func
        
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
        
        return {
            'period_hours': hours,
            'by_severity': {s.severity: s.count for s in severity_counts},
            'by_status': {s.status: s.count for s in status_counts},
            'total': sum(s.count for s in severity_counts)
        }
    
    def acknowledge(self, user_id):
        """Acknowledge the alert"""
        self.status = 'acknowledged'
        self.assigned_to = user_id
        self.acknowledged_at = datetime.utcnow()
        db.session.commit()
    
    def resolve(self, resolution, resolution_type='confirmed_threat'):
        """Resolve the alert"""
        self.status = 'resolved'
        self.resolution = resolution
        self.resolution_type = resolution_type
        self.resolved_at = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<Alert {self.alert_id} severity={self.severity}>'


class Incident(db.Model):
    """Security incident for major threats"""
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(50), unique=True, nullable=False)
    # Format: INC-YYYYMMDD-XXXX
    
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Incident details
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impact_level = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Incident response
    response_team = db.Column(db.JSON, default=list)  # List of responder IDs
    containment_actions = db.Column(db.JSON, default=list)
    eradication_actions = db.Column(db.JSON, default=list)
    recovery_actions = db.Column(db.JSON, default=list)
    
    # Timeline
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    contained_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Status
    status = db.Column(db.String(20), default='open')  # open, contained, resolved, closed
    
    # Lessons learned
    post_incident_report = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.JSON, default=list)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self, include_details=False):
        """Convert incident to dictionary"""
        data = {
            'id': self.id,
            'incident_id': self.incident_id,
            'alert_id': self.alert_id,
            'user_id': self.user_id,
            'username': self.alert.user.username if self.alert and self.alert.user else None,
            'title': self.title,
            'description': self.description,
            'impact_level': self.impact_level,
            'status': self.status,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'contained_at': self.contained_at.isoformat() if self.contained_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_details:
            data['response_team'] = self.response_team
            data['containment_actions'] = self.containment_actions
            data['eradication_actions'] = self.eradication_actions
            data['recovery_actions'] = self.recovery_actions
            data['post_incident_report'] = self.post_incident_report
            data['recommendations'] = self.recommendations
        
        return data
    
    @staticmethod
    def generate_incident_id():
        """Generate unique incident ID"""
        from datetime import date
        import random
        
        date_str = date.today().strftime('%Y%m%d')
        random_num = random.randint(1000, 9999)
        return f"INC-{date_str}-{random_num}"
    
    def __repr__(self):
        return f'<Incident {self.incident_id}>'


class AlertRule(db.Model):
    """Custom alert rules for threat detection"""
    __tablename__ = 'alert_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Rule conditions
    condition_type = db.Column(db.String(50), nullable=False)  # threshold, pattern, ml_anomaly
    conditions = db.Column(db.JSON, nullable=False)  # Structured conditions
    
    # Rule actions
    severity = db.Column(db.String(20), default='medium')
    alert_type = db.Column(db.String(50), nullable=False)
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'condition_type': self.condition_type,
            'conditions': self.conditions,
            'severity': self.severity,
            'alert_type': self.alert_type,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<AlertRule {self.name}>'
