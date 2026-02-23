"""
Behavior Models for BTIS
Tracks user behavior patterns and activity logs
"""

from datetime import datetime
from app import db

class BehaviorLog(db.Model):
    """Detailed behavior log for each user action"""
    __tablename__ = 'behavior_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Action details
    action_type = db.Column(db.String(50), nullable=False, index=True)
    # login, logout, file_access, file_download, command, privilege_escalation, 
    # data_export, config_change, network_access, etc.
    
    action_subtype = db.Column(db.String(50), nullable=True)
    # For file_access: read, write, delete, copy
    # For command: admin, user, system
    
    # Context
    resource = db.Column(db.String(255), nullable=True)  # File path, command, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # file, directory, database, etc.
    sensitivity_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    
    # Network context
    ip_address = db.Column(db.String(45), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    device_id = db.Column(db.String(100), nullable=True)
    
    # Session context
    session_id = db.Column(db.String(255), nullable=True)
    session_duration_minutes = db.Column(db.Float, nullable=True)
    
    # Anomaly detection
    is_anomalous = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float, default=0.0)  # 0-100
    anomaly_features = db.Column(db.JSON, default=dict)  # Features that triggered anomaly
    
    # Risk contribution
    risk_contribution = db.Column(db.Float, default=0.0)
    
    # Raw data for analysis
    raw_data = db.Column(db.JSON, default=dict)
    
    # Metadata
    processed = db.Column(db.Boolean, default=False)  # Whether processed by ML
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self, include_raw=False):
        """Convert behavior log to dictionary"""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'action_type': self.action_type,
            'action_subtype': self.action_subtype,
            'resource': self.resource,
            'resource_type': self.resource_type,
            'sensitivity_level': self.sensitivity_level,
            'ip_address': self.ip_address,
            'location': self.location,
            'device_id': self.device_id,
            'session_id': self.session_id,
            'session_duration_minutes': self.session_duration_minutes,
            'is_anomalous': self.is_anomalous,
            'anomaly_score': self.anomaly_score,
            'anomaly_features': self.anomaly_features,
            'risk_contribution': self.risk_contribution,
            'processed': self.processed,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        if include_raw:
            data['raw_data'] = self.raw_data
        
        return data
    
    @staticmethod
    def get_user_activity_summary(user_id, hours=24):
        """Get activity summary for a user"""
        from sqlalchemy import func
        
        since = datetime.utcnow() - __import__('datetime').timedelta(hours=hours)
        
        summary = db.session.query(
            BehaviorLog.action_type,
            func.count(BehaviorLog.id).label('count'),
            func.avg(BehaviorLog.anomaly_score).label('avg_anomaly')
        ).filter(
            BehaviorLog.user_id == user_id,
            BehaviorLog.timestamp >= since
        ).group_by(BehaviorLog.action_type).all()
        
        return {
            'user_id': user_id,
            'period_hours': hours,
            'activities': [
                {
                    'action_type': s.action_type,
                    'count': s.count,
                    'avg_anomaly_score': round(s.avg_anomaly or 0, 2)
                }
                for s in summary
            ]
        }
    
    def __repr__(self):
        return f'<BehaviorLog user={self.user_id} action={self.action_type}>'


class BehaviorPattern(db.Model):
    """Aggregated behavior patterns for ML training"""
    __tablename__ = 'behavior_patterns'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Time window
    date = db.Column(db.Date, nullable=False, index=True)
    hour_start = db.Column(db.Integer, nullable=False)  # 0-23
    
    # Aggregated metrics
    login_count = db.Column(db.Integer, default=0)
    logout_count = db.Column(db.Integer, default=0)
    file_access_count = db.Column(db.Integer, default=0)
    file_download_count = db.Column(db.Integer, default=0)
    command_count = db.Column(db.Integer, default=0)
    admin_command_count = db.Column(db.Integer, default=0)
    sensitive_access_count = db.Column(db.Integer, default=0)
    data_export_count = db.Column(db.Integer, default=0)
    
    # Session metrics
    total_session_minutes = db.Column(db.Float, default=0)
    avg_session_minutes = db.Column(db.Float, default=0)
    
    # Anomaly metrics
    anomaly_count = db.Column(db.Integer, default=0)
    max_anomaly_score = db.Column(db.Float, default=0)
    avg_anomaly_score = db.Column(db.Float, default=0)
    
    # Feature vector for ML (pre-computed)
    feature_vector = db.Column(db.JSON, default=list)
    
    # Labels for supervised learning
    is_baseline = db.Column(db.Boolean, default=False)  # Known normal behavior
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert pattern to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'date': self.date.isoformat() if self.date else None,
            'hour_start': self.hour_start,
            'login_count': self.login_count,
            'logout_count': self.logout_count,
            'file_access_count': self.file_access_count,
            'file_download_count': self.file_download_count,
            'command_count': self.command_count,
            'admin_command_count': self.admin_command_count,
            'sensitive_access_count': self.sensitive_access_count,
            'data_export_count': self.data_export_count,
            'total_session_minutes': self.total_session_minutes,
            'avg_session_minutes': self.avg_session_minutes,
            'anomaly_count': self.anomaly_count,
            'max_anomaly_score': self.max_anomaly_score,
            'avg_anomaly_score': self.avg_anomaly_score,
            'feature_vector': self.feature_vector,
            'is_baseline': self.is_baseline,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @staticmethod
    def get_recent_patterns(user_id, days=7):
        """Get recent behavior patterns for a user"""
        from datetime import date, timedelta
        
        since = date.today() - timedelta(days=days)
        
        patterns = BehaviorPattern.query.filter(
            BehaviorPattern.user_id == user_id,
            BehaviorPattern.date >= since
        ).order_by(BehaviorPattern.date.desc(), BehaviorPattern.hour_start.desc()).all()
        
        return [p.to_dict() for p in patterns]
    
    def __repr__(self):
        return f'<BehaviorPattern user={self.user_id} date={self.date}>'


class BehaviorBaseline(db.Model):
    """Stored baseline behavior for anomaly detection"""
    __tablename__ = 'behavior_baselines'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Baseline statistics
    baseline_data = db.Column(db.JSON, default=dict)
    # Stores: mean, std, min, max for each feature
    
    # Training metadata
    training_samples = db.Column(db.Integer, default=0)
    training_start = db.Column(db.DateTime, nullable=True)
    training_end = db.Column(db.DateTime, nullable=True)
    
    # Model performance
    false_positive_rate = db.Column(db.Float, default=0.0)
    detection_rate = db.Column(db.Float, default=0.0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'baseline_data': self.baseline_data,
            'training_samples': self.training_samples,
            'training_start': self.training_start.isoformat() if self.training_start else None,
            'training_end': self.training_end.isoformat() if self.training_end else None,
            'false_positive_rate': self.false_positive_rate,
            'detection_rate': self.detection_rate,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<BehaviorBaseline user={self.user_id}>'
