"""
User Models for BTIS
Handles user authentication, profiles, and role management
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

# Note: db instance is created in app.py
from app import db

class User(db.Model):
    """User model for authentication and basic info"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='analyst')  # admin, analyst, operator
    department = db.Column(db.String(50), default='IT')
    is_active = db.Column(db.Boolean, default=True)
    is_flagged = db.Column(db.Boolean, default=False)
    flag_reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    login_count = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    profile = db.relationship('UserProfile', backref='user', uselist=False, cascade='all, delete-orphan')
    behavior_logs = db.relationship('BehaviorLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    risk_scores = db.relationship('RiskScore', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    alerts = db.relationship('Alert', foreign_keys='Alert.user_id', back_populates='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        """Verify user password"""
        return check_password_hash(self.password_hash, password)
    
    def record_login(self, success=True):
        """Record login attempt"""
        if success:
            self.last_login = datetime.utcnow()
            self.login_count += 1
            self.failed_login_attempts = 0
        else:
            self.failed_login_attempts += 1
            self.last_failed_login = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'department': self.department,
            'is_active': self.is_active,
            'is_flagged': self.is_flagged,
            'flag_reason': self.flag_reason,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'login_count': self.login_count,
            'failed_login_attempts': self.failed_login_attempts
        }
        
        if include_sensitive:
            data['last_failed_login'] = self.last_failed_login.isoformat() if self.last_failed_login else None
        
        return data
    
    def __repr__(self):
        return f'<User {self.username}>'


class UserProfile(db.Model):
    """Extended user profile for behavior baseline"""
    __tablename__ = 'user_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    
    # Baseline behavior patterns
    avg_login_hour = db.Column(db.Float, default=9.0)  # Average login hour (0-23)
    std_login_hour = db.Column(db.Float, default=1.0)  # Standard deviation
    avg_session_duration = db.Column(db.Float, default=480)  # Average session in minutes
    std_session_duration = db.Column(db.Float, default=60)
    avg_files_accessed_per_day = db.Column(db.Float, default=50)
    std_files_accessed = db.Column(db.Float, default=20)
    avg_commands_per_session = db.Column(db.Float, default=100)
    std_commands_per_session = db.Column(db.Float, default=30)
    
    # Working days pattern (bitmask: Mon=1, Tue=2, Wed=4, etc.)
    typical_work_days = db.Column(db.Integer, default=31)  # Mon-Fri = 31
    
    # Risk baseline
    baseline_risk_score = db.Column(db.Float, default=10.0)
    risk_trend = db.Column(db.String(10), default='stable')  # increasing, decreasing, stable
    
    # ML features
    feature_vector = db.Column(db.JSON, default=list)  # Stored feature vector for ML
    last_model_update = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert profile to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'avg_login_hour': self.avg_login_hour,
            'std_login_hour': self.std_login_hour,
            'avg_session_duration': self.avg_session_duration,
            'std_session_duration': self.std_session_duration,
            'avg_files_accessed_per_day': self.avg_files_accessed_per_day,
            'std_files_accessed': self.std_files_accessed,
            'avg_commands_per_session': self.avg_commands_per_session,
            'std_commands_per_session': self.std_commands_per_session,
            'typical_work_days': self.typical_work_days,
            'baseline_risk_score': self.baseline_risk_score,
            'risk_trend': self.risk_trend,
            'last_model_update': self.last_model_update.isoformat() if self.last_model_update else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<UserProfile user_id={self.user_id}>'


class UserSession(db.Model):
    """Active user sessions for real-time monitoring"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 support
    user_agent = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Session metrics
    commands_executed = db.Column(db.Integer, default=0)
    files_accessed = db.Column(db.Integer, default=0)
    sensitive_files_accessed = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'location': self.location,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'is_active': self.is_active,
            'duration_minutes': (datetime.utcnow() - self.started_at).total_seconds() / 60 if self.started_at else 0,
            'commands_executed': self.commands_executed,
            'files_accessed': self.files_accessed,
            'sensitive_files_accessed': self.sensitive_files_accessed
        }
    
    def __repr__(self):
        return f'<UserSession user_id={self.user_id}>'
