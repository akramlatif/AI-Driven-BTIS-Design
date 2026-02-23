"""
Risk Score Models for BTIS
Dynamic risk scoring and factor analysis
"""

from datetime import datetime
from app import db

class RiskScore(db.Model):
    """Dynamic risk score for users"""
    __tablename__ = 'risk_scores'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Risk score (0-100)
    overall_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default='low')  # low, medium, high, critical
    
    # Component scores
    behavior_score = db.Column(db.Float, default=0.0)  # Based on behavior anomalies
    access_score = db.Column(db.Float, default=0.0)  # Based on access patterns
    time_score = db.Column(db.Float, default=0.0)  # Based on time-based anomalies
    volume_score = db.Column(db.Float, default=0.0)  # Based on data volume anomalies
    privilege_score = db.Column(db.Float, default=0.0)  # Based on privilege usage
    
    # Scoring metadata
    calculation_method = db.Column(db.String(50), default='ml_weighted')  # Algorithm used
    confidence = db.Column(db.Float, default=0.0)  # Confidence in the score (0-1)
    
    # Time window
    calculated_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    period_start = db.Column(db.DateTime, nullable=True)
    period_end = db.Column(db.DateTime, nullable=True)
    
    # Trend analysis
    previous_score = db.Column(db.Float, nullable=True)
    score_change = db.Column(db.Float, default=0.0)  # Change from previous
    trend_direction = db.Column(db.String(20), default='stable')  # increasing, decreasing, stable
    
    # Contributing factors (summary)
    top_factors = db.Column(db.JSON, default=list)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self, include_components=True):
        """Convert risk score to dictionary"""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else None,
            'overall_score': round(self.overall_score, 2),
            'risk_level': self.risk_level,
            'calculated_at': self.calculated_at.isoformat() if self.calculated_at else None,
            'confidence': round(self.confidence, 2),
            'trend_direction': self.trend_direction,
            'score_change': round(self.score_change, 2),
            'top_factors': self.top_factors
        }
        
        if include_components:
            data['components'] = {
                'behavior_score': round(self.behavior_score, 2),
                'access_score': round(self.access_score, 2),
                'time_score': round(self.time_score, 2),
                'volume_score': round(self.volume_score, 2),
                'privilege_score': round(self.privilege_score, 2)
            }
        
        return data
    
    @staticmethod
    def get_current_score(user_id):
        """Get the most recent risk score for a user"""
        return RiskScore.query.filter_by(user_id=user_id).order_by(
            RiskScore.calculated_at.desc()
        ).first()
    
    @staticmethod
    def get_score_history(user_id, hours=168):  # Default 7 days
        """Get risk score history for a user"""
        from datetime import timedelta
        
        since = datetime.utcnow() - timedelta(hours=hours)
        
        scores = RiskScore.query.filter(
            RiskScore.user_id == user_id,
            RiskScore.calculated_at >= since
        ).order_by(RiskScore.calculated_at.asc()).all()
        
        return [s.to_dict(include_components=False) for s in scores]
    
    @staticmethod
    def get_organization_risk():
        """Get organization-wide risk statistics"""
        from sqlalchemy import func
        
        # Latest scores for all users
        subquery = db.session.query(
            RiskScore.user_id,
            func.max(RiskScore.calculated_at).label('max_date')
        ).group_by(RiskScore.user_id).subquery()
        
        latest_scores = db.session.query(RiskScore).join(
            subquery,
            db.and_(
                RiskScore.user_id == subquery.c.user_id,
                RiskScore.calculated_at == subquery.c.max_date
            )
        ).all()
        
        # Calculate statistics
        if not latest_scores:
            return {
                'total_users': 0,
                'avg_score': 0,
                'max_score': 0,
                'by_level': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            }
        
        scores = [s.overall_score for s in latest_scores]
        by_level = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for s in latest_scores:
            by_level[s.risk_level] = by_level.get(s.risk_level, 0) + 1
        
        return {
            'total_users': len(latest_scores),
            'avg_score': round(sum(scores) / len(scores), 2),
            'max_score': round(max(scores), 2),
            'by_level': by_level
        }
    
    def __repr__(self):
        return f'<RiskScore user={self.user_id} score={self.overall_score}>'


class RiskFactor(db.Model):
    """Individual risk factors contributing to overall score"""
    __tablename__ = 'risk_factors'
    
    id = db.Column(db.Integer, primary_key=True)
    risk_score_id = db.Column(db.Integer, db.ForeignKey('risk_scores.id'), nullable=False)
    
    # Factor details
    factor_type = db.Column(db.String(50), nullable=False)  # time_anomaly, volume_spike, etc.
    factor_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Impact
    weight = db.Column(db.Float, default=1.0)  # Factor weight
    contribution = db.Column(db.Float, default=0.0)  # Contribution to score (0-100)
    severity = db.Column(db.String(20), default='low')  # low, medium, high
    
    # Evidence
    evidence = db.Column(db.JSON, default=dict)  # Supporting evidence
    related_logs = db.Column(db.JSON, default=list)  # Related log IDs
    
    # Mitigation
    is_mitigated = db.Column(db.Boolean, default=False)
    mitigation_action = db.Column(db.String(100), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'risk_score_id': self.risk_score_id,
            'factor_type': self.factor_type,
            'factor_name': self.factor_name,
            'description': self.description,
            'weight': self.weight,
            'contribution': round(self.contribution, 2),
            'severity': self.severity,
            'evidence': self.evidence,
            'is_mitigated': self.is_mitigated,
            'mitigation_action': self.mitigation_action,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<RiskFactor {self.factor_name} contribution={self.contribution}>'


class RiskThreshold(db.Model):
    """Configurable risk thresholds"""
    __tablename__ = 'risk_thresholds'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    
    # Threshold values
    low_threshold = db.Column(db.Float, default=25.0)
    medium_threshold = db.Column(db.Float, default=50.0)
    high_threshold = db.Column(db.Float, default=75.0)
    critical_threshold = db.Column(db.Float, default=90.0)
    
    # Actions at each level
    low_action = db.Column(db.String(50), default='log')
    medium_action = db.Column(db.String(50), default='alert')
    high_action = db.Column(db.String(50), default='notify_admin')
    critical_action = db.Column(db.String(50), default='block_account')
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'thresholds': {
                'low': self.low_threshold,
                'medium': self.medium_threshold,
                'high': self.high_threshold,
                'critical': self.critical_threshold
            },
            'actions': {
                'low': self.low_action,
                'medium': self.medium_action,
                'high': self.high_action,
                'critical': self.critical_action
            },
            'is_active': self.is_active
        }
    
    def get_level_for_score(self, score):
        """Get risk level for a given score"""
        if score >= self.critical_threshold:
            return 'critical'
        elif score >= self.high_threshold:
            return 'high'
        elif score >= self.medium_threshold:
            return 'medium'
        else:
            return 'low'
    
    def __repr__(self):
        return f'<RiskThreshold {self.name}>'
