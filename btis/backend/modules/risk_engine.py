"""
Risk Engine Module for BTIS
Calculates dynamic risk scores based on behavior, context, and threat intelligence
"""

import logging
from datetime import datetime, timedelta
import numpy as np

logger = logging.getLogger(__name__)

class RiskEngine:
    """
    Dynamic Risk Scoring Engine
    Combines multiple factors to calculate overall risk score
    """
    
    def __init__(self):
        # Risk weights (sum to 1.0)
        self.weights = {
            'behavior': 0.30,
            'access': 0.20,
            'time': 0.15,
            'volume': 0.15,
            'privilege': 0.10,
            'threat_intel': 0.10
        }
        
        # Risk thresholds
        self.thresholds = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 90
        }
        
        # Decay factors (per hour)
        self.decay_rate = 0.95
        
        logger.info("Risk Engine initialized")
    
    def calculate_user_risk(self, user_id, context=None):
        """
        Calculate comprehensive risk score for a user
        
        Args:
            user_id: User ID
            context: Optional additional context
        
        Returns:
            RiskScore object
        """
        from app import app
        from models.user import User, UserProfile
        from models.behavior import BehaviorLog, BehaviorPattern
        from models.risk import RiskScore, RiskFactor, RiskThreshold
        from models.alert import Alert
        from app import db
        
        with app.app_context():
            try:
                user = User.query.get(user_id)
                if not user:
                    return None
                
                # Get recent behavior data
                since = datetime.utcnow() - timedelta(hours=24)
                
                logs = BehaviorLog.query.filter(
                    BehaviorLog.user_id == user_id,
                    BehaviorLog.timestamp >= since
                ).all()
                
                patterns = BehaviorPattern.query.filter(
                    BehaviorPattern.user_id == user_id,
                    BehaviorPattern.date >= since.date()
                ).all()
                
                # Calculate component scores
                behavior_score = self._calculate_behavior_score(logs, patterns)
                access_score = self._calculate_access_score(logs)
                time_score = self._calculate_time_score(logs)
                volume_score = self._calculate_volume_score(logs)
                privilege_score = self._calculate_privilege_score(logs)
                threat_intel_score = self._calculate_threat_intel_score(user, logs, context)
                
                # Calculate weighted overall score
                overall_score = (
                    behavior_score * self.weights['behavior'] +
                    access_score * self.weights['access'] +
                    time_score * self.weights['time'] +
                    volume_score * self.weights['volume'] +
                    privilege_score * self.weights['privilege'] +
                    threat_intel_score * self.weights['threat_intel']
                )
                
                # Apply decay from previous score
                previous_score = self._get_previous_score(user_id)
                if previous_score:
                    hours_since = (datetime.utcnow() - previous_score.calculated_at).total_seconds() / 3600
                    decay_factor = self.decay_rate ** hours_since
                    overall_score = (overall_score * (1 - decay_factor)) + (previous_score.overall_score * decay_factor)
                
                # Ensure score is within bounds
                overall_score = max(0, min(100, overall_score))
                
                # Determine risk level
                risk_level = self._get_risk_level(overall_score)
                
                # Calculate trend
                trend_direction = 'stable'
                score_change = 0
                if previous_score:
                    score_change = overall_score - previous_score.overall_score
                    if score_change > 5:
                        trend_direction = 'increasing'
                    elif score_change < -5:
                        trend_direction = 'decreasing'
                
                # Create risk score record
                risk_score = RiskScore(
                    user_id=user_id,
                    overall_score=overall_score,
                    risk_level=risk_level,
                    behavior_score=behavior_score,
                    access_score=access_score,
                    time_score=time_score,
                    volume_score=volume_score,
                    privilege_score=privilege_score,
                    confidence=self._calculate_confidence(logs),
                    previous_score=previous_score.overall_score if previous_score else None,
                    score_change=score_change,
                    trend_direction=trend_direction,
                    period_start=since,
                    period_end=datetime.utcnow()
                )
                
                db.session.add(risk_score)
                db.session.flush()  # Get ID without committing
                
                # Generate risk factors
                risk_factors = self._generate_risk_factors(
                    risk_score.id, logs, patterns,
                    behavior_score, access_score, time_score, volume_score, privilege_score
                )
                
                # Update top factors
                risk_score.top_factors = [
                    {'type': f.factor_type, 'name': f.factor_name, 'contribution': f.contribution}
                    for f in sorted(risk_factors, key=lambda x: x.contribution, reverse=True)[:5]
                ]
                
                db.session.commit()
                
                logger.info(f"Calculated risk score for user {user_id}: {overall_score:.2f} ({risk_level})")
                
                # Trigger alert for high risk
                if risk_level in ['high', 'critical']:
                    from app import alert_manager
                    alert_manager.create_alert(
                        user_id=user_id,
                        alert_type='behavior_deviation',
                        severity=risk_level,
                        title=f"High Risk User Detected: {user.username}",
                        description=f"User risk score elevated to {overall_score:.1f}. Top factors: {', '.join([f['name'] for f in risk_score.top_factors])}",
                        risk_score=overall_score,
                        details={
                            'risk_score_id': risk_score.id,
                            'risk_factors': risk_score.top_factors
                        }
                    )
                    logger.info(f"Triggered high risk alert for user {user.username}")

                return risk_score
                
            except Exception as e:
                logger.error(f"Error calculating risk score: {str(e)}")
                db.session.rollback()
                return None
    
    def _calculate_behavior_score(self, logs, patterns):
        """Calculate behavior-based risk score"""
        if not logs:
            return 0
        
        # Anomaly-based scoring
        anomaly_scores = [log.anomaly_score for log in logs if log.anomaly_score > 0]
        if not anomaly_scores:
            return 0
        
        # Weight recent anomalies more heavily
        weighted_anomaly = np.mean(anomaly_scores) * (1 + len(anomaly_scores) / 10)
        
        # Count of anomalous events
        anomaly_count = sum(1 for log in logs if log.is_anomalous)
        anomaly_ratio = anomaly_count / len(logs) if logs else 0
        
        # Combine scores
        score = weighted_anomaly * (1 + anomaly_ratio)
        
        return min(100, score)
    
    def _calculate_access_score(self, logs):
        """Calculate access pattern risk score"""
        if not logs:
            return 0
        
        score = 0
        
        # Sensitive file access
        sensitive_access = [log for log in logs 
                           if log.sensitivity_level in ['high', 'critical']]
        score += len(sensitive_access) * 5
        
        # Unusual resource access
        file_access_logs = [log for log in logs if log.action_type == 'file_access']
        unique_resources = set(log.resource for log in file_access_logs if log.resource)
        if len(file_access_logs) > 0:
            uniqueness_ratio = len(unique_resources) / len(file_access_logs)
            if uniqueness_ratio > 0.8:  # Accessing many different files
                score += 20
        
        # Failed access attempts
        failed_access = [log for log in logs if log.action_type == 'access_denied']
        score += len(failed_access) * 10
        
        return min(100, score)
    
    def _calculate_time_score(self, logs):
        """Calculate time-based risk score"""
        if not logs:
            return 0
        
        score = 0
        
        # After-hours activity
        after_hours_logs = []
        weekend_logs = []
        
        for log in logs:
            hour = log.timestamp.hour
            weekday = log.timestamp.weekday()
            
            if hour < 7 or hour > 20:  # Before 7 AM or after 8 PM
                after_hours_logs.append(log)
            
            if weekday >= 5:  # Weekend
                weekend_logs.append(log)
        
        # Score based on after-hours ratio
        if logs:
            after_hours_ratio = len(after_hours_logs) / len(logs)
            score += after_hours_ratio * 30
            
            weekend_ratio = len(weekend_logs) / len(logs)
            score += weekend_ratio * 20
        
        # Unusual login times
        login_logs = [log for log in logs if log.action_type == 'login']
        for log in login_logs:
            hour = log.timestamp.hour
            if hour < 6 or hour > 22:  # Very unusual hours
                score += 15
        
        return min(100, score)
    
    def _calculate_volume_score(self, logs):
        """Calculate data volume risk score"""
        if not logs:
            return 0
        
        score = 0
        
        # File download volume
        download_logs = [log for log in logs if log.action_type == 'file_download']
        if len(download_logs) > 10:  # High download activity
            score += min(30, (len(download_logs) - 10) * 3)
        
        # Data export activity
        export_logs = [log for log in logs if log.action_type == 'data_export']
        score += len(export_logs) * 20
        
        # Command volume
        command_logs = [log for log in logs if log.action_type == 'command']
        if len(command_logs) > 100:  # Unusually high command activity
            score += min(20, (len(command_logs) - 100) * 0.5)
        
        # Spike detection (compare to recent average)
        if len(logs) > 50:  # Significant activity spike
            score += 15
        
        return min(100, score)
    
    def _calculate_privilege_score(self, logs):
        """Calculate privilege escalation risk score"""
        if not logs:
            return 0
        
        score = 0
        
        # Admin command usage
        admin_commands = [log for log in logs 
                         if log.action_type == 'command' and log.action_subtype == 'admin']
        score += len(admin_commands) * 5
        
        # Privilege escalation attempts
        priv_esc_logs = [log for log in logs if log.action_type == 'privilege_escalation']
        score += len(priv_esc_logs) * 25
        
        # Configuration changes
        config_changes = [log for log in logs if log.action_type == 'config_change']
        score += len(config_changes) * 10
        
        return min(100, score)
    
    def _calculate_threat_intel_score(self, user, logs, context):
        """Calculate threat intelligence-based risk score"""
        score = 0
        
        # Check if user is flagged
        if user.is_flagged:
            score += 30
        
        # Check for known malicious IPs
        if context and 'ip_reputation' in context:
            if context['ip_reputation'] == 'bad':
                score += 40
            elif context['ip_reputation'] == 'suspicious':
                score += 20
        
        # Failed login patterns
        failed_logins = user.failed_login_attempts if hasattr(user, 'failed_login_attempts') else 0
        if failed_logins > 5:
            score += min(30, (failed_logins - 5) * 5)
        
        # Check for known attack patterns
        attack_pattern_logs = [log for log in logs if log.action_subtype == 'suspicious_pattern']
        score += len(attack_pattern_logs) * 15
        
        return min(100, score)
    
    def _get_previous_score(self, user_id):
        """Get the most recent risk score for a user"""
        from models.risk import RiskScore
        
        return RiskScore.query.filter_by(user_id=user_id).order_by(
            RiskScore.calculated_at.desc()
        ).first()
    
    def _calculate_confidence(self, logs):
        """Calculate confidence level based on data quality"""
        if not logs:
            return 0.0
        
        # More data = higher confidence
        data_volume_score = min(1.0, len(logs) / 50)
        
        # Data diversity
        action_types = set(log.action_type for log in logs)
        diversity_score = min(1.0, len(action_types) / 5)
        
        # Recency
        if logs:
            latest_log = max(log.timestamp for log in logs)
            hours_since = (datetime.utcnow() - latest_log).total_seconds() / 3600
            recency_score = max(0, 1 - (hours_since / 24))
        else:
            recency_score = 0
        
        # Combine factors
        confidence = (data_volume_score * 0.4 + 
                     diversity_score * 0.3 + 
                     recency_score * 0.3)
        
        return round(confidence, 2)
    
    def _get_risk_level(self, score):
        """Determine risk level from score"""
        if score >= self.thresholds['critical']:
            return 'critical'
        elif score >= self.thresholds['high']:
            return 'high'
        elif score >= self.thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _generate_risk_factors(self, risk_score_id, logs, patterns, *component_scores):
        """Generate detailed risk factors"""
        from models.risk import RiskFactor
        from app import db
        
        factors = []
        factor_types = ['behavior', 'access', 'time', 'volume', 'privilege']
        
        for i, (factor_type, score) in enumerate(zip(factor_types, component_scores)):
            if score > 20:  # Only significant factors
                factor = RiskFactor(
                    risk_score_id=risk_score_id,
                    factor_type=factor_type,
                    factor_name=f'{factor_type}_anomaly',
                    description=f'Elevated {factor_type} risk detected',
                    contribution=score,
                    severity='high' if score > 50 else 'medium'
                )
                db.session.add(factor)
                factors.append(factor)
        
        # Add specific factors from logs
        if logs:
            # Time anomaly factor
            after_hours = [log for log in logs if log.timestamp.hour < 7 or log.timestamp.hour > 20]
            if after_hours:
                factor = RiskFactor(
                    risk_score_id=risk_score_id,
                    factor_type='time',
                    factor_name='after_hours_activity',
                    description=f'{len(after_hours)} after-hours activities detected',
                    contribution=min(30, len(after_hours) * 5),
                    severity='medium',
                    evidence={'count': len(after_hours)}
                )
                db.session.add(factor)
                factors.append(factor)
            
            # Sensitive access factor
            sensitive = [log for log in logs if log.sensitivity_level in ['high', 'critical']]
            if sensitive:
                factor = RiskFactor(
                    risk_score_id=risk_score_id,
                    factor_type='access',
                    factor_name='sensitive_file_access',
                    description=f'{len(sensitive)} sensitive resource accesses',
                    contribution=min(40, len(sensitive) * 8),
                    severity='high',
                    evidence={'resources': [log.resource for log in sensitive[:5]]}
                )
                db.session.add(factor)
                factors.append(factor)
        
        db.session.commit()
        return factors
    
    def get_risk_explanation(self, risk_score_id):
        """Get human-readable explanation of risk score"""
        from models.risk import RiskScore, RiskFactor
        
        risk_score = RiskScore.query.get(risk_score_id)
        if not risk_score:
            return None
        
        factors = RiskFactor.query.filter_by(risk_score_id=risk_score_id).all()
        
        explanation = {
            'overall_score': risk_score.overall_score,
            'risk_level': risk_score.risk_level,
            'confidence': risk_score.confidence,
            'summary': f"User has a {risk_score.risk_level} risk score of {risk_score.overall_score:.1f}",
            'key_factors': [],
            'recommendations': []
        }
        
        for factor in sorted(factors, key=lambda x: x.contribution, reverse=True)[:5]:
            explanation['key_factors'].append({
                'type': factor.factor_type,
                'name': factor.factor_name,
                'description': factor.description,
                'contribution': factor.contribution,
                'severity': factor.severity
            })
        
        # Generate recommendations
        if risk_score.risk_level in ['high', 'critical']:
            explanation['recommendations'].append('Immediate investigation required')
            explanation['recommendations'].append('Consider temporary access restriction')
        
        if risk_score.time_score > 50:
            explanation['recommendations'].append('Review after-hours access policies')
        
        if risk_score.access_score > 50:
            explanation['recommendations'].append('Audit sensitive file access permissions')
        
        if risk_score.volume_score > 50:
            explanation['recommendations'].append('Monitor for data exfiltration')
        
        return explanation
