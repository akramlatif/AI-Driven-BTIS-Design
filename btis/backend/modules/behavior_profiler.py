"""
Behavior Profiler Module for BTIS
Analyzes and profiles user behavior patterns
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)

class BehaviorProfiler:
    """
    Profiles user behavior and establishes baselines
    Tracks login patterns, session behavior, file access, and command usage
    """
    
    def __init__(self):
        self.baseline_window_days = 14  # Days to establish baseline
        self.min_samples_for_baseline = 10
        logger.info("Behavior Profiler initialized")
    
    def profile_user(self, user_id, hours=168):
        """
        Generate comprehensive behavior profile for a user
        
        Args:
            user_id: User ID to profile
            hours: Lookback period in hours (default 7 days)
        
        Returns:
            dict with behavior profile
        """
        from app import app
        from models.user import User, UserProfile
        from models.behavior import BehaviorLog
        
        with app.app_context():
            try:
                user = User.query.get(user_id)
                if not user:
                    return {'error': 'User not found'}
                
                since = datetime.utcnow() - timedelta(hours=hours)
                
                # Get behavior logs
                logs = BehaviorLog.query.filter(
                    BehaviorLog.user_id == user_id,
                    BehaviorLog.timestamp >= since
                ).order_by(BehaviorLog.timestamp.asc()).all()
                
                if not logs:
                    return {
                        'user_id': user_id,
                        'username': user.username,
                        'period_hours': hours,
                        'error': 'No behavior data available'
                    }
                
                # Analyze different aspects
                login_profile = self._analyze_login_patterns(logs)
                session_profile = self._analyze_session_patterns(logs)
                file_profile = self._analyze_file_access(logs)
                command_profile = self._analyze_command_usage(logs)
                time_profile = self._analyze_time_patterns(logs)
                
                # Combine into comprehensive profile
                profile = {
                    'user_id': user_id,
                    'username': user.username,
                    'period_hours': hours,
                    'total_events': len(logs),
                    'login_patterns': login_profile,
                    'session_patterns': session_profile,
                    'file_access_patterns': file_profile,
                    'command_patterns': command_profile,
                    'time_patterns': time_profile,
                    'anomaly_count': sum(1 for log in logs if log.is_anomalous),
                    'avg_anomaly_score': round(
                        sum(log.anomaly_score for log in logs) / len(logs), 2
                    ) if logs else 0,
                    'generated_at': datetime.utcnow().isoformat()
                }
                
                # Update or create user profile
                self._update_user_profile(user_id, profile)
                
                return profile
                
            except Exception as e:
                logger.error(f"Error profiling user {user_id}: {str(e)}")
                return {'error': str(e)}
    
    def _analyze_login_patterns(self, logs):
        """Analyze login patterns"""
        login_logs = [log for log in logs if log.action_type == 'login']
        failed_logins = [log for log in logs if log.action_type == 'failed_login']
        
        if not login_logs:
            return {
                'total_logins': 0,
                'failed_attempts': len(failed_logins),
                'success_rate': 0,
                'typical_login_hours': [],
                'login_hour_variance': 0
            }
        
        # Extract login hours
        login_hours = [log.timestamp.hour + log.timestamp.minute/60 
                      for log in login_logs]
        
        # Calculate statistics
        avg_hour = np.mean(login_hours)
        std_hour = np.std(login_hours) if len(login_hours) > 1 else 0
        
        # Most common login hours
        hour_counts = defaultdict(int)
        for h in login_hours:
            hour_counts[int(h)] += 1
        typical_hours = sorted(hour_counts.keys(), key=lambda x: hour_counts[x], reverse=True)[:3]
        
        return {
            'total_logins': len(login_logs),
            'failed_attempts': len(failed_logins),
            'success_rate': round(len(login_logs) / (len(login_logs) + len(failed_logins)) * 100, 2),
            'typical_login_hours': typical_hours,
            'avg_login_hour': round(avg_hour, 2),
            'login_hour_variance': round(std_hour, 2),
            'unique_ips': len(set(log.ip_address for log in login_logs if log.ip_address))
        }
    
    def _analyze_session_patterns(self, logs):
        """Analyze session patterns"""
        session_logs = [log for log in logs if log.session_duration_minutes]
        
        if not session_logs:
            return {
                'total_sessions': 0,
                'avg_duration_minutes': 0,
                'max_duration_minutes': 0,
                'min_duration_minutes': 0
            }
        
        durations = [log.session_duration_minutes for log in session_logs]
        
        return {
            'total_sessions': len(session_logs),
            'avg_duration_minutes': round(np.mean(durations), 2),
            'max_duration_minutes': round(max(durations), 2),
            'min_duration_minutes': round(min(durations), 2),
            'duration_variance': round(np.std(durations), 2) if len(durations) > 1 else 0
        }
    
    def _analyze_file_access(self, logs):
        """Analyze file access patterns"""
        file_logs = [log for log in logs if log.action_type == 'file_access']
        download_logs = [log for log in logs if log.action_type == 'file_download']
        sensitive_logs = [log for log in logs if log.sensitivity_level in ['high', 'critical']]
        
        if not file_logs:
            return {
                'total_accesses': 0,
                'downloads': 0,
                'sensitive_accesses': 0,
                'access_pattern': 'none'
            }
        
        # Analyze access pattern
        timestamps = [log.timestamp for log in file_logs]
        if len(timestamps) > 1:
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() / 60 
                        for i in range(len(timestamps)-1)]
            avg_interval = np.mean(intervals)
            
            if avg_interval < 1:
                pattern = 'rapid'
            elif avg_interval < 5:
                pattern = 'normal'
            else:
                pattern = 'sparse'
        else:
            pattern = 'single'
        
        # File types accessed
        file_types = defaultdict(int)
        for log in file_logs:
            if log.resource:
                ext = log.resource.split('.')[-1] if '.' in log.resource else 'unknown'
                file_types[ext] += 1
        
        return {
            'total_accesses': len(file_logs),
            'downloads': len(download_logs),
            'sensitive_accesses': len(sensitive_logs),
            'access_pattern': pattern,
            'unique_resources': len(set(log.resource for log in file_logs if log.resource)),
            'file_type_distribution': dict(file_types),
            'avg_access_per_hour': round(len(file_logs) / 24, 2)  # Assuming 24-hour window
        }
    
    def _analyze_command_usage(self, logs):
        """Analyze command usage patterns"""
        command_logs = [log for log in logs if log.action_type == 'command']
        admin_logs = [log for log in command_logs if log.action_subtype == 'admin']
        
        if not command_logs:
            return {
                'total_commands': 0,
                'admin_commands': 0,
                'admin_ratio': 0
            }
        
        return {
            'total_commands': len(command_logs),
            'admin_commands': len(admin_logs),
            'admin_ratio': round(len(admin_logs) / len(command_logs) * 100, 2),
            'unique_commands': len(set(log.resource for log in command_logs if log.resource))
        }
    
    def _analyze_time_patterns(self, logs):
        """Analyze time-based patterns"""
        timestamps = [log.timestamp for log in logs]
        
        if not timestamps:
            return {
                'after_hours_activity': 0,
                'weekend_activity': 0,
                'business_hours_activity': 0
            }
        
        # Define business hours (9 AM - 6 PM)
        business_hours_count = 0
        after_hours_count = 0
        weekend_count = 0
        
        for ts in timestamps:
            # Check weekend (5=Saturday, 6=Sunday)
            if ts.weekday() >= 5:
                weekend_count += 1
            
            # Check business hours
            if 9 <= ts.hour < 18:
                business_hours_count += 1
            else:
                after_hours_count += 1
        
        total = len(timestamps)
        
        return {
            'after_hours_activity': round(after_hours_count / total * 100, 2),
            'weekend_activity': round(weekend_count / total * 100, 2),
            'business_hours_activity': round(business_hours_count / total * 100, 2),
            'peak_activity_hour': self._get_peak_hour(timestamps)
        }
    
    def _get_peak_hour(self, timestamps):
        """Get the hour with most activity"""
        hour_counts = defaultdict(int)
        for ts in timestamps:
            hour_counts[ts.hour] += 1
        
        if hour_counts:
            return max(hour_counts.keys(), key=lambda x: hour_counts[x])
        return None
    
    def _update_user_profile(self, user_id, profile):
        """Update user profile in database"""
        from models.user import UserProfile
        from app import db
        
        try:
            user_profile = UserProfile.query.filter_by(user_id=user_id).first()
            
            if not user_profile:
                user_profile = UserProfile(user_id=user_id)
                db.session.add(user_profile)
            
            # Update with new profile data
            login_patterns = profile.get('login_patterns', {})
            session_patterns = profile.get('session_patterns', {})
            file_patterns = profile.get('file_access_patterns', {})
            command_patterns = profile.get('command_patterns', {})
            time_patterns = profile.get('time_patterns', {})
            
            user_profile.avg_login_hour = login_patterns.get('avg_login_hour', 9.0)
            user_profile.std_login_hour = login_patterns.get('login_hour_variance', 1.0)
            user_profile.avg_session_duration = session_patterns.get('avg_duration_minutes', 480)
            user_profile.std_session_duration = session_patterns.get('duration_variance', 60)
            user_profile.avg_files_accessed_per_day = file_patterns.get('total_accesses', 50) / 7
            user_profile.avg_commands_per_session = command_patterns.get('total_commands', 100)
            
            # Update feature vector for ML
            user_profile.feature_vector = [
                login_patterns.get('avg_login_hour', 9.0),
                session_patterns.get('avg_duration_minutes', 480),
                file_patterns.get('total_accesses', 0),
                command_patterns.get('total_commands', 0),
                login_patterns.get('failed_attempts', 0),
                file_patterns.get('sensitive_accesses', 0),
                0,  # data_export_count
                command_patterns.get('admin_commands', 0),
                time_patterns.get('after_hours_activity', 0),
                time_patterns.get('weekend_activity', 0)
            ]
            
            user_profile.updated_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Updated profile for user {user_id}")
            
        except Exception as e:
            logger.error(f"Error updating user profile: {str(e)}")
            db.session.rollback()
    
    def establish_baseline(self, user_id):
        """
        Establish behavior baseline for a user
        Requires sufficient historical data
        """
        from app import app
        from models.behavior import BehaviorBaseline, BehaviorPattern
        from app import db
        
        with app.app_context():
            try:
                # Get historical patterns
                since = datetime.utcnow() - timedelta(days=self.baseline_window_days)
                
                patterns = BehaviorPattern.query.filter(
                    BehaviorPattern.user_id == user_id,
                    BehaviorPattern.date >= since.date()
                ).all()
                
                if len(patterns) < self.min_samples_for_baseline:
                    return {
                        'success': False,
                        'message': f'Insufficient data. Need {self.min_samples_for_baseline} samples, got {len(patterns)}'
                    }
                
                # Calculate baseline statistics
                baseline_data = self._calculate_baseline_stats(patterns)
                
                # Save baseline
                baseline = BehaviorBaseline.query.filter_by(user_id=user_id).first()
                if not baseline:
                    baseline = BehaviorBaseline(user_id=user_id)
                    db.session.add(baseline)
                
                baseline.baseline_data = baseline_data
                baseline.training_samples = len(patterns)
                baseline.training_start = datetime.combine(
                    min(p.date for p in patterns), datetime.min.time()
                )
                baseline.training_end = datetime.combine(
                    max(p.date for p in patterns), datetime.min.time()
                )
                baseline.updated_at = datetime.utcnow()
                
                db.session.commit()
                
                logger.info(f"Established baseline for user {user_id}")
                
                return {
                    'success': True,
                    'baseline_data': baseline_data,
                    'samples_used': len(patterns)
                }
                
            except Exception as e:
                logger.error(f"Error establishing baseline: {str(e)}")
                db.session.rollback()
                return {'success': False, 'error': str(e)}
    
    def _calculate_baseline_stats(self, patterns):
        """Calculate baseline statistics from patterns"""
        
        def calc_stats(values):
            if not values:
                return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
            return {
                'mean': round(np.mean(values), 2),
                'std': round(np.std(values), 2) if len(values) > 1 else 0,
                'min': round(min(values), 2),
                'max': round(max(values), 2)
            }
        
        # Extract metrics
        login_counts = [p.login_count for p in patterns]
        file_counts = [p.file_access_count for p in patterns]
        command_counts = [p.command_count for p in patterns]
        session_durations = [p.total_session_minutes for p in patterns]
        anomaly_scores = [p.avg_anomaly_score for p in patterns]
        
        return {
            'login_count': calc_stats(login_counts),
            'file_access_count': calc_stats(file_counts),
            'command_count': calc_stats(command_counts),
            'session_duration': calc_stats(session_durations),
            'anomaly_score': calc_stats(anomaly_scores),
            'established_at': datetime.utcnow().isoformat()
        }
    
    def compare_to_baseline(self, user_id, current_behavior):
        """
        Compare current behavior to established baseline
        Returns deviation metrics
        """
        from app import app
        from models.behavior import BehaviorBaseline
        
        with app.app_context():
            try:
                baseline = BehaviorBaseline.query.filter_by(user_id=user_id).first()
                
                if not baseline or not baseline.baseline_data:
                    return {
                        'has_baseline': False,
                        'deviations': {}
                    }
                
                baseline_data = baseline.baseline_data
                deviations = {}
                
                # Compare each metric
                for metric, stats in baseline_data.items():
                    if metric == 'established_at':
                        continue
                    
                    current_value = current_behavior.get(metric, 0)
                    mean = stats.get('mean', 0)
                    std = stats.get('std', 0)
                    
                    if std > 0:
                        z_score = (current_value - mean) / std
                        deviation_percent = ((current_value - mean) / mean * 100) if mean > 0 else 0
                    else:
                        z_score = 0
                        deviation_percent = 0
                    
                    deviations[metric] = {
                        'current': current_value,
                        'baseline_mean': mean,
                        'z_score': round(z_score, 2),
                        'deviation_percent': round(deviation_percent, 2),
                        'is_anomalous': abs(z_score) > 2  # 2 sigma
                    }
                
                return {
                    'has_baseline': True,
                    'deviations': deviations,
                    'overall_deviation': round(
                        np.mean([abs(d['z_score']) for d in deviations.values()]), 2
                    )
                }
                
            except Exception as e:
                logger.error(f"Error comparing to baseline: {str(e)}")
                return {'error': str(e)}
    
    def get_behavior_timeline(self, user_id, hours=24):
        """Get behavior timeline for visualization"""
        from app import app
        from models.behavior import BehaviorLog
        
        with app.app_context():
            try:
                since = datetime.utcnow() - timedelta(hours=hours)
                
                logs = BehaviorLog.query.filter(
                    BehaviorLog.user_id == user_id,
                    BehaviorLog.timestamp >= since
                ).order_by(BehaviorLog.timestamp.asc()).all()
                
                timeline = []
                for log in logs:
                    timeline.append({
                        'timestamp': log.timestamp.isoformat(),
                        'action_type': log.action_type,
                        'action_subtype': log.action_subtype,
                        'resource': log.resource,
                        'sensitivity_level': log.sensitivity_level,
                        'is_anomalous': log.is_anomalous,
                        'anomaly_score': log.anomaly_score,
                        'risk_contribution': log.risk_contribution
                    })
                
                return timeline
                
            except Exception as e:
                logger.error(f"Error getting behavior timeline: {str(e)}")
                return []
