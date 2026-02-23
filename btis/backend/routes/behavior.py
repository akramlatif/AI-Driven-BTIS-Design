"""
Behavior Routes for BTIS
Handles behavior logging, profiling, and analysis
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
behavior_bp = Blueprint('behavior', __name__)

@behavior_bp.route('/log', methods=['POST'])
@jwt_required()
def log_behavior():
    """Log a user behavior event"""
    try:
        from models.behavior import BehaviorLog
        from models.user import User
        from app import db, ml_engine, risk_engine, alert_manager
        
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Required fields
        action_type = data.get('action_type')
        if not action_type:
            return jsonify({'error': 'action_type is required'}), 400
        
        # Create behavior log
        behavior_log = BehaviorLog(
            user_id=user_id,
            action_type=action_type,
            action_subtype=data.get('action_subtype'),
            resource=data.get('resource'),
            resource_type=data.get('resource_type'),
            sensitivity_level=data.get('sensitivity_level', 'low'),
            ip_address=request.remote_addr or data.get('ip_address'),
            device_id=data.get('device_id'),
            session_id=data.get('session_id'),
            session_duration_minutes=data.get('session_duration_minutes'),
            raw_data=data.get('raw_data', {})
        )
        
        db.session.add(behavior_log)
        db.session.commit()
        
        # Run ML anomaly detection
        behavior_data = {
            'login_hour': datetime.utcnow().hour,
            'session_duration': behavior_log.session_duration_minutes or 0,
            'file_access_count': 1 if action_type == 'file_access' else 0,
            'command_count': 1 if action_type == 'command' else 0,
            'failed_login_count': 1 if action_type == 'failed_login' else 0,
            'sensitive_access_count': 1 if behavior_log.sensitivity_level in ['high', 'critical'] else 0,
            'data_export_count': 1 if action_type == 'data_export' else 0,
            'privilege_escalation_count': 1 if action_type == 'privilege_escalation' else 0,
            'after_hours_activity': 1 if datetime.utcnow().hour < 7 or datetime.utcnow().hour > 20 else 0,
            'weekend_activity': 1 if datetime.utcnow().weekday() >= 5 else 0
        }
        
        # Detect anomaly
        anomaly_result = ml_engine.detect_anomaly(behavior_data, user_id=user_id)
        
        # Update behavior log with anomaly info
        behavior_log.is_anomalous = anomaly_result['is_anomalous']
        behavior_log.anomaly_score = anomaly_result['anomaly_score']
        behavior_log.anomaly_features = anomaly_result.get('feature_contributions', {})
        behavior_log.processed = True
        
        db.session.commit()
        
        # If anomalous, trigger risk calculation
        if anomaly_result['is_anomalous'] and anomaly_result['anomaly_score'] > 50:
            risk_score = risk_engine.calculate_user_risk(user_id)
            
            # Check if alert should be created
            if risk_score and risk_score.risk_level in ['high', 'critical']:
                alert_manager.create_alert(
                    user_id=user_id,
                    alert_type='ml_anomaly',
                    severity=risk_score.risk_level,
                    title=f"Anomalous behavior detected for user {behavior_log.user.username}",
                    description=f"ML model detected anomalous {action_type} activity with score {anomaly_result['anomaly_score']:.1f}",
                    risk_score=risk_score.overall_score,
                    details={
                        'anomaly_result': anomaly_result,
                        'behavior_data': behavior_data
                    },
                    related_logs=[behavior_log.id]
                )
        
        return jsonify({
            'success': True,
            'log_id': behavior_log.id,
            'anomaly_detected': anomaly_result['is_anomalous'],
            'anomaly_score': anomaly_result['anomaly_score']
        }), 201
        
    except Exception as e:
        logger.error(f"Behavior log error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/profile/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    """Get comprehensive behavior profile for a user"""
    try:
        from modules.behavior_profiler import BehaviorProfiler
        
        hours = request.args.get('hours', 168, type=int)  # Default 7 days
        
        profiler = BehaviorProfiler()
        profile = profiler.profile_user(user_id, hours=hours)
        
        if 'error' in profile:
            return jsonify({'error': profile['error']}), 404
        
        return jsonify({
            'success': True,
            'profile': profile
        }), 200
        
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/timeline/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_timeline(user_id):
    """Get behavior timeline for a user"""
    try:
        from modules.behavior_profiler import BehaviorProfiler
        
        hours = request.args.get('hours', 24, type=int)
        
        profiler = BehaviorProfiler()
        timeline = profiler.get_behavior_timeline(user_id, hours=hours)
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'timeline': timeline
        }), 200
        
    except Exception as e:
        logger.error(f"Get timeline error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/baseline/<int:user_id>', methods=['POST'])
@jwt_required()
def establish_baseline(user_id):
    """Establish behavior baseline for a user"""
    try:
        from modules.behavior_profiler import BehaviorProfiler
        
        profiler = BehaviorProfiler()
        result = profiler.establish_baseline(user_id)
        
        if result.get('success'):
            return jsonify({
                'success': True,
                'message': 'Baseline established successfully',
                'data': result
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': result.get('message', 'Failed to establish baseline')
            }), 400
        
    except Exception as e:
        logger.error(f"Establish baseline error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/compare-baseline/<int:user_id>', methods=['GET'])
@jwt_required()
def compare_to_baseline(user_id):
    """Compare current behavior to baseline"""
    try:
        from modules.behavior_profiler import BehaviorProfiler
        from models.behavior import BehaviorPattern
        
        # Get recent patterns
        since = datetime.utcnow() - timedelta(days=1)
        patterns = BehaviorPattern.query.filter(
            BehaviorPattern.user_id == user_id,
            BehaviorPattern.date >= since.date()
        ).all()
        
        # Calculate current behavior metrics
        current_behavior = {
            'login_count': sum(p.login_count for p in patterns),
            'file_access_count': sum(p.file_access_count for p in patterns),
            'command_count': sum(p.command_count for p in patterns),
            'session_duration': sum(p.total_session_minutes for p in patterns),
            'anomaly_score': sum(p.avg_anomaly_score for p in patterns) / len(patterns) if patterns else 0
        }
        
        profiler = BehaviorProfiler()
        comparison = profiler.compare_to_baseline(user_id, current_behavior)
        
        return jsonify({
            'success': True,
            'comparison': comparison,
            'current_behavior': current_behavior
        }), 200
        
    except Exception as e:
        logger.error(f"Compare baseline error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/patterns/<int:user_id>', methods=['GET'])
@jwt_required()
def get_behavior_patterns(user_id):
    """Get behavior patterns for a user"""
    try:
        from models.behavior import BehaviorPattern
        
        days = request.args.get('days', 7, type=int)
        
        since = datetime.utcnow() - timedelta(days=days)
        
        patterns = BehaviorPattern.query.filter(
            BehaviorPattern.user_id == user_id,
            BehaviorPattern.date >= since.date()
        ).order_by(BehaviorPattern.date.desc(), BehaviorPattern.hour_start.desc()).all()
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'patterns': [p.to_dict() for p in patterns]
        }), 200
        
    except Exception as e:
        logger.error(f"Get patterns error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/logs/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_logs(user_id):
    """Get behavior logs for a user"""
    try:
        from models.behavior import BehaviorLog
        
        hours = request.args.get('hours', 24, type=int)
        action_type = request.args.get('action_type')
        limit = request.args.get('limit', 100, type=int)
        
        since = datetime.utcnow() - timedelta(hours=hours)
        
        query = BehaviorLog.query.filter(
            BehaviorLog.user_id == user_id,
            BehaviorLog.timestamp >= since
        )
        
        if action_type:
            query = query.filter_by(action_type=action_type)
        
        logs = query.order_by(BehaviorLog.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'logs': [log.to_dict(include_raw=True) for log in logs]
        }), 200
        
    except Exception as e:
        logger.error(f"Get logs error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@behavior_bp.route('/simulate', methods=['POST'])
@jwt_required()
def simulate_behavior():
    """Simulate behavior for testing/demo purposes"""
    try:
        from models.behavior import BehaviorLog
        from models.user import User
        from app import db
        
        data = request.get_json()
        user_id = data.get('user_id', get_jwt_identity())
        behavior_type = data.get('behavior_type', 'normal')
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate simulated behavior logs
        logs_created = []
        
        if behavior_type == 'normal':
            # Normal business hours login
            logs_created.append(create_behavior_log(user_id, 'login', {
                'ip_address': '10.0.1.100',
                'raw_data': {'location': 'office'}
            }))
            
            # Normal file access
            for i in range(5):
                logs_created.append(create_behavior_log(user_id, 'file_access', {
                    'resource': f'/docs/file{i}.pdf',
                    'sensitivity_level': 'low'
                }))
        
        elif behavior_type == 'insider_threat':
            # Suspicious after-hours login
            logs_created.append(create_behavior_log(user_id, 'login', {
                'ip_address': '203.0.113.25',
                'raw_data': {'location': 'external'}
            }))
            
            # Mass file download
            for i in range(50):
                logs_created.append(create_behavior_log(user_id, 'file_download', {
                    'resource': f'/confidential/doc{i}.pdf',
                    'sensitivity_level': 'critical'
                }))
            
            # Data export
            logs_created.append(create_behavior_log(user_id, 'data_export', {
                'resource': '/data/customer_database.csv',
                'sensitivity_level': 'critical'
            }))
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'behavior_type': behavior_type,
            'logs_created': len(logs_created)
        }), 200
        
    except Exception as e:
        logger.error(f"Simulate behavior error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def create_behavior_log(user_id, action_type, extra_data=None):
    """Helper function to create behavior logs"""
    from models.behavior import BehaviorLog
    from app import db
    
    log = BehaviorLog(
        user_id=user_id,
        action_type=action_type,
        ip_address=extra_data.get('ip_address') if extra_data else None,
        resource=extra_data.get('resource') if extra_data else None,
        sensitivity_level=extra_data.get('sensitivity_level', 'low') if extra_data else 'low',
        raw_data=extra_data.get('raw_data', {}) if extra_data else {}
    )
    db.session.add(log)
    return log
