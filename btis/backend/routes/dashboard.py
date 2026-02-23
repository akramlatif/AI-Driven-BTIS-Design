"""
Dashboard Routes for BTIS
Provides SOC dashboard data and real-time metrics
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import func
import logging

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/overview', methods=['GET'])
@jwt_required()
def get_overview():
    """Get dashboard overview data"""
    try:
        from models.user import User
        from models.alert import Alert
        from models.risk import RiskScore
        from models.behavior import BehaviorLog
        
        # Get time range (default last 24 hours)
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # User statistics
        total_users = User.query.filter_by(is_active=True).count()
        flagged_users = User.query.filter_by(is_flagged=True).count()
        active_users = UserSession.query.filter_by(is_active=True).count() if 'UserSession' in dir() else 0
        
        # Alert statistics
        alert_stats = Alert.get_stats(hours=hours)
        
        # Risk statistics
        risk_stats = RiskScore.get_organization_risk()
        
        # Recent activity
        recent_logs = BehaviorLog.query.filter(
            BehaviorLog.timestamp >= since
        ).order_by(BehaviorLog.timestamp.desc()).limit(10).all()
        
        # Critical alerts
        critical_alerts = Alert.query.filter(
            Alert.severity.in_(['high', 'critical']),
            Alert.status.in_(['new', 'acknowledged'])
        ).order_by(Alert.detected_at.desc()).limit(5).all()
        
        return jsonify({
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'period_hours': hours,
            'users': {
                'total': total_users,
                'active_now': active_users,
                'flagged': flagged_users,
                'flagged_percentage': round(flagged_users / total_users * 100, 2) if total_users > 0 else 0
            },
            'alerts': alert_stats,
            'risk': risk_stats,
            'recent_activity': [log.to_dict() for log in recent_logs],
            'critical_alerts': [alert.to_dict() for alert in critical_alerts]
        }), 200
        
    except Exception as e:
        logger.error(f"Dashboard overview error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/metrics', methods=['GET'])
@jwt_required()
def get_metrics():
    """Get time-series metrics for charts"""
    try:
        from models.alert import Alert
        from models.risk import RiskScore
        from models.behavior import BehaviorLog
        
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Alert timeline (hourly)
        alert_timeline = []
        for i in range(hours):
            hour_start = since + timedelta(hours=i)
            hour_end = since + timedelta(hours=i+1)
            
            count = Alert.query.filter(
                Alert.detected_at >= hour_start,
                Alert.detected_at < hour_end
            ).count()
            
            alert_timeline.append({
                'hour': hour_start.isoformat(),
                'count': count
            })
        
        # Risk score distribution
        risk_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        # Get latest risk score for each user
        subquery = db.session.query(
            RiskScore.user_id,
            func.max(RiskScore.calculated_at).label('max_date')
        ).group_by(RiskScore.user_id).subquery()
        
        latest_scores = RiskScore.query.join(
            subquery,
            db.and_(
                RiskScore.user_id == subquery.c.user_id,
                RiskScore.calculated_at == subquery.c.max_date
            )
        ).all()
        
        for score in latest_scores:
            risk_distribution[score.risk_level] = risk_distribution.get(score.risk_level, 0) + 1
        
        # Activity by type
        activity_by_type = db.session.query(
            BehaviorLog.action_type,
            func.count(BehaviorLog.id).label('count')
        ).filter(BehaviorLog.timestamp >= since).group_by(BehaviorLog.action_type).all()
        
        return jsonify({
            'success': True,
            'alert_timeline': alert_timeline,
            'risk_distribution': risk_distribution,
            'activity_by_type': [
                {'type': a.action_type, 'count': a.count}
                for a in activity_by_type
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"Metrics error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/users-at-risk', methods=['GET'])
@jwt_required()
def get_users_at_risk():
    """Get users with elevated risk scores"""
    try:
        from models.user import User
        from models.risk import RiskScore
        
        limit = request.args.get('limit', 10, type=int)
        min_risk = request.args.get('min_risk', 50, type=int)
        
        # Get users with high risk scores
        subquery = db.session.query(
            RiskScore.user_id,
            func.max(RiskScore.calculated_at).label('max_date')
        ).group_by(RiskScore.user_id).subquery()
        
        high_risk_users = db.session.query(User, RiskScore).join(
            RiskScore, User.id == RiskScore.user_id
        ).join(
            subquery,
            db.and_(
                RiskScore.user_id == subquery.c.user_id,
                RiskScore.calculated_at == subquery.c.max_date
            )
        ).filter(
            RiskScore.overall_score >= min_risk
        ).order_by(RiskScore.overall_score.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'users': [
                {
                    'user': user.to_dict(),
                    'risk_score': score.to_dict()
                }
                for user, score in high_risk_users
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"Users at risk error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/recent-alerts', methods=['GET'])
@jwt_required()
def get_recent_alerts():
    """Get recent alerts with filtering"""
    try:
        from models.alert import Alert
        
        # Query parameters
        severity = request.args.get('severity')
        status = request.args.get('status')
        limit = request.args.get('limit', 20, type=int)
        hours = request.args.get('hours', 24, type=int)
        
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query
        query = Alert.query.filter(Alert.detected_at >= since)
        
        if severity:
            query = query.filter_by(severity=severity)
        if status:
            query = query.filter_by(status=status)
        
        alerts = query.order_by(Alert.detected_at.desc()).limit(limit).all()
        
        return jsonify({
            'success': True,
            'alerts': [alert.to_dict(include_details=True) for alert in alerts],
            'total': query.count()
        }), 200
        
    except Exception as e:
        logger.error(f"Recent alerts error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/system-health', methods=['GET'])
@jwt_required()
def get_system_health():
    """Get system health status"""
    try:
        from app import ml_engine, risk_engine, alert_manager
        
        # Check database connection
        db_status = 'healthy'
        try:
            db.session.execute('SELECT 1')
        except:
            db_status = 'error'
        
        # Get ML model status
        ml_status = ml_engine.get_model_stats() if ml_engine.global_model else {'status': 'not_initialized'}
        
        # Get queue sizes (simulated)
        pending_alerts = Alert.query.filter_by(status='new').count()
        
        return jsonify({
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'database': db_status,
                'ml_engine': ml_status,
                'risk_engine': 'active',
                'alert_system': 'operational'
            },
            'queues': {
                'pending_alerts': pending_alerts
            },
            'overall_status': 'healthy' if db_status == 'healthy' else 'degraded'
        }), 200
        
    except Exception as e:
        logger.error(f"System health error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/activity-feed', methods=['GET'])
@jwt_required()
def get_activity_feed():
    """Get real-time activity feed"""
    try:
        from models.behavior import BehaviorLog
        from models.alert import Alert
        
        limit = request.args.get('limit', 50, type=int)
        
        # Get recent behavior logs and alerts
        logs = BehaviorLog.query.order_by(BehaviorLog.timestamp.desc()).limit(limit).all()
        
        # Combine into feed
        feed = []
        for log in logs:
            feed.append({
                'type': 'behavior',
                'timestamp': log.timestamp.isoformat(),
                'user_id': log.user_id,
                'username': log.user.username if log.user else 'Unknown',
                'action': log.action_type,
                'details': log.to_dict()
            })
        
        # Sort by timestamp
        feed.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'success': True,
            'feed': feed[:limit]
        }), 200
        
    except Exception as e:
        logger.error(f"Activity feed error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Import db at the end to avoid circular imports
from app import db
