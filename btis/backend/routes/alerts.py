"""
Alert Routes for BTIS
Handles alert management and incident response
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
@jwt_required()
def get_alerts():
    """Get alerts with filtering and pagination"""
    try:
        from models.alert import Alert
        
        # Query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        severity = request.args.get('severity')
        status = request.args.get('status')
        category = request.args.get('category')
        user_id = request.args.get('user_id', type=int)
        
        # Build query
        query = Alert.query
        
        if severity:
            query = query.filter_by(severity=severity)
        if status:
            query = query.filter_by(status=status)
        if category:
            query = query.filter_by(category=category)
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        # Order by detected_at descending
        query = query.order_by(Alert.detected_at.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'alerts': [alert.to_dict(include_details=True) for alert in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get alerts error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/<alert_id>', methods=['GET'])
@jwt_required()
def get_alert(alert_id):
    """Get single alert details"""
    try:
        from models.alert import Alert
        
        alert = Alert.query.filter_by(alert_id=alert_id).first()
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        return jsonify({
            'success': True,
            'alert': alert.to_dict(include_details=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Get alert error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/<alert_id>/acknowledge', methods=['POST'])
@jwt_required()
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        from modules.alert_manager import AlertManager
        from app import alert_manager
        
        user_id = get_jwt_identity()
        
        result = alert_manager.acknowledge_alert(alert_id, user_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Acknowledge alert error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/<alert_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_alert(alert_id):
    """Resolve an alert"""
    try:
        from modules.alert_manager import AlertManager
        from app import alert_manager
        
        data = request.get_json() or {}
        resolution = data.get('resolution', 'Resolved by analyst')
        resolution_type = data.get('resolution_type', 'confirmed_threat')
        
        result = alert_manager.resolve_alert(alert_id, resolution, resolution_type)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Resolve alert error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/<alert_id>/escalate', methods=['POST'])
@jwt_required()
def escalate_alert(alert_id):
    """Escalate an alert"""
    try:
        from app import alert_manager
        
        result = alert_manager.escalate_alert(alert_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Escalate alert error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/<alert_id>/incident', methods=['POST'])
@jwt_required()
def create_incident(alert_id):
    """Create incident from alert"""
    try:
        from app import alert_manager
        
        result = alert_manager.create_incident(alert_id)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Create incident error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_alert_stats():
    """Get alert statistics"""
    try:
        from app import alert_manager
        
        hours = request.args.get('hours', 24, type=int)
        
        stats = alert_manager.get_alert_stats(hours=hours)
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Get alert stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/incidents', methods=['GET'])
@jwt_required()
def get_incidents():
    """Get incidents"""
    try:
        from models.alert import Incident
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status')
        
        query = Incident.query
        
        if status:
            query = query.filter_by(status=status)
        
        query = query.order_by(Incident.detected_at.desc())
        
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'incidents': [inc.to_dict(include_details=True) for inc in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get incidents error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/incidents/<incident_id>', methods=['GET'])
@jwt_required()
def get_incident(incident_id):
    """Get incident details"""
    try:
        from models.alert import Incident
        
        incident = Incident.query.filter_by(incident_id=incident_id).first()
        
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        
        return jsonify({
            'success': True,
            'incident': incident.to_dict(include_details=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Get incident error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/incidents/<incident_id>/update', methods=['POST'])
@jwt_required()
def update_incident(incident_id):
    """Update incident status"""
    try:
        from models.alert import Incident
        from app import db
        
        data = request.get_json() or {}
        incident = Incident.query.filter_by(incident_id=incident_id).first()
        
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        
        # Update fields
        if 'status' in data:
            incident.status = data['status']
            if data['status'] == 'contained':
                incident.contained_at = datetime.utcnow()
            elif data['status'] == 'resolved':
                incident.resolved_at = datetime.utcnow()
        
        if 'containment_actions' in data:
            incident.containment_actions.extend(data['containment_actions'])
        
        if 'eradication_actions' in data:
            incident.eradication_actions.extend(data['eradication_actions'])
        
        if 'recovery_actions' in data:
            incident.recovery_actions.extend(data['recovery_actions'])
        
        if 'post_incident_report' in data:
            incident.post_incident_report = data['post_incident_report']
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'incident': incident.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Update incident error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/rules', methods=['GET'])
@jwt_required()
def get_alert_rules():
    """Get alert rules"""
    try:
        from models.alert import AlertRule
        
        rules = AlertRule.query.all()
        
        return jsonify({
            'success': True,
            'rules': [rule.to_dict() for rule in rules]
        }), 200
        
    except Exception as e:
        logger.error(f"Get alert rules error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@alerts_bp.route('/rules', methods=['POST'])
@jwt_required()
def create_alert_rule():
    """Create new alert rule"""
    try:
        from models.alert import AlertRule
        from app import db
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = get_jwt_identity()
        
        rule = AlertRule(
            name=data.get('name'),
            description=data.get('description'),
            condition_type=data.get('condition_type'),
            conditions=data.get('conditions'),
            severity=data.get('severity', 'medium'),
            alert_type=data.get('alert_type'),
            is_active=data.get('is_active', True),
            created_by=user_id
        )
        
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'rule': rule.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Create alert rule error: {str(e)}")
        return jsonify({'error': str(e)}), 500
