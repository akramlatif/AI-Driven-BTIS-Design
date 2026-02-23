"""
User Management Routes for BTIS
Handles user CRUD operations and user-specific data
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
users_bp = Blueprint('users', __name__)

@users_bp.route('/', methods=['GET'])
@jwt_required()
def get_users():
    """Get all users with filtering"""
    try:
        from models.user import User
        
        # Query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        role = request.args.get('role')
        is_active = request.args.get('is_active')
        is_flagged = request.args.get('is_flagged')
        
        # Build query
        query = User.query
        
        if role:
            query = query.filter_by(role=role)
        if is_active is not None:
            query = query.filter_by(is_active=is_active.lower() == 'true')
        if is_flagged is not None:
            query = query.filter_by(is_flagged=is_flagged.lower() == 'true')
        
        # Order by created_at
        query = query.order_by(User.created_at.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get user details"""
    try:
        from models.user import User, UserProfile
        from models.risk import RiskScore
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user profile
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        
        # Get current risk score
        risk_score = RiskScore.get_current_score(user_id)
        
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'profile': profile.to_dict() if profile else None,
            'risk_score': risk_score.to_dict() if risk_score else None
        }), 200
        
    except Exception as e:
        logger.error(f"Get user error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/', methods=['POST'])
@jwt_required()
def create_user():
    """Create new user"""
    try:
        from models.user import User, UserProfile
        from app import db
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Required fields
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password required'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409
        
        # Create user
        user = User(
            username=username,
            email=email,
            role=data.get('role', 'analyst'),
            department=data.get('department', 'IT'),
            is_active=data.get('is_active', True)
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create user profile
        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        
        db.session.commit()
        
        logger.info(f"Created user: {username}")
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Create user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@users_bp.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Update user"""
    try:
        from models.user import User
        from app import db
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update fields
        if 'email' in data:
            # Check if email is taken
            existing = User.query.filter_by(email=data['email']).first()
            if existing and existing.id != user_id:
                return jsonify({'error': 'Email already exists'}), 409
            user.email = data['email']
        
        if 'role' in data:
            user.role = data['role']
        
        if 'department' in data:
            user.department = data['department']
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        if 'password' in data:
            user.set_password(data['password'])
        
        db.session.commit()
        
        logger.info(f"Updated user: {user_id}")
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@users_bp.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete user (soft delete by deactivating)"""
    try:
        from models.user import User
        from app import db
        
        current_user_id = get_jwt_identity()
        
        # Prevent self-deletion
        if user_id == current_user_id:
            return jsonify({'error': 'Cannot delete yourself'}), 400
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Soft delete - deactivate
        user.is_active = False
        db.session.commit()
        
        logger.info(f"Deactivated user: {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'User deactivated successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Delete user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@users_bp.route('/<int:user_id>/flag', methods=['POST'])
@jwt_required()
def flag_user(user_id):
    """Flag/unflag user account"""
    try:
        from models.user import User
        from app import db
        
        data = request.get_json() or {}
        
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        is_flagged = data.get('is_flagged', True)
        reason = data.get('reason', 'Manual flag by admin')
        
        user.is_flagged = is_flagged
        user.flag_reason = reason if is_flagged else None
        
        db.session.commit()
        
        action = 'flagged' if is_flagged else 'unflagged'
        logger.info(f"User {user_id} {action}: {reason}")
        
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'action': action
        }), 200
        
    except Exception as e:
        logger.error(f"Flag user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@users_bp.route('/<int:user_id>/risk-history', methods=['GET'])
@jwt_required()
def get_user_risk_history(user_id):
    """Get risk score history for user"""
    try:
        from models.risk import RiskScore
        
        hours = request.args.get('hours', 168, type=int)  # Default 7 days
        
        history = RiskScore.get_score_history(user_id, hours=hours)
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'history': history
        }), 200
        
    except Exception as e:
        logger.error(f"Get risk history error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    try:
        from models.user import User
        
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Get current user error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/me/activity', methods=['GET'])
@jwt_required()
def get_my_activity():
    """Get current user's activity summary"""
    try:
        from models.behavior import BehaviorLog
        
        user_id = get_jwt_identity()
        hours = request.args.get('hours', 24, type=int)
        
        summary = BehaviorLog.get_user_activity_summary(user_id, hours=hours)
        
        return jsonify({
            'success': True,
            'activity': summary
        }), 200
        
    except Exception as e:
        logger.error(f"Get my activity error: {str(e)}")
        return jsonify({'error': str(e)}), 500
