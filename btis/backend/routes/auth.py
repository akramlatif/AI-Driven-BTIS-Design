"""
Authentication Routes for BTIS
Handles user login, logout, and token management
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from models.user import User, UserSession
from app import db
import logging

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            # Log failed login attempt
            logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.failed_login_attempts >= 5:
            last_failed = user.last_failed_login
            if last_failed and (datetime.utcnow() - last_failed).total_seconds() < 1800:
                logger.warning(f"Locked account login attempt: {username}")
                return jsonify({'error': 'Account temporarily locked. Try again later.'}), 403
        
        # Verify password
        if not user.check_password(password):
            user.record_login(success=False)
            logger.warning(f"Failed login for user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if user is flagged
        if user.is_flagged:
            logger.warning(f"Flagged user login attempt: {username}")
            # Still allow login but log it
        
        # Record successful login
        user.record_login(success=True)
        
        # Create session
        import uuid
        session_token = str(uuid.uuid4())
        
        # Get client info
        ip_address = request.remote_addr or 'unknown'
        user_agent = request.headers.get('User-Agent', 'unknown')
        
        session = UserSession(
            user_id=user.id,
            session_token=session_token,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True
        )
        db.session.add(session)
        db.session.commit()
        
        # Create JWT token
        access_token = create_access_token(
            identity=user.id,
            additional_claims={
                'username': user.username,
                'role': user.role,
                'session_token': session_token
            }
        )
        
        # Log behavior
        from modules.behavior_profiler import BehaviorProfiler
        profiler = BehaviorProfiler()
        
        # Create behavior log
        from models.behavior import BehaviorLog
        behavior_log = BehaviorLog(
            user_id=user.id,
            action_type='login',
            ip_address=ip_address,
            device_id=user_agent[:100] if user_agent else None,
            session_id=session_token,
            raw_data={
                'login_method': 'password',
                'user_agent': user_agent
            }
        )
        db.session.add(behavior_log)
        db.session.commit()
        
        logger.info(f"Successful login for user: {username}")
        
        return jsonify({
            'success': True,
            'access_token': access_token,
            'token_type': 'Bearer',
            'user': user.to_dict(),
            'session_token': session_token
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user and invalidate session"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}
        session_token = data.get('session_token')
        
        # Deactivate session
        if session_token:
            session = UserSession.query.filter_by(
                session_token=session_token,
                user_id=user_id
            ).first()
            
            if session:
                session.is_active = False
                
                # Log logout behavior
                from models.behavior import BehaviorLog
                behavior_log = BehaviorLog(
                    user_id=user_id,
                    action_type='logout',
                    session_id=session_token,
                    session_duration_minutes=(datetime.utcnow() - session.started_at).total_seconds() / 60
                )
                db.session.add(behavior_log)
                db.session.commit()
        
        logger.info(f"User {user_id} logged out")
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    """Verify JWT token validity"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.is_active:
            return jsonify({'error': 'User account is disabled'}), 403
        
        return jsonify({
            'valid': True,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        return jsonify({'error': 'Invalid token'}), 401

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password required'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log password change
        from models.behavior import BehaviorLog
        behavior_log = BehaviorLog(
            user_id=user_id,
            action_type='config_change',
            action_subtype='password_change',
            resource='account'
        )
        db.session.add(behavior_log)
        db.session.commit()
        
        logger.info(f"Password changed for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auth_bp.route('/sessions', methods=['GET'])
@jwt_required()
def get_sessions():
    """Get active sessions for current user"""
    try:
        user_id = get_jwt_identity()
        
        sessions = UserSession.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()
        
        return jsonify({
            'sessions': [s.to_dict() for s in sessions]
        }), 200
        
    except Exception as e:
        logger.error(f"Get sessions error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
