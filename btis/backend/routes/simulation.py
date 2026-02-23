from flask import Blueprint, jsonify
import logging
from app import db
from modules.risk_engine import RiskEngine
from utils.helpers import generate_suspicious_behavior

simulation_bp = Blueprint('simulation', __name__)
logger = logging.getLogger(__name__)

@simulation_bp.route('/insider-threat', methods=['POST'])
def simulate_insider_threat():
    """
    Simulate an insider threat scenario for the demo user (malicious.user)
    Triggers generation of suspicious logs and immediate risk score update
    """
    try:
        from models.user import User
        
        # Find the malicious user or create if not exists
        user = User.query.filter_by(username='malicious.user').first()
        
        if not user:
            return jsonify({'error': 'Demo user malicious.user not found'}), 404
            
        logger.info(f"Starting insider threat simulation for user {user.username}")
        
        # 1. Inject suspicious behavior (Mass download, After hours login)
        generate_suspicious_behavior(user.id)
        
        # 2. Force immediate risk calculation
        risk_engine = RiskEngine()
        risk_score = risk_engine.calculate_user_risk(user.id)
        
        if risk_score:
            logger.info(f"Simulation complete. New risk score: {risk_score.overall_score}")
            return jsonify({
                'success': True,
                'message': 'Insider threat simulation completed',
                'user': user.username,
                'new_risk_score': risk_score.overall_score,
                'risk_level': risk_score.risk_level
            }), 200
        else:
            return jsonify({'error': 'Failed to calculate risk score'}), 500
            
    except Exception as e:
        logger.error(f"Simulation error: {str(e)}")
        return jsonify({'error': str(e)}), 500
