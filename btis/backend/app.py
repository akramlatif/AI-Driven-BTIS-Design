"""
AI-Driven Behavioral Threat Intelligence System (BTIS)
Main Flask Application
Enterprise SOC Architecture for Insider Threat Detection
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_mail import Mail
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/btis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'btis-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///btis.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'btis-jwt-secret')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '').strip()
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '').replace(' ', '')

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
mail = Mail(app)

# Create logs directory
os.makedirs('logs', exist_ok=True)

# Import models and modules
from models.user import User, UserProfile
from models.behavior import BehaviorLog, BehaviorPattern
from models.alert import Alert, Incident
from models.risk import RiskScore, RiskFactor
from modules.ml_engine import MLEngine
from modules.behavior_profiler import BehaviorProfiler
from modules.risk_engine import RiskEngine
from modules.alert_manager import AlertManager
from modules.threat_intel import ThreatIntelligence

# Initialize core modules
ml_engine = MLEngine()
behavior_profiler = BehaviorProfiler()
risk_engine = RiskEngine()
alert_manager = AlertManager(mail, socketio)
threat_intel = ThreatIntelligence()

# Background scheduler for periodic tasks
scheduler = BackgroundScheduler()

def periodic_risk_assessment():
    """Run periodic risk assessment for all users"""
    with app.app_context():
        try:
            logger.info("Running periodic risk assessment...")
            users = User.query.filter_by(is_active=True).all()
            for user in users:
                risk_engine.calculate_user_risk(user.id)
            logger.info(f"Risk assessment completed for {len(users)} users")
        except Exception as e:
            logger.error(f"Error in periodic risk assessment: {str(e)}")

# Schedule periodic tasks
scheduler.add_job(
    func=periodic_risk_assessment,
    trigger="interval",
    minutes=5,
    id='risk_assessment',
    replace_existing=True
)

# Register blueprints
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.behavior import behavior_bp
from routes.alerts import alerts_bp
from routes.users import users_bp
from routes.ml import ml_bp

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
app.register_blueprint(behavior_bp, url_prefix='/api/behavior')
app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
app.register_blueprint(users_bp, url_prefix='/api/users')
app.register_blueprint(ml_bp, url_prefix='/api/ml')

from routes.simulation import simulation_bp
app.register_blueprint(simulation_bp, url_prefix='/api/simulation')

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'status': 'connected', 'timestamp': datetime.utcnow().isoformat()})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe_alerts')
def handle_subscribe_alerts():
    """Subscribe to real-time alerts"""
    logger.info(f"Client {request.sid} subscribed to alerts")
    emit('subscription_confirmed', {'channel': 'alerts'})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Server Error: {error}")
    return jsonify({'error': f'Internal server error: {error}'}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'components': {
            'database': 'connected',
            'ml_engine': 'ready',
            'risk_engine': 'active',
            'alert_system': 'operational'
        }
    })

# Initialize database and create demo data
@app.before_request
def initialize_system():
    """Initialize system on first request"""
    if not hasattr(app, '_initialized'):
        with app.app_context():
            db.create_all()
            
            # Create admin user if not exists
            from utils.helpers import create_admin_user
            create_admin_user()
            
            # Initialize ML models
            ml_engine.initialize_models()
            
            # Start scheduler
            scheduler.start()
            
            logger.info("BTIS System Initialized Successfully")
            app._initialized = True

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Run the application
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )
