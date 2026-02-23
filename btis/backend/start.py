#!/usr/bin/env python3
"""
BTIS Startup Script
Initializes and starts the Behavioral Threat Intelligence System
"""

import os
import sys
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_environment():
    """Setup environment and dependencies"""
    logger.info("Setting up BTIS environment...")
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('models/saved', exist_ok=True)
    os.makedirs('models/saved/users', exist_ok=True)
    
    logger.info("Environment setup complete")

def init_database():
    """Initialize database"""
    logger.info("Initializing database...")
    
    from app import app, db
    
    with app.app_context():
        db.create_all()
        logger.info("Database tables created")
        
        # Create admin user
        from utils.helpers import create_admin_user
        create_admin_user()

def train_initial_models():
    """Train initial ML models"""
    logger.info("Training initial ML models...")
    
    from app import app, ml_engine
    
    with app.app_context():
        ml_engine.initialize_models()
        logger.info("ML models initialized")

def start_server(host='0.0.0.0', port=5000, debug=False):
    """Start the BTIS server"""
    logger.info(f"Starting BTIS server on {host}:{port}...")
    
    from app import socketio, app
    
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=False
    )

def main():
    parser = argparse.ArgumentParser(description='BTIS - Behavioral Threat Intelligence System')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--setup', action='store_true', help='Run setup only')
    parser.add_argument('--init-db', action='store_true', help='Initialize database')
    
    args = parser.parse_args()
    
    # Setup environment
    setup_environment()
    
    # Initialize database if requested
    if args.init_db:
        init_database()
        return
    
    # Full setup
    init_database()
    train_initial_models()
    
    if args.setup:
        logger.info("Setup complete. Exiting.")
        return
    
    # Start server
    start_server(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()
