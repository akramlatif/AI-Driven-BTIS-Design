"""
Utility Helpers for BTIS
"""

import os
import logging
from datetime import datetime
from app import db

logger = logging.getLogger(__name__)

def create_admin_user():
    """Create default admin user if not exists"""
    from models.user import User, UserProfile
    
    try:
        # Check if admin exists
        admin = User.query.filter_by(username='admin').first()
        
        if not admin:
            # Create admin user
            admin = User(
                username='admin',
                email='admin@btis.local',
                role='admin',
                department='Security',
                is_active=True
            )
            admin.set_password('admin123')  # Change in production!
            
            db.session.add(admin)
            db.session.flush()
            
            # Create profile
            profile = UserProfile(user_id=admin.id)
            db.session.add(profile)
            
            db.session.commit()
            
            logger.info("Created default admin user")
            
            # Create demo users
            create_demo_users()
            
        return True
        
    except Exception as e:
        logger.error(f"Error creating admin user: {str(e)}")
        print(f"CRITICAL ERROR creating admin user: {str(e)}")  # Force print to stdout
        db.session.rollback()
        return False


def create_demo_users():
    """Create demo users for testing"""
    from models.user import User, UserProfile
    
    demo_users = [
        {
            'username': 'john.doe',
            'email': 'john.doe@company.com',
            'role': 'analyst',
            'department': 'Finance'
        },
        {
            'username': 'jane.smith',
            'email': 'jane.smith@company.com',
            'role': 'analyst',
            'department': 'HR'
        },
        {
            'username': 'bob.wilson',
            'email': 'bob.wilson@company.com',
            'role': 'operator',
            'department': 'IT'
        },
        {
            'username': 'alice.brown',
            'email': 'alice.brown@company.com',
            'role': 'analyst',
            'department': 'Engineering'
        },
        {
            'username': 'malicious.user',
            'email': 'suspicious@external.com',
            'role': 'analyst',
            'department': 'Contractor'
        }
    ]
    
    try:
        for user_data in demo_users:
            existing = User.query.filter_by(username=user_data['username']).first()
            if not existing:
                user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    role=user_data['role'],
                    department=user_data['department'],
                    is_active=True
                )
                user.set_password('password123')
                
                db.session.add(user)
                db.session.flush()
                
                profile = UserProfile(user_id=user.id)
                db.session.add(profile)
                
                logger.info(f"Created demo user: {user_data['username']}")
        
        db.session.commit()
        
        # Generate demo behavior data
        generate_demo_behavior()
        
    except Exception as e:
        logger.error(f"Error creating demo users: {str(e)}")
        db.session.rollback()


def generate_demo_behavior():
    """Generate demo behavior data"""
    from models.user import User
    from models.behavior import BehaviorLog
    from datetime import timedelta
    import random
    
    try:
        users = User.query.filter(User.username != 'admin').all()
        
        # Generate normal behavior for most users
        for user in users[:4]:  # First 4 users - normal behavior
            generate_normal_behavior(user.id)
        
        # Generate suspicious behavior for last user
        if len(users) >= 5:
            generate_suspicious_behavior(users[4].id)
        
        logger.info("Generated demo behavior data")
        
    except Exception as e:
        logger.error(f"Error generating demo behavior: {str(e)}")


def generate_normal_behavior(user_id):
    """Generate normal behavior patterns"""
    from models.behavior import BehaviorLog
    from datetime import timedelta
    import random
    
    now = datetime.utcnow()
    
    # Generate login during business hours
    login_time = now - timedelta(days=1, hours=2)
    login_time = login_time.replace(hour=9, minute=random.randint(0, 59))
    
    log = BehaviorLog(
        user_id=user_id,
        action_type='login',
        ip_address=f'10.0.1.{random.randint(10, 100)}',
        timestamp=login_time,
        is_anomalous=False,
        anomaly_score=random.uniform(0, 15),
        processed=True
    )
    db.session.add(log)
    
    # Generate file accesses
    for i in range(random.randint(10, 30)):
        file_log = BehaviorLog(
            user_id=user_id,
            action_type='file_access',
            resource=f'/docs/document_{i}.pdf',
            sensitivity_level='low',
            timestamp=login_time + timedelta(minutes=random.randint(1, 480)),
            is_anomalous=False,
            anomaly_score=random.uniform(0, 10),
            processed=True
        )
        db.session.add(file_log)
    
    # Generate commands
    for i in range(random.randint(20, 50)):
        cmd_log = BehaviorLog(
            user_id=user_id,
            action_type='command',
            action_subtype='user',
            timestamp=login_time + timedelta(minutes=random.randint(1, 480)),
            is_anomalous=False,
            anomaly_score=random.uniform(0, 8),
            processed=True
        )
        db.session.add(cmd_log)
    
    # Logout
    logout_log = BehaviorLog(
        user_id=user_id,
        action_type='logout',
        timestamp=login_time + timedelta(hours=random.randint(7, 9)),
        session_duration_minutes=random.randint(420, 540),
        is_anomalous=False,
        anomaly_score=random.uniform(0, 5),
        processed=True
    )
    db.session.add(logout_log)
    
    db.session.commit()


def generate_suspicious_behavior(user_id):
    """Generate suspicious behavior patterns"""
    from models.behavior import BehaviorLog
    from datetime import timedelta
    import random
    
    now = datetime.utcnow()
    
    # Suspicious after-hours login
    login_time = now - timedelta(hours=6)
    login_time = login_time.replace(hour=2, minute=random.randint(0, 59))  # 2 AM
    
    log = BehaviorLog(
        user_id=user_id,
        action_type='login',
        ip_address='203.0.113.25',  # Suspicious IP
        timestamp=login_time,
        is_anomalous=True,
        anomaly_score=random.uniform(60, 80),
        anomaly_features={'login_hour': 2.5, 'after_hours_activity': 1},
        processed=True
    )
    db.session.add(log)
    
    # Mass file downloads of sensitive files
    for i in range(50):  # Much higher than normal
        file_log = BehaviorLog(
            user_id=user_id,
            action_type='file_download',
            resource=f'/confidential/customer_data_{i}.csv',
            sensitivity_level='critical',
            timestamp=login_time + timedelta(minutes=random.randint(1, 60)),
            is_anomalous=True,
            anomaly_score=random.uniform(70, 95),
            anomaly_features={'file_access_count': 50, 'sensitive_access_count': 50},
            processed=True
        )
        db.session.add(file_log)
    
    # Data export
    export_log = BehaviorLog(
        user_id=user_id,
        action_type='data_export',
        resource='/data/financial_records.zip',
        sensitivity_level='critical',
        timestamp=login_time + timedelta(minutes=45),
        is_anomalous=True,
        anomaly_score=85.5,
        anomaly_features={'data_export_count': 1, 'sensitive_access_count': 1},
        processed=True
    )
    db.session.add(export_log)
    
    # Failed privilege escalation
    priv_log = BehaviorLog(
        user_id=user_id,
        action_type='privilege_escalation',
        resource='sudo su -',
        timestamp=login_time + timedelta(minutes=30),
        is_anomalous=True,
        anomaly_score=90.0,
        anomaly_features={'privilege_escalation_count': 1},
        processed=True
    )
    db.session.add(priv_log)
    
    db.session.commit()
    
    # Create risk score and alert for this user
    create_demo_alert(user_id)


def create_demo_alert(user_id):
    """Create demo alert for suspicious user"""
    from models.alert import Alert
    from models.risk import RiskScore
    from models.user import User
    
    try:
        # Create risk score
        risk_score = RiskScore(
            user_id=user_id,
            overall_score=87.5,
            risk_level='high',
            behavior_score=85.0,
            access_score=90.0,
            time_score=80.0,
            volume_score=95.0,
            privilege_score=85.0,
            confidence=0.85,
            trend_direction='increasing',
            top_factors=[
                {'type': 'time', 'name': 'after_hours_activity', 'contribution': 80},
                {'type': 'volume', 'name': 'mass_file_download', 'contribution': 95},
                {'type': 'access', 'name': 'sensitive_file_access', 'contribution': 90}
            ]
        )
        db.session.add(risk_score)
        db.session.commit()
        
        # Create alert
        user = User.query.get(user_id)
        
        alert = Alert(
            alert_id=Alert.generate_alert_id(),
            user_id=user_id,
            severity='high',
            category='insider_threat',
            alert_type='behavior_deviation',
            title=f'Potential Insider Threat: {user.username}',
            description=f'User {user.username} exhibited multiple suspicious behaviors including after-hours access, mass file downloads, and data export attempts.',
            risk_score=87.5,
            risk_factors=[
                {'type': 'time_anomaly', 'description': 'Login at 2:00 AM'},
                {'type': 'volume_spike', 'description': 'Downloaded 50+ sensitive files'},
                {'type': 'data_exfiltration', 'description': 'Attempted data export'}
            ],
            evidence=[
                {'type': 'login_log', 'timestamp': (datetime.utcnow() - timedelta(hours=6)).isoformat(), 'details': 'Login from suspicious IP'},
                {'type': 'file_access', 'count': 50, 'sensitivity': 'critical'}
            ],
            status='new',
            detected_at=datetime.utcnow()
        )
        db.session.add(alert)
        db.session.commit()
        
        logger.info(f"Created demo alert for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error creating demo alert: {str(e)}")
        db.session.rollback()


def format_datetime(dt):
    """Format datetime for display"""
    if not dt:
        return None
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def calculate_time_diff(start, end):
    """Calculate time difference in minutes"""
    if not start or not end:
        return 0
    diff = end - start
    return int(diff.total_seconds() / 60)


def sanitize_input(text):
    """Sanitize user input"""
    if not text:
        return ''
    # Remove potentially dangerous characters
    import re
    return re.sub(r'[<>&"\']', '', str(text))


def generate_report_filename(report_type, extension='pdf'):
    """Generate standardized report filename"""
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    return f"btis_{report_type}_{timestamp}.{extension}"
