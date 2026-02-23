"""
BTIS API Routes Package
"""

from .auth import auth_bp
from .dashboard import dashboard_bp
from .behavior import behavior_bp
from .alerts import alerts_bp
from .users import users_bp
from .ml import ml_bp

__all__ = [
    'auth_bp',
    'dashboard_bp',
    'behavior_bp',
    'alerts_bp',
    'users_bp',
    'ml_bp'
]
