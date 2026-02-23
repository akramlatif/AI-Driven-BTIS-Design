# BTIS - Behavioral Threat Intelligence System

An AI-Driven cybersecurity platform for detecting insider threats and zero-day attacks through behavioral analysis.

## Overview

BTIS (Behavioral Threat Intelligence System) is an enterprise-grade Security Operations Center (SOC) solution that uses machine learning to detect anomalous user behavior, calculate dynamic risk scores, and generate real-time alerts for potential security threats.

## Key Features

### Core Capabilities
- **AI-Powered Anomaly Detection**: Uses Isolation Forest algorithm to detect behavioral anomalies
- **Dynamic Risk Scoring**: Multi-factor risk calculation (behavior, access, time, volume, privilege)
- **Real-Time Alerting**: WebSocket-based alert notifications with email integration
- **Behavior Profiling**: Establishes user baselines and detects deviations
- **SOC Dashboard**: Professional security operations center interface

### Security Features
- JWT-based authentication
- Role-based access control (Admin, Analyst, Operator)
- User session monitoring
- Account flagging and restriction
- Incident management workflow

### ML/AI Components
- **Isolation Forest**: Primary anomaly detection algorithm
- **User-Specific Models**: Personalized models for each user
- **Global Baseline Model**: Organization-wide behavior baseline
- **Feature Engineering**: 10 behavioral features analyzed
- **Risk Engine**: Weighted multi-factor risk scoring

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        BTIS Architecture                     │
├─────────────────────────────────────────────────────────────┤
│  Frontend (React + TypeScript + Tailwind CSS)               │
│  └── SOC Dashboard, Real-time Alerts, User Management       │
├─────────────────────────────────────────────────────────────┤
│  Flask Backend (REST API + WebSocket)                       │
│  ├── Authentication (JWT)                                   │
│  ├── Behavior Logging                                       │
│  ├── Risk Scoring Engine                                    │
│  └── Alert Management                                       │
├─────────────────────────────────────────────────────────────┤
│  AI/ML Layer                                                │
│  ├── Isolation Forest (Anomaly Detection)                   │
│  ├── Behavior Profiler                                      │
│  └── Threat Intelligence                                    │
├─────────────────────────────────────────────────────────────┤
│  Data Layer (SQLite/PostgreSQL)                             │
│  ├── Users & Profiles                                       │
│  ├── Behavior Logs                                          │
│  ├── Risk Scores                                            │
│  └── Alerts & Incidents                                     │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8+
- Node.js 18+
- pip
- npm

### Backend Setup

```bash
# Navigate to backend directory
cd btis/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database and create admin user
python start.py --init-db

# Start the server
python start.py
```

The backend will start on `http://localhost:5000`

### Frontend Setup

```bash
# Navigate to frontend directory
cd btis/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will start on `http://localhost:5173`

### Default Credentials
- **Username**: admin
- **Password**: admin123

> **Warning**: Change the default password in production!

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/verify` - Verify JWT token

### Dashboard
- `GET /api/dashboard/overview` - Dashboard overview data
- `GET /api/dashboard/metrics` - Time-series metrics
- `GET /api/dashboard/users-at-risk` - High-risk users
- `GET /api/dashboard/recent-alerts` - Recent alerts

### Behavior
- `POST /api/behavior/log` - Log behavior event
- `GET /api/behavior/profile/<user_id>` - Get user behavior profile
- `GET /api/behavior/timeline/<user_id>` - Get behavior timeline
- `POST /api/behavior/simulate` - Simulate behavior (demo)

### Alerts
- `GET /api/alerts/` - Get alerts with filtering
- `GET /api/alerts/<alert_id>` - Get alert details
- `POST /api/alerts/<alert_id>/acknowledge` - Acknowledge alert
- `POST /api/alerts/<alert_id>/resolve` - Resolve alert

### Users
- `GET /api/users/` - Get all users
- `GET /api/users/<user_id>` - Get user details
- `POST /api/users/` - Create new user
- `POST /api/users/<user_id>/flag` - Flag/unflag user

### ML
- `POST /api/ml/detect` - Run anomaly detection
- `POST /api/ml/train` - Train ML model
- `GET /api/ml/status` - Get model status

## Demo Scenarios

### Normal User Behavior
User `john.doe` demonstrates typical work patterns:
- Login during business hours (9 AM)
- Normal file access (10-30 files/day)
- Standard command usage
- Logout at end of day

### Insider Threat Simulation
User `malicious.user` exhibits suspicious behavior:
- After-hours login (2 AM)
- Mass file downloads (50+ sensitive files)
- Data export attempts
- Privilege escalation attempts
- Login from suspicious IP

## Risk Score Calculation

The risk engine calculates scores (0-100) based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Behavior | 30% | Anomaly detection results |
| Access | 20% | Sensitive resource access |
| Time | 15% | After-hours/weekend activity |
| Volume | 15% | Data transfer volumes |
| Privilege | 10% | Admin command usage |
| Threat Intel | 10% | External threat indicators |

### Risk Levels
- **Low**: 0-25
- **Medium**: 26-50
- **High**: 51-75
- **Critical**: 76-100

## Configuration

Edit `.env` file to configure:

```env
# Database
DATABASE_URL=sqlite:///btis.db

# Security
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Mail (for alerts)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email
MAIL_PASSWORD=your-password

# ML Settings
ANOMALY_THRESHOLD=50
RISK_CALCULATION_INTERVAL=300
```

## Technology Stack

### Backend
- **Flask**: Web framework
- **SQLAlchemy**: ORM
- **Flask-JWT-Extended**: Authentication
- **Flask-SocketIO**: Real-time communication
- **Scikit-learn**: Machine learning
- **Pandas**: Data processing

### Frontend
- **React**: UI framework
- **TypeScript**: Type safety
- **Tailwind CSS**: Styling
- **shadcn/ui**: Component library
- **Lucide React**: Icons

### ML/AI
- **Isolation Forest**: Anomaly detection
- **StandardScaler**: Feature scaling
- **PCA**: Dimensionality reduction (optional)

## Security Considerations

1. **Change default credentials** immediately after installation
2. Use **HTTPS** in production
3. Configure **CORS** appropriately
4. Set strong **SECRET_KEY** and **JWT_SECRET_KEY**
5. Enable **email alerts** for critical notifications
6. Regularly **retrain ML models** with new data

## Development

### Adding New Behavior Features

1. Update `feature_columns` in `modules/ml_engine.py`
2. Add feature extraction logic in `extract_features()`
3. Update behavior profiler to calculate new metrics

### Custom Alert Rules

Create alert rules via API:

```json
POST /api/alerts/rules
{
  "name": "High Volume Download",
  "condition_type": "threshold",
  "conditions": {
    "metric": "file_download_count",
    "operator": "gt",
    "threshold": 20
  },
  "severity": "high",
  "alert_type": "volume_spike"
}
```

## License

MIT License - See LICENSE file for details

## Support

For issues and feature requests, please create an issue in the repository.

---

**BTIS** - Protecting organizations through intelligent behavioral analysis
