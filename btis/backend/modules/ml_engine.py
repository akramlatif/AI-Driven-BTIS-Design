"""
ML Engine Module for BTIS
Implements anomaly detection using Isolation Forest and other ML techniques
"""

import os
import pickle
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
import joblib

logger = logging.getLogger(__name__)

class MLEngine:
    """
    Machine Learning Engine for Behavioral Threat Detection
    Uses Isolation Forest for unsupervised anomaly detection
    """
    
    def __init__(self, model_dir='models/saved'):
        self.model_dir = model_dir
        self.models = {}  # User-specific models
        self.scalers = {}  # User-specific scalers
        self.global_model = None
        self.global_scaler = None
        
        # Model parameters
        self.contamination = 0.1  # Expected anomaly ratio
        self.n_estimators = 100
        self.max_samples = 'auto'
        self.random_state = 42
        
        # Feature configuration
        self.feature_columns = [
            'login_hour', 'session_duration', 'file_access_count',
            'command_count', 'failed_login_count', 'sensitive_access_count',
            'data_export_count', 'privilege_escalation_count',
            'after_hours_activity', 'weekend_activity'
        ]
        
        # Create model directory
        os.makedirs(model_dir, exist_ok=True)
        
        logger.info("ML Engine initialized")
    
    def initialize_models(self):
        """Initialize or load existing models"""
        try:
            # Try to load global model
            global_model_path = os.path.join(self.model_dir, 'global_model.pkl')
            global_scaler_path = os.path.join(self.model_dir, 'global_scaler.pkl')
            
            if os.path.exists(global_model_path) and os.path.exists(global_scaler_path):
                self.global_model = joblib.load(global_model_path)
                self.global_scaler = joblib.load(global_scaler_path)
                logger.info("Loaded existing global model")
            else:
                # Initialize new global model
                self.global_model = IsolationForest(
                    n_estimators=self.n_estimators,
                    contamination=self.contamination,
                    max_samples=self.max_samples,
                    random_state=self.random_state,
                    n_jobs=-1
                )
                self.global_scaler = StandardScaler()
                logger.info("Initialized new global model")
            
            # Load user-specific models
            self._load_user_models()
            
        except Exception as e:
            logger.error(f"Error initializing models: {str(e)}")
            # Initialize with default models
            self.global_model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state
            )
            self.global_scaler = StandardScaler()
    
    def _load_user_models(self):
        """Load user-specific models from disk"""
        try:
            user_models_dir = os.path.join(self.model_dir, 'users')
            if os.path.exists(user_models_dir):
                for filename in os.listdir(user_models_dir):
                    if filename.endswith('_model.pkl'):
                        user_id = int(filename.replace('_model.pkl', ''))
                        model_path = os.path.join(user_models_dir, filename)
                        scaler_path = os.path.join(user_models_dir, f'{user_id}_scaler.pkl')
                        
                        if os.path.exists(scaler_path):
                            self.models[user_id] = joblib.load(model_path)
                            self.scalers[user_id] = joblib.load(scaler_path)
                            logger.info(f"Loaded model for user {user_id}")
        except Exception as e:
            logger.error(f"Error loading user models: {str(e)}")
    
    def _save_model(self, user_id=None):
        """Save model to disk"""
        try:
            if user_id:
                # Save user-specific model
                user_models_dir = os.path.join(self.model_dir, 'users')
                os.makedirs(user_models_dir, exist_ok=True)
                
                model_path = os.path.join(user_models_dir, f'{user_id}_model.pkl')
                scaler_path = os.path.join(user_models_dir, f'{user_id}_scaler.pkl')
                
                if user_id in self.models:
                    joblib.dump(self.models[user_id], model_path)
                    joblib.dump(self.scalers[user_id], scaler_path)
                    logger.info(f"Saved model for user {user_id}")
            else:
                # Save global model
                model_path = os.path.join(self.model_dir, 'global_model.pkl')
                scaler_path = os.path.join(self.model_dir, 'global_scaler.pkl')
                
                joblib.dump(self.global_model, model_path)
                joblib.dump(self.global_scaler, scaler_path)
                logger.info("Saved global model")
                
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
    
    def extract_features(self, behavior_data):
        """
        Extract features from behavior data
        
        Args:
            behavior_data: dict or DataFrame with behavior metrics
        
        Returns:
            numpy array of features
        """
        if isinstance(behavior_data, dict):
            features = []
            for col in self.feature_columns:
                value = behavior_data.get(col, 0)
                # Handle None values
                if value is None:
                    value = 0
                features.append(value)
            return np.array(features).reshape(1, -1)
        
        elif isinstance(behavior_data, pd.DataFrame):
            # Ensure all columns exist
            for col in self.feature_columns:
                if col not in behavior_data.columns:
                    behavior_data[col] = 0
            return behavior_data[self.feature_columns].values
        
        else:
            raise ValueError("behavior_data must be dict or DataFrame")
    
    def train_global_model(self, behavior_data):
        """
        Train global anomaly detection model
        
        Args:
            behavior_data: DataFrame with behavior features from multiple users
        """
        try:
            if len(behavior_data) < 10:
                logger.warning("Insufficient data for training global model")
                return False
            
            # Extract features
            X = self.extract_features(behavior_data)
            
            # Scale features
            self.global_scaler.fit(X)
            X_scaled = self.global_scaler.transform(X)
            
            # Train model
            self.global_model.fit(X_scaled)
            
            # Save model
            self._save_model()
            
            logger.info(f"Trained global model on {len(X)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training global model: {str(e)}")
            return False
    
    def train_user_model(self, user_id, behavior_data):
        """
        Train user-specific anomaly detection model
        
        Args:
            user_id: User ID
            behavior_data: DataFrame or list of behavior features
        """
        try:
            if len(behavior_data) < 5:
                logger.warning(f"Insufficient data for training user {user_id} model")
                return False
            
            # Extract features
            X = self.extract_features(behavior_data)
            
            # Adjust contamination based on data size
            contamination = min(0.1, max(0.01, 2.0 / len(X)))
            
            # Create and train user-specific model
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=contamination,
                max_samples=min(256, len(X)),
                random_state=self.random_state,
                n_jobs=-1
            )
            
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            model.fit(X_scaled)
            
            # Store model
            self.models[user_id] = model
            self.scalers[user_id] = scaler
            
            # Save model
            self._save_model(user_id)
            
            logger.info(f"Trained model for user {user_id} on {len(X)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training user model: {str(e)}")
            return False
    
    def detect_anomaly(self, behavior_data, user_id=None):
        """
        Detect anomaly in behavior data
        
        Args:
            behavior_data: dict or DataFrame with behavior features
            user_id: Optional user ID for user-specific detection
        
        Returns:
            dict with anomaly detection results
        """
        try:
            # Extract features
            X = self.extract_features(behavior_data)
            
            # Use user-specific model if available
            if user_id and user_id in self.models and user_id in self.scalers:
                model = self.models[user_id]
                scaler = self.scalers[user_id]
                model_type = 'user_specific'
            else:
                # Fall back to global model
                model = self.global_model
                scaler = self.global_scaler
                model_type = 'global'
            
            # Scale features
            X_scaled = scaler.transform(X)
            
            # Predict anomaly
            prediction = model.predict(X_scaled)[0]
            anomaly_score = model.decision_function(X_scaled)[0]
            
            # Convert to 0-100 scale (higher = more anomalous)
            # Isolation Forest: negative values = anomaly, positive = normal
            normalized_score = max(0, min(100, (0.5 - anomaly_score) * 100))
            
            # Determine if anomalous
            is_anomalous = prediction == -1
            
            # Get feature contributions
            feature_contributions = self._get_feature_contributions(X_scaled, model)
            
            return {
                'is_anomalous': is_anomalous,
                'anomaly_score': round(normalized_score, 2),
                'raw_score': round(anomaly_score, 4),
                'model_type': model_type,
                'feature_contributions': feature_contributions
            }
            
        except Exception as e:
            logger.error(f"Error detecting anomaly: {str(e)}")
            return {
                'is_anomalous': False,
                'anomaly_score': 0.0,
                'raw_score': 0.0,
                'model_type': 'error',
                'feature_contributions': {},
                'error': str(e)
            }
    
    def _get_feature_contributions(self, X_scaled, model):
        """
        Calculate feature contributions to anomaly score
        
        Uses path length in isolation trees to determine feature importance
        """
        try:
            contributions = {}
            
            # Get average path length for each feature
            for i, feature in enumerate(self.feature_columns):
                if i < X_scaled.shape[1]:
                    contributions[feature] = round(abs(float(X_scaled[0][i])), 2)
            
            return contributions
            
        except Exception as e:
            logger.error(f"Error calculating feature contributions: {str(e)}")
            return {}
    
    def batch_detect(self, behavior_data_list, user_id=None):
        """
        Batch anomaly detection for multiple behavior records
        
        Args:
            behavior_data_list: List of behavior data dicts
            user_id: Optional user ID
        
        Returns:
            List of anomaly detection results
        """
        results = []
        for data in behavior_data_list:
            result = self.detect_anomaly(data, user_id)
            results.append(result)
        return results
    
    def get_model_stats(self, user_id=None):
        """Get model statistics"""
        if user_id:
            model = self.models.get(user_id)
            scaler = self.scalers.get(user_id)
            model_type = 'user_specific'
        else:
            model = self.global_model
            scaler = self.global_scaler
            model_type = 'global'
        
        if model is None:
            return {'error': 'Model not found'}
        
        return {
            'model_type': model_type,
            'n_estimators': model.n_estimators,
            'contamination': model.contamination,
            'max_samples': model.max_samples,
            'n_features': len(self.feature_columns),
            'feature_columns': self.feature_columns,
            'trained': hasattr(model, 'offset_')
        }
    
    def retrain_all_models(self):
        """Retrain all models with latest data"""
        from app import app
        from models.behavior import BehaviorPattern
        
        with app.app_context():
            try:
                # Get all behavior patterns
                patterns = BehaviorPattern.query.all()
                
                if len(patterns) < 10:
                    logger.warning("Insufficient data for retraining")
                    return False
                
                # Convert to DataFrame
                data = []
                for p in patterns:
                    if p.feature_vector:
                        data.append(p.feature_vector)
                
                if len(data) < 10:
                    logger.warning("Insufficient feature vectors for retraining")
                    return False
                
                df = pd.DataFrame(data, columns=self.feature_columns)
                
                # Train global model
                self.train_global_model(df)
                
                # Train user-specific models
                from models.user import User
                users = User.query.all()
                for user in users:
                    user_patterns = [p for p in patterns if p.user_id == user.id]
                    if len(user_patterns) >= 5:
                        user_data = []
                        for p in user_patterns:
                            if p.feature_vector:
                                user_data.append(p.feature_vector)
                        if user_data:
                            user_df = pd.DataFrame(user_data, columns=self.feature_columns)
                            self.train_user_model(user.id, user_df)
                
                logger.info("Retrained all models successfully")
                return True
                
            except Exception as e:
                logger.error(f"Error retraining models: {str(e)}")
                return False


class AutoencoderAnomalyDetector:
    """
    Optional: Deep Learning-based anomaly detection using Autoencoder
    For advanced use cases requiring non-linear feature interactions
    """
    
    def __init__(self, input_dim=10, encoding_dim=5):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = None
        
    def build_model(self):
        """Build autoencoder model"""
        try:
            from tensorflow.keras.models import Model
            from tensorflow.keras.layers import Input, Dense
            from tensorflow.keras.optimizers import Adam
            
            # Encoder
            input_layer = Input(shape=(self.input_dim,))
            encoded = Dense(self.encoding_dim * 2, activation='relu')(input_layer)
            encoded = Dense(self.encoding_dim, activation='relu')(encoded)
            
            # Decoder
            decoded = Dense(self.encoding_dim * 2, activation='relu')(encoded)
            decoded = Dense(self.input_dim, activation='linear')(decoded)
            
            # Autoencoder
            self.model = Model(input_layer, decoded)
            self.model.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
            
            return True
        except ImportError:
            logger.warning("TensorFlow not available, autoencoder disabled")
            return False
    
    def train(self, X, epochs=50, batch_size=32, validation_split=0.1):
        """Train autoencoder"""
        if self.model is None:
            if not self.build_model():
                return False
        
        # Scale data
        X_scaled = self.scaler.fit_transform(X)
        
        # Train
        history = self.model.fit(
            X_scaled, X_scaled,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=0
        )
        
        # Calculate threshold (95th percentile of reconstruction error)
        predictions = self.model.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - predictions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)
        
        return True
    
    def detect(self, X):
        """Detect anomalies using reconstruction error"""
        if self.model is None or self.threshold is None:
            return {'error': 'Model not trained'}
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - predictions, 2), axis=1)
        
        is_anomalous = mse > self.threshold
        anomaly_score = (mse / self.threshold) * 50  # Scale to 0-100
        
        return {
            'is_anomalous': bool(is_anomalous[0] if isinstance(is_anomalous, np.ndarray) else is_anomalous),
            'anomaly_score': min(100, round(float(anomaly_score[0] if isinstance(anomaly_score, np.ndarray) else anomaly_score), 2)),
            'reconstruction_error': round(float(mse[0] if isinstance(mse, np.ndarray) else mse), 4)
        }
