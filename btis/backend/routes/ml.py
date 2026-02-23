"""
ML Routes for BTIS
Handles ML model operations and predictions
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging

logger = logging.getLogger(__name__)
ml_bp = Blueprint('ml', __name__)

@ml_bp.route('/detect', methods=['POST'])
@jwt_required()
def detect_anomaly():
    """Run anomaly detection on behavior data"""
    try:
        from app import ml_engine
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = data.get('user_id')
        behavior_data = data.get('behavior_data')
        
        if not behavior_data:
            return jsonify({'error': 'behavior_data is required'}), 400
        
        # Run detection
        result = ml_engine.detect_anomaly(behavior_data, user_id=user_id)
        
        return jsonify({
            'success': True,
            'result': result
        }), 200
        
    except Exception as e:
        logger.error(f"Anomaly detection error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/detect-batch', methods=['POST'])
@jwt_required()
def detect_anomaly_batch():
    """Run batch anomaly detection"""
    try:
        from app import ml_engine
        
        data = request.get_json()
        
        if not data or not data.get('behavior_data_list'):
            return jsonify({'error': 'behavior_data_list is required'}), 400
        
        user_id = data.get('user_id')
        behavior_data_list = data.get('behavior_data_list')
        
        # Run batch detection
        results = ml_engine.batch_detect(behavior_data_list, user_id=user_id)
        
        return jsonify({
            'success': True,
            'results': results,
            'anomaly_count': sum(1 for r in results if r['is_anomalous']),
            'avg_score': sum(r['anomaly_score'] for r in results) / len(results) if results else 0
        }), 200
        
    except Exception as e:
        logger.error(f"Batch detection error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/train', methods=['POST'])
@jwt_required()
def train_model():
    """Train ML model with new data"""
    try:
        from app import ml_engine
        import pandas as pd
        
        data = request.get_json()
        
        if not data or not data.get('training_data'):
            return jsonify({'error': 'training_data is required'}), 400
        
        user_id = data.get('user_id')  # Optional - if None, trains global model
        training_data = data.get('training_data')
        
        # Convert to DataFrame
        df = pd.DataFrame(training_data)
        
        # Train model
        if user_id:
            success = ml_engine.train_user_model(user_id, df)
        else:
            success = ml_engine.train_global_model(df)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Model trained successfully for {"user " + str(user_id) if user_id else "global model"}'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to train model - insufficient data'
            }), 400
        
    except Exception as e:
        logger.error(f"Train model error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/retrain-all', methods=['POST'])
@jwt_required()
def retrain_all_models():
    """Retrain all models with latest data"""
    try:
        from app import ml_engine
        
        result = ml_engine.retrain_all_models()
        
        if result:
            return jsonify({
                'success': True,
                'message': 'All models retrained successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to retrain models'
            }), 400
        
    except Exception as e:
        logger.error(f"Retrain all error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/status', methods=['GET'])
@jwt_required()
def get_model_status():
    """Get ML model status"""
    try:
        from app import ml_engine
        
        user_id = request.args.get('user_id', type=int)
        
        stats = ml_engine.get_model_stats(user_id=user_id)
        
        return jsonify({
            'success': True,
            'status': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Get model status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/features', methods=['GET'])
@jwt_required()
def get_feature_list():
    """Get list of ML features"""
    try:
        from app import ml_engine
        
        return jsonify({
            'success': True,
            'features': ml_engine.feature_columns
        }), 200
        
    except Exception as e:
        logger.error(f"Get features error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/feature-importance', methods=['GET'])
@jwt_required()
def get_feature_importance():
    """Get feature importance from model"""
    try:
        from app import ml_engine
        
        user_id = request.args.get('user_id', type=int)
        
        # Get model
        if user_id and user_id in ml_engine.models:
            model = ml_engine.models[user_id]
        else:
            model = ml_engine.global_model
        
        # For Isolation Forest, we can use feature importances if available
        # or return a placeholder
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            feature_importance = {
                feature: round(float(importance), 4)
                for feature, importance in zip(ml_engine.feature_columns, importances)
            }
        else:
            # Return equal importance for Isolation Forest
            feature_importance = {
                feature: round(1.0 / len(ml_engine.feature_columns), 4)
                for feature in ml_engine.feature_columns
            }
        
        return jsonify({
            'success': True,
            'feature_importance': feature_importance
        }), 200
        
    except Exception as e:
        logger.error(f"Get feature importance error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@ml_bp.route('/explain', methods=['POST'])
@jwt_required()
def explain_prediction():
    """Explain an anomaly prediction"""
    try:
        from app import ml_engine
        
        data = request.get_json()
        
        if not data or not data.get('behavior_data'):
            return jsonify({'error': 'behavior_data is required'}), 400
        
        user_id = data.get('user_id')
        behavior_data = data.get('behavior_data')
        
        # Run detection
        result = ml_engine.detect_anomaly(behavior_data, user_id=user_id)
        
        # Generate explanation
        explanation = {
            'is_anomalous': result['is_anomalous'],
            'anomaly_score': result['anomaly_score'],
            'explanation': generate_explanation(result, behavior_data)
        }
        
        return jsonify({
            'success': True,
            'explanation': explanation
        }), 200
        
    except Exception as e:
        logger.error(f"Explain prediction error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def generate_explanation(result, behavior_data):
    """Generate human-readable explanation for anomaly"""
    explanations = []
    
    if not result['is_anomalous']:
        return "Behavior appears normal. No significant anomalies detected."
    
    # Analyze feature contributions
    contributions = result.get('feature_contributions', {})
    
    # Sort by contribution
    sorted_features = sorted(
        contributions.items(),
        key=lambda x: x[1],
        reverse=True
    )
    
    for feature, contribution in sorted_features[:3]:
        if contribution > 1.0:
            feature_name = feature.replace('_', ' ').title()
            value = behavior_data.get(feature, 0)
            
            if feature == 'login_hour':
                if value < 6 or value > 22:
                    explanations.append(f"Unusual login time ({value:.1f}:00 - outside business hours)")
            elif feature == 'file_access_count':
                if value > 50:
                    explanations.append(f"High volume of file access ({value} files)")
            elif feature == 'sensitive_access_count':
                if value > 0:
                    explanations.append(f"Access to sensitive resources ({value} instances)")
            elif feature == 'failed_login_count':
                if value > 3:
                    explanations.append(f"Multiple failed login attempts ({value} failures)")
            elif feature == 'after_hours_activity':
                if value > 0:
                    explanations.append("Activity detected outside normal working hours")
            elif feature == 'data_export_count':
                if value > 0:
                    explanations.append(f"Data export activity detected ({value} instances)")
    
    if not explanations:
        explanations.append("Behavior deviates from established baseline patterns")
    
    return "; ".join(explanations)
