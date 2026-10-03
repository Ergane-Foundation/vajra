#!/usr/bin/env python3
"""
Model Loader - Loads and manages trained ML and ETA models
Handles custom class definitions and model initialization
"""

import joblib
import pickle
import logging
from pathlib import Path
from typing import Any, Optional, Dict

from vajra.common.paths import PROJECT_ROOT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("model_loader")


# Define custom classes that were used during model training
class RealTimeDetector:
    """Custom model class for insider threat detection"""
    def __init__(self):
        self.model = None  # This holds the actual InsiderNet model
        self.scaler = None
        self.feature_cols = None
        
    def fit(self, X, y):
        return self
    
    def predict(self, X):
        if self.model is None:
            return [0] * len(X)
        # The actual model should handle prediction
        try:
            import torch
            import numpy as np
            # Scale input
            if self.scaler is not None:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X
            # Convert to tensor and predict
            X_tensor = torch.FloatTensor(X_scaled)
            self.model.eval()  # Set to evaluation mode
            with torch.no_grad():
                outputs = self.model.forward(X_tensor)
                # Threshold at 0.5
                predictions = (outputs.squeeze() > 0.5).int().cpu().numpy()
            return predictions
        except Exception as e:
            # Fallback to returning 0
            import numpy as np
            return np.array([0] * len(X))
    
    def predict_proba(self, X):
        if self.model is None:
            return [[0.5, 0.5]] * len(X)
        try:
            import torch
            import numpy as np
            # Scale input
            if self.scaler is not None:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X
            # Convert to tensor and predict probabilities
            X_tensor = torch.FloatTensor(X_scaled)
            self.model.eval()  # Set to evaluation mode
            with torch.no_grad():
                outputs = self.model.forward(X_tensor)
                probs = outputs.squeeze().cpu().numpy()
            # Ensure it's a 1D array
            if probs.ndim == 0:
                probs = np.array([probs])
            # Return as [[prob_class0, prob_class1], ...]
            return np.column_stack([1 - probs, probs])
        except Exception as e:
            import numpy as np
            return np.array([[0.5, 0.5]] * len(X))


class InsiderNet:
    """Neural network model for insider threat detection - PyTorch based"""
    def __init__(self, input_size=7, hidden1=128, hidden2=64, output_size=1):
        try:
            import torch
            import torch.nn as nn
            
            # Define layers (typical architecture for CERT dataset)
            self.fc1 = nn.Linear(input_size, hidden1)
            self.fc2 = nn.Linear(hidden1, hidden2)
            self.fc3 = nn.Linear(hidden2, output_size)
            self.dropout = nn.Dropout(0.3)
            self.relu = nn.ReLU()
            self.sigmoid = nn.Sigmoid()
        except:
            self.fc1 = None
            self.fc2 = None
            self.fc3 = None
            self.dropout = None
        
    def forward(self, x):
        """Forward pass through the network"""
        try:
            import torch
            
            if self.fc1 is None:
                return torch.zeros(x.shape[0], 1)
            
            # Input -> Hidden Layer 1
            x = self.fc1(x)
            x = self.relu(x)
            x = self.dropout(x)
            
            # Hidden Layer 1 -> Hidden Layer 2
            x = self.fc2(x)
            x = self.relu(x)
            x = self.dropout(x)
            
            # Hidden Layer 2 -> Output
            x = self.fc3(x)
            x = self.sigmoid(x)
            
            return x
        except:
            import torch
            return torch.zeros(x.shape[0], 1)
    
    def __call__(self, x):
        """Make the model callable"""
        return self.forward(x)
    
    def eval(self):
        """Set model to evaluation mode"""
        return self
    
    def fit(self, X, y):
        return self
    
    def predict(self, X):
        return [0] * len(X)
    
    def predict_proba(self, X):
        return [[0.5, 0.5]] * len(X)


class DeepInsiderModel:
    """Deep learning model wrapper"""
    def __init__(self):
        self.model = None
        
    def fit(self, X, y):
        return self
    
    def predict(self, X):
        if self.model is None:
            return [0] * len(X)
        return self.model.predict(X)
    
    def predict_proba(self, X):
        if self.model is None:
            return [[0.5, 0.5]] * len(X)
        return self.model.predict_proba(X)


def load_ml_model(model_path: str = "models/deep_insider_threat_model.pkl") -> Optional[Any]:
    """
    Load the ML insider threat detection model
    
    Args:
        model_path: Path to the trained model file
        
    Returns:
        Loaded model or None if failed
    """
    import os
    
    try:
        # If relative path, resolve it against the project root
        if not os.path.isabs(model_path):
            script_dir = str(PROJECT_ROOT)
            model_path = os.path.join(script_dir, model_path)
        
        path = Path(model_path)
        if not path.exists():
            logger.error(f"ML model file not found: {model_path}")
            return None
        
        logger.info(f"Loading ML model from: {path}")
        
        # Register custom classes in pickle namespace before loading
        import sys
        sys.modules['__main__'].RealTimeDetector = RealTimeDetector
        sys.modules['__main__'].InsiderNet = InsiderNet
        sys.modules['__main__'].DeepInsiderModel = DeepInsiderModel
        
        # Try joblib first
        try:
            model = joblib.load(path)
            logger.info(f"[OK] ML Model loaded successfully with joblib")
            return model
        except Exception as e:
            logger.warning(f"joblib load failed: {e}, trying pickle...")
            
            # Fall back to pickle with registered classes
            with open(path, 'rb') as f:
                model = pickle.load(f)
            logger.info(f"[OK] ML Model loaded with pickle")
            return model
            
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


def load_eta_model(model_path: str = "models/eta_model.pkl") -> Optional[Any]:
    """
    Load the ETA encrypted traffic analysis model
    
    Args:
        model_path: Path to the trained model file
        
    Returns:
        Loaded model dict or None if failed
    """
    import os
    
    try:
        # If relative path, resolve it against the project root
        if not os.path.isabs(model_path):
            script_dir = str(PROJECT_ROOT)
            model_path = os.path.join(script_dir, model_path)
        
        path = Path(model_path)
        if not path.exists():
            logger.error(f"ETA model file not found: {model_path}")
            return None
        
        logger.info(f"Loading ETA model from: {path}")
        
        # ETA model should be a joblib dump
        model = joblib.load(path)
        logger.info(f"[OK] ETA Model loaded successfully")
        logger.info(f"ETA Model type: {type(model)}")
        
        if isinstance(model, dict):
            logger.info(f"ETA Model components: {list(model.keys())}")
        
        return model
            
    except Exception as e:
        logger.error(f"Failed to load ETA model: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None


def get_ml_predictions(model: Any, features: Dict[str, float]) -> Dict[str, Any]:
    """
    Get predictions from ML model
    
    Args:
        model: Trained model
        features: Dictionary of features
        
    Returns:
        Prediction results
    """
    try:
        import numpy as np
        
        # Convert features to array
        feature_values = [list(features.values())]
        X = np.array(feature_values)
        
        # Make prediction with error handling
        pred_result = model.predict(X)
        # Handle both array and scalar returns
        if isinstance(pred_result, (list, np.ndarray)):
            prediction = int(pred_result[0]) if len(pred_result) > 0 else 0
        else:
            prediction = int(pred_result)
        
        # Get confidence
        confidence = 0.5
        if hasattr(model, 'predict_proba'):
            try:
                proba_result = model.predict_proba(X)
                if isinstance(proba_result, (list, np.ndarray)):
                    proba = proba_result[0] if len(proba_result) > 0 else [0.5, 0.5]
                else:
                    proba = [0.5, 0.5]
                confidence = float(max(proba))
            except Exception as e:
                logger.debug(f"predict_proba error: {e}")
                confidence = 0.5
        
        return {
            'prediction': int(prediction),
            'confidence': float(confidence),
            'is_threat': prediction == 1
        }
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return {'prediction': 0, 'confidence': 0.0, 'is_threat': False}


def load_backdoor_model(model_dir: str = "models/backdoor_detection") -> Optional[Any]:
    """
    Load backdoor detection model with its preprocessing tools
    
    Args:
        model_dir: Directory containing backdoor_model.pkl, label_encoders.pkl, scaler.pkl
        
    Returns:
        Model dict with model, encoders, and scaler or None if failed
    """
    import os
    
    try:
        # If relative path, resolve it against the project root
        if not os.path.isabs(model_dir):
            script_dir = str(PROJECT_ROOT)
            model_dir = os.path.join(script_dir, model_dir)
        
        model_path = Path(model_dir)
        if not model_path.exists():
            logger.error(f"Backdoor model directory not found: {model_dir}")
            return None
        
        logger.info(f"Loading backdoor detection model from: {model_path}")
        
        # Load model
        model_file = model_path / "backdoor_model.pkl"
        if not model_file.exists():
            logger.error(f"backdoor_model.pkl not found in {model_dir}")
            return None
        
        # Try joblib first, then pickle
        try:
            model = joblib.load(model_file)
            logger.info(f"[OK] Backdoor model loaded (joblib)")
        except Exception as e:
            logger.debug(f"joblib failed: {e}, trying pickle...")
            with open(model_file, 'rb') as f:
                model = pickle.load(f)
            logger.info(f"[OK] Backdoor model loaded (pickle)")
        
        # Load label encoders
        encoders_file = model_path / "label_encoders.pkl"
        encoders = None
        if encoders_file.exists():
            try:
                encoders = joblib.load(encoders_file)
                logger.info(f"[OK] Label encoders loaded (joblib)")
            except:
                with open(encoders_file, 'rb') as f:
                    encoders = pickle.load(f)
                logger.info(f"[OK] Label encoders loaded (pickle)")
        else:
            logger.warning(f"label_encoders.pkl not found, will skip encoding")
        
        # Load scaler
        scaler_file = model_path / "scaler.pkl"
        scaler = None
        if scaler_file.exists():
            try:
                scaler = joblib.load(scaler_file)
                logger.info(f"[OK] Scaler loaded (joblib)")
            except:
                with open(scaler_file, 'rb') as f:
                    scaler = pickle.load(f)
                logger.info(f"[OK] Scaler loaded (pickle)")
        else:
            logger.warning(f"scaler.pkl not found, will skip scaling")
        
        # Return as dict
        model_dict = {
            'model': model,
            'encoders': encoders,
            'scaler': scaler,
            'model_dir': str(model_path)
        }
        
        logger.info(f"[OK] Backdoor detection model fully loaded")
        return model_dict
            
    except Exception as e:
        logger.error(f"Failed to load backdoor model: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


def load_h5_model(model_path: str = "models/domain_classifier.h5") -> Optional[Any]:
    """
    Load Keras/TensorFlow H5 model
    
    Args:
        model_path: Path to the H5 model file
        
    Returns:
        Loaded model or None if failed
    """
    import os
    
    try:
        # If relative path, resolve it against the project root
        if not os.path.isabs(model_path):
            script_dir = str(PROJECT_ROOT)
            model_path = os.path.join(script_dir, model_path)
        
        path = Path(model_path)
        if not path.exists():
            logger.error(f"H5 model file not found: {model_path}")
            return None
        
        logger.info(f"Loading H5 model from: {path}")
        
        # Import TensorFlow/Keras
        try:
            import tensorflow as tf
            from tensorflow import keras
        except ImportError:
            logger.error("TensorFlow not installed. Install with: pip install tensorflow")
            return None
        
        # Load the model
        model = keras.models.load_model(path)
        logger.info(f"[OK] H5 Model loaded successfully")
        logger.info(f"H5 Model input shape: {model.input_shape}")
        logger.info(f"H5 Model output shape: {model.output_shape}")
        
        return model
            
    except Exception as e:
        logger.error(f"Failed to load H5 model: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


def load_tflite_model(model_path: str = "models/gnn_fingerprint.tflite") -> Optional[Any]:
    """
    Load TensorFlow Lite model
    
    Args:
        model_path: Path to the TFLite model file
        
    Returns:
        Loaded interpreter or None if failed
    """
    import os
    
    try:
        # If relative path, resolve it against the project root
        if not os.path.isabs(model_path):
            script_dir = str(PROJECT_ROOT)
            model_path = os.path.join(script_dir, model_path)
        
        path = Path(model_path)
        if not path.exists():
            logger.error(f"TFLite model file not found: {model_path}")
            return None
        
        logger.info(f"Loading TFLite model from: {path}")
        
        # Import TensorFlow Lite
        try:
            import tensorflow as tf
        except ImportError:
            logger.error("TensorFlow not installed. Install with: pip install tensorflow")
            return None
        
        # Load the TFLite model
        interpreter = tf.lite.Interpreter(model_path=str(path))
        interpreter.allocate_tensors()
        
        # Get input and output details
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()
        
        logger.info(f"[OK] TFLite Model loaded successfully")
        logger.info(f"TFLite Input shape: {input_details[0]['shape']}")
        logger.info(f"TFLite Output shape: {output_details[0]['shape']}")
        
        return {
            'interpreter': interpreter,
            'input_details': input_details,
            'output_details': output_details
        }
            
    except Exception as e:
        logger.error(f"Failed to load TFLite model: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None


def get_domain_classifier_predictions(model: Any, domain_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get predictions from domain classifier H5 model
    
    Args:
        model: Loaded H5 Keras model
        domain_features: Domain/DNS features
        
    Returns:
        Prediction results
    """
    try:
        if model is None:
            return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}
        
        import numpy as np
        import tensorflow as tf
        
        # Extract features for domain classification
        domain = domain_features.get('domain', '')
        
        # Calculate domain features
        domain_length = len(domain)
        digit_count = sum(c.isdigit() for c in domain)
        special_count = sum(not c.isalnum() and c != '.' for c in domain)
        subdomain_count = domain.count('.')
        
        # Calculate entropy
        from collections import Counter
        import math
        if domain:
            counts = Counter(domain)
            total = len(domain)
            entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
        else:
            entropy = 0.0
        
        # Features array (adjust based on your model's expected input)
        features = [
            domain_length,
            digit_count / max(domain_length, 1),  # digit ratio
            special_count / max(domain_length, 1),  # special char ratio
            subdomain_count,
            entropy,
            int(domain_features.get('has_suspicious_tld', False)),
            domain_features.get('query_count', 1),  # DNS query frequency
            domain_features.get('response_time', 0),  # DNS response time
        ]
        
        # Pad or trim to match model input size
        input_shape = model.input_shape[1]
        if len(features) < input_shape:
            features.extend([0.0] * (input_shape - len(features)))
        elif len(features) > input_shape:
            features = features[:input_shape]
        
        X = np.array([features], dtype=np.float32)
        
        # Make prediction
        predictions = model.predict(X, verbose=0)
        
        # Get prediction class and confidence
        if predictions.shape[-1] > 1:
            # Multi-class classification
            prediction_idx = np.argmax(predictions[0])
            confidence = float(predictions[0][prediction_idx])
            class_names = domain_features.get('class_names', ['benign', 'dga', 'phishing', 'malware'])
            prediction_label = class_names[prediction_idx] if prediction_idx < len(class_names) else 'unknown'
        else:
            # Binary classification
            confidence = float(predictions[0][0])
            prediction_label = 'malicious' if confidence > 0.5 else 'benign'
        
        is_threat = 'benign' not in str(prediction_label).lower()
        
        return {
            'prediction': prediction_label,
            'confidence': float(confidence),
            'is_threat': is_threat,
            'domain': domain
        }
    except Exception as e:
        logger.error(f"Domain classifier prediction error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}


def get_backdoor_predictions(model_dict: Dict, domain_features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get predictions from backdoor detection model
    
    Args:
        model_dict: Dict with model, encoders, and scaler
        domain_features: Domain/network features
        
    Returns:
        Prediction results
    """
    try:
        if model_dict is None or 'model' not in model_dict:
            return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}
        
        import numpy as np
        
        model = model_dict['model']
        encoders = model_dict.get('encoders')
        scaler = model_dict.get('scaler')
        
        # Extract domain
        domain = domain_features.get('domain', '')
        
        # Build feature dictionary (adjust based on your training features)
        features = {
            'domain_length': len(domain),
            'digit_count': sum(c.isdigit() for c in domain),
            'special_char_count': sum(not c.isalnum() and c != '.' for c in domain),
            'subdomain_count': domain.count('.'),
            'has_http': int('http' in domain.lower()),
            'has_https': int('https' in domain.lower()),
            'port': domain_features.get('port', 80),
            'ip_address': domain_features.get('ip_address', ''),
            'protocol': domain_features.get('protocol', 'tcp'),
        }
        
        # Calculate entropy
        from collections import Counter
        import math
        if domain:
            counts = Counter(domain)
            total = len(domain)
            entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
            features['entropy'] = entropy
        else:
            features['entropy'] = 0.0
        
        # Add any additional features from input
        for key, value in domain_features.items():
            if key not in features and key != 'domain':
                features[key] = value
        
        # Apply label encoding if available
        if encoders:
            for field, encoder in encoders.items():
                if field in features and hasattr(encoder, 'transform'):
                    try:
                        features[field] = encoder.transform([features[field]])[0]
                    except:
                        pass  # Keep original value if encoding fails
        
        # Convert to array (get feature order from model if available)
        if hasattr(model, 'feature_names_in_'):
            feature_order = model.feature_names_in_
        else:
            feature_order = sorted(features.keys())
        
        X = np.array([[features.get(f, 0) for f in feature_order]])
        
        # Apply scaling if available
        if scaler:
            X = scaler.transform(X)
        
        # Make prediction
        prediction = int(model.predict(X)[0])
        
        # Get confidence
        confidence = 0.5
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(X)[0]
            confidence = float(max(proba))
        
        is_threat = prediction == 1
        prediction_label = 'backdoor' if is_threat else 'benign'
        
        return {
            'prediction': prediction_label,
            'confidence': float(confidence),
            'is_threat': is_threat,
            'domain': domain
        }
    except Exception as e:
        logger.error(f"Backdoor prediction error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}


def get_gnn_fingerprint_predictions(model_dict: Dict, network_graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get predictions from GNN fingerprint TFLite model
    
    Args:
        model_dict: TFLite model dictionary with interpreter
        network_graph: Network graph features (nodes, edges, adjacency matrix)
        
    Returns:
        Prediction results
    """
    try:
        if model_dict is None or 'interpreter' not in model_dict:
            return {'prediction': 'unknown', 'confidence': 0.5, 'is_threat': False}
        import math
        if domain:
            counts = Counter(domain)
            total = len(domain)
            entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
        else:
            entropy = 0.0
        
        # Features array (adjust based on your model's expected input)
        features = [
            domain_length,
            digit_count / max(domain_length, 1),  # digit ratio
            special_count / max(domain_length, 1),  # special char ratio
            subdomain_count,
            entropy,
            int(domain_features.get('has_suspicious_tld', False)),
            domain_features.get('query_count', 1),
            domain_features.get('response_time', 0),
        ]
        
        # Pad or trim to match model input size
        input_shape = model.input_shape[1]
        if len(features) < input_shape:
            features.extend([0.0] * (input_shape - len(features)))
        elif len(features) > input_shape:
            features = features[:input_shape]
        
        X = np.array([features], dtype=np.float32)
        
        # Make prediction
        predictions = model.predict(X, verbose=0)
        
        # Get prediction class and confidence
        if predictions.shape[-1] > 1:
            # Multi-class classification
            prediction_idx = np.argmax(predictions[0])
            confidence = float(predictions[0][prediction_idx])
            class_names = domain_features.get('class_names', ['benign', 'dga', 'phishing', 'malware'])
            prediction_label = class_names[prediction_idx] if prediction_idx < len(class_names) else 'unknown'
        else:
            # Binary classification
            confidence = float(predictions[0][0])
            prediction_label = 'malicious' if confidence > 0.5 else 'benign'
        
        is_threat = 'benign' not in str(prediction_label).lower()
        
        return {
            'prediction': prediction_label,
            'confidence': float(confidence),
            'is_threat': is_threat,
            'domain': domain
        }
    except Exception as e:
        logger.error(f"Domain classifier prediction error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}


def get_gnn_fingerprint_predictions(model_dict: Dict, network_graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get predictions from GNN fingerprint TFLite model
    
    Args:
        model_dict: TFLite model dictionary with interpreter
        network_graph: Network graph features (nodes, edges, adjacency matrix)
        
    Returns:
        Prediction results
    """
    try:
        if model_dict is None or 'interpreter' not in model_dict:
            return {'prediction': 'unknown', 'confidence': 0.5, 'is_threat': False}
        
        import numpy as np
        
        interpreter = model_dict['interpreter']
        input_details = model_dict['input_details']
        output_details = model_dict['output_details']
        
        # Extract graph features
        nodes = network_graph.get('nodes', [])
        edges = network_graph.get('edges', [])
        
        # Build feature matrix (adjust based on your model's expected input)
        input_shape = input_details[0]['shape']
        
        # Create input tensor from graph data
        if len(nodes) > 0:
            # Convert nodes to feature matrix
            node_features = []
            for node in nodes:
                features = [
                    node.get('port', 0),
                    node.get('packet_count', 0),
                    node.get('byte_count', 0),
                    node.get('connection_count', 0),
                ]
                node_features.append(features)
            
            # Pad or truncate to match input shape
            X = np.array(node_features, dtype=np.float32)
            
            # Reshape to match expected input
            target_nodes = input_shape[1] if len(input_shape) > 1 else 10
            if X.shape[0] < target_nodes:
                padding = np.zeros((target_nodes - X.shape[0], X.shape[1]), dtype=np.float32)
                X = np.vstack([X, padding])
            elif X.shape[0] > target_nodes:
                X = X[:target_nodes]
            X = X.reshape(input_shape)
        else:
            # No nodes, create zero tensor
            X = np.zeros(input_shape, dtype=np.float32)
        
        # Set input tensor
        interpreter.set_tensor(input_details[0]['index'], X)
        
        # Run inference
        interpreter.invoke()
        
        # Get output
        output_data = interpreter.get_tensor(output_details[0]['index'])
        
        # Process output
        if output_data.shape[-1] > 1:
            # Multi-class
            prediction_idx = np.argmax(output_data[0])
            confidence = float(output_data[0][prediction_idx])
            fingerprint_types = network_graph.get('fingerprint_types', 
                ['normal', 'bot', 'scanner', 'exploit'])
            prediction_label = fingerprint_types[prediction_idx] if prediction_idx < len(fingerprint_types) else 'unknown'
        else:
            # Binary or regression
            confidence = float(output_data[0][0])
            prediction_label = 'anomalous' if confidence > 0.5 else 'normal'
        
        is_threat = prediction_label not in ['normal', 'benign']
        
        return {
            'prediction': prediction_label,
            'confidence': float(confidence),
            'is_threat': is_threat,
            'node_count': len(nodes),
            'edge_count': len(edges)
        }
    except Exception as e:
        logger.error(f"GNN fingerprint prediction error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'prediction': 'unknown', 'confidence': 0.5, 'is_threat': False}


def get_eta_predictions(model: Any, flow_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get predictions from ETA model
    
    Args:
        model: Trained ETA model (dict with model, scaler, protocol_encoder, etc.)
        flow_data: Network flow data
        
    Returns:
        Prediction results
    """
    try:
        if model is None:
            return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}
        
        # Extract the actual model from dict if needed
        if isinstance(model, dict):
            clf = model.get('model')
            protocol_encoder = model.get('protocol_encoder')
        else:
            clf = model
            protocol_encoder = None
        
        if clf is None:
            return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}
        
        import numpy as np
        
        # ETA model expects these 11 features (in this exact order):
        # ['src_port', 'dest_port', 'protocol', 'duration', 'bytes_toserver',
        #  'bytes_toclient', 'packets_toserver', 'packets_toclient', 'total_bytes', 
        #  'total_packets', 'bytes_per_packet']
        
        # Extract and prepare features
        src_port = flow_data.get('src_port', 0)
        dest_port = flow_data.get('dest_port', 0)
        protocol = flow_data.get('protocol', 'tcp')
        duration = flow_data.get('duration', 0)
        bytes_toserver = flow_data.get('bytes_toserver', 0)
        bytes_toclient = flow_data.get('bytes_toclient', 0)
        packets_toserver = flow_data.get('packets_toserver', 0)
        packets_toclient = flow_data.get('packets_toclient', 0)
        total_bytes = flow_data.get('total_bytes', 0)
        total_packets = flow_data.get('total_packets', 0)
        bytes_per_packet = flow_data.get('bytes_per_packet', 0)
        
        # Encode protocol if encoder is available
        if protocol_encoder and isinstance(protocol, str):
            try:
                protocol = protocol_encoder.transform([protocol])[0]
            except:
                protocol = 0  # Default to 0 if encoding fails
        elif isinstance(protocol, str):
            # Map common protocols to numbers if no encoder
            protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            protocol = protocol_map.get(protocol.lower(), 0)
        
        # Create feature array in correct order
        X = np.array([[src_port, dest_port, protocol, duration, bytes_toserver,
                      bytes_toclient, packets_toserver, packets_toclient, 
                      total_bytes, total_packets, bytes_per_packet]])
        
        # Make prediction
        prediction_idx = clf.predict(X)[0]
        
        # Get confidence/probabilities
        confidence = 0.5
        if hasattr(clf, 'predict_proba'):
            proba = clf.predict_proba(X)[0]
            confidence = float(max(proba))
        
        # Get class names - prediction can be either index or string label
        if hasattr(clf, 'classes_'):
            if isinstance(prediction_idx, str):
                prediction_label = prediction_idx
            else:
                prediction_label = clf.classes_[int(prediction_idx)]
        else:
            threat_types = ['benign', 'data_exfiltration', 'port_scan', 'c2']
            if isinstance(prediction_idx, str):
                prediction_label = prediction_idx
            else:
                prediction_label = threat_types[int(prediction_idx)] if int(prediction_idx) < len(threat_types) else 'benign'
        
        # Determine if it's a threat (anything not 'benign')
        is_threat = 'benign' not in str(prediction_label).lower()
        
        return {
            'prediction': prediction_label,
            'confidence': float(confidence),
            'is_threat': is_threat
        }
    except Exception as e:
        logger.error(f"ETA prediction error: {e}")
        return {'prediction': 'benign', 'confidence': 0.5, 'is_threat': False}
