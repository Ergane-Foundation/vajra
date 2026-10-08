#!/usr/bin/env python3
"""
Inference API - FastAPI for ML Model Serving

Loads AI models and provides prediction endpoints for SOAR engine.
Supports multiple specialized models (SQLi, DDoS, XSS, etc.)

Endpoints:
- GET /health - Health check
- POST /predict/sqli - SQL Injection detection
- POST /predict/ddos - DDoS attack detection
- POST /predict/xss - XSS attack detection
- POST /predict/general - General threat detection
- GET /models - List available models
- POST /reload - Reload models from disk
"""

import os
import logging
import pickle
import joblib
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import numpy as np

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import asyncio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/inference_api.log')
    ]
)
logger = logging.getLogger("inference_api")

# Create FastAPI app
app = FastAPI(
    title="Vajra ML Inference API",
    description="Model serving for Vajra",
    version="1.0.0"
)

# Add CORS middleware for web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model registry
MODEL_REGISTRY = {}
MODELS_DIR = Path("fl_models")
MODELS_DIR.mkdir(exist_ok=True)

# Global event loop reference for thread-safe async operations
MAIN_EVENT_LOOP = None

# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time log streaming"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.filters: Dict[WebSocket, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, filters: Dict[str, Any] = None):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
            self.filters[websocket] = filters or {}
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
                self.filters.pop(websocket, None)
        logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients with filtering"""
        if not self.active_connections:
            return
        
        disconnected = []
        
        for connection in self.active_connections:
            try:
                # Apply client-specific filters
                client_filters = self.filters.get(connection, {})
                
                if self._should_send(message, client_filters):
                    await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            await self.disconnect(conn)
    
    def _should_send(self, event: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if event matches client filters"""
        if not filters:
            return True
        
        # Filter by event type
        if 'event_types' in filters:
            if event.get('event_type') not in filters['event_types']:
                return False
        
        # Filter by threat level
        if 'threat_levels' in filters:
            if event.get('threat_level') not in filters['threat_levels']:
                return False
        
        # Filter by source component
        if 'components' in filters:
            if event.get('source_component') not in filters['components']:
                return False
        
        # Filter by minimum confidence
        if 'min_confidence' in filters:
            if event.get('confidence', 0) < filters['min_confidence']:
                return False
        
        return True

manager = ConnectionManager()


# Request/Response Models

class PredictionRequest(BaseModel):
    """Request format for predictions"""
    features: Dict[str, Any] = Field(..., description="Feature dictionary")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    protocol: Optional[str] = Field(None, description="Protocol")
    signature: Optional[str] = Field(None, description="Alert signature")


class PredictionResponse(BaseModel):
    """Response format for predictions"""
    model_name: str
    prediction: int  # 0 = benign, 1 = malicious
    confidence: float
    probabilities: Optional[List[float]]
    is_threat: bool
    threat_type: str
    timestamp: str
    inference_time_ms: float


class ModelInfo(BaseModel):
    """Model information"""
    name: str
    type: str
    loaded: bool
    last_updated: Optional[str]
    version: int
    metrics: Optional[Dict[str, float]]


# Model Loading

def load_model(model_path: Path, model_name: str, model_type: str) -> bool:
    """Load a model from disk into registry"""
    try:
        if model_path.suffix == '.pkl':
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
        elif model_path.suffix == '.joblib':
            model = joblib.load(model_path)
        else:
            logger.warning(f"Unsupported model format: {model_path.suffix}")
            return False
        
        MODEL_REGISTRY[model_name] = {
            'model': model,
            'type': model_type,
            'path': str(model_path),
            'loaded_at': datetime.now().isoformat(),
            'version': 1
        }
        
        logger.info(f"[OK] Loaded model: {model_name} ({model_type})")
        return True
    
    except Exception as e:
        logger.error(f"Failed to load model {model_name}: {e}")
        return False


def load_h5_model_to_registry(model_path: Path, model_name: str, model_type: str) -> bool:
    """Load H5 model into registry"""
    try:
        import tensorflow as tf
        from tensorflow import keras
        
        model = keras.models.load_model(model_path)
        
        MODEL_REGISTRY[model_name] = {
            'model': model,
            'type': model_type,
            'format': 'h5',
            'path': str(model_path),
            'loaded_at': datetime.now().isoformat(),
            'version': 1
        }
        
        logger.info(f"[OK] Loaded H5 model: {model_name} ({model_type})")
        return True
    except Exception as e:
        logger.error(f"Failed to load H5 model {model_name}: {e}")
        return False


def load_tflite_model_to_registry(model_path: Path, model_name: str, model_type: str) -> bool:
    """Load TFLite model into registry"""
    try:
        import tensorflow as tf
        
        interpreter = tf.lite.Interpreter(model_path=str(model_path))
        interpreter.allocate_tensors()
        
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()
        
        MODEL_REGISTRY[model_name] = {
            'model': {
                'interpreter': interpreter,
                'input_details': input_details,
                'output_details': output_details
            },
            'type': model_type,
            'format': 'tflite',
            'path': str(model_path),
            'loaded_at': datetime.now().isoformat(),
            'version': 1
        }
        
        logger.info(f"[OK] Loaded TFLite model: {model_name} ({model_type})")
        return True
    except Exception as e:
        logger.error(f"Failed to load TFLite model {model_name}: {e}")
        return False


def load_multifile_model_to_registry(model_dir: Path, model_name: str, model_type: str) -> bool:
    """Load multi-file model (e.g., backdoor detection with model + encoders + scaler)"""
    try:
        # Load model
        model_file = model_dir / "backdoor_model.pkl"
        if not model_file.exists():
            model_file = model_dir / f"{model_type}_model.pkl"
        
        if not model_file.exists():
            logger.error(f"Model file not found in {model_dir}")
            return False
        
        with open(model_file, 'rb') as f:
            model = pickle.load(f)
        
        # Load encoders if available
        encoders_file = model_dir / "label_encoders.pkl"
        encoders = None
        if encoders_file.exists():
            with open(encoders_file, 'rb') as f:
                encoders = pickle.load(f)
        
        # Load scaler if available
        scaler_file = model_dir / "scaler.pkl"
        scaler = None
        if scaler_file.exists():
            with open(scaler_file, 'rb') as f:
                scaler = pickle.load(f)
        
        MODEL_REGISTRY[model_name] = {
            'model': {
                'classifier': model,
                'encoders': encoders,
                'scaler': scaler
            },
            'type': model_type,
            'format': 'multifile',
            'path': str(model_dir),
            'loaded_at': datetime.now().isoformat(),
            'version': 1
        }
        
        logger.info(f"[OK] Loaded multi-file model: {model_name} ({model_type})")
        return True
    except Exception as e:
        logger.error(f"Failed to load multi-file model {model_name}: {e}")
        return False


def load_all_models():
    """Load all models from fl_models and models directories"""
    loaded_count = 0
    
    # Define expected FL models (pkl format)
    expected_models = {
        'sqli_model.pkl': ('sqli', 'SQL Injection Detector'),
        'ddos_model.pkl': ('ddos', 'DDoS Attack Detector'),
        'xss_model.pkl': ('xss', 'XSS Attack Detector'),
        'general_model.pkl': ('general', 'General Threat Detector'),
    }
    
    # Define TensorFlow models (H5 and TFLite)
    ml_models_dir = Path("models")
    tf_models = {
        'domain_classifier.h5': ('domain', 'Domain/DNS Classifier'),
        'gnn_fingerprint.tflite': ('gnn', 'GNN Network Fingerprinting'),
    }
    
    # Define multi-file models (directories)
    multi_file_models = {
        'backdoor_detection': ('backdoor', 'Backdoor Detection')
    }
    
    # Load FL models (PKL format)
    for filename, (model_type, description) in expected_models.items():
        model_path = MODELS_DIR / filename
        
        if model_path.exists():
            if load_model(model_path, model_type, model_type):
                loaded_count += 1
        else:
            logger.warning(f"Model not found: {model_path}")
            # Create placeholder model
            MODEL_REGISTRY[model_type] = {
                'model': create_placeholder_model(model_type),
                'type': model_type,
                'path': 'placeholder',
                'loaded_at': datetime.now().isoformat(),
                'version': 0
            }
            logger.info(f"Created placeholder model for {model_type}")
    
    # Load TensorFlow models (H5 and TFLite)
    for filename, (model_type, description) in tf_models.items():
        model_path = ml_models_dir / filename
        
        if model_path.exists():
            if filename.endswith('.h5'):
                if load_h5_model_to_registry(model_path, model_type, model_type):
                    loaded_count += 1
            elif filename.endswith('.tflite'):
                if load_tflite_model_to_registry(model_path, model_type, model_type):
                    loaded_count += 1
        else:
            logger.warning(f"TF Model not found: {model_path}")
    
    # Load multi-file models (directories with multiple PKL files)
    for dir_name, (model_type, description) in multi_file_models.items():
        model_dir = ml_models_dir / dir_name
        
        if model_dir.exists() and model_dir.is_dir():
            if load_multifile_model_to_registry(model_dir, model_type, model_type):
                loaded_count += 1
        else:
            logger.warning(f"Multi-file model directory not found: {model_dir}")
    
    logger.info(f"Loaded {loaded_count} models, {len(MODEL_REGISTRY)} total (including placeholders)")
    return loaded_count


def create_placeholder_model(model_type: str):
    """Create a simple placeholder model"""
    class PlaceholderModel:
        
        def __init__(self, model_type):
            self.model_type = model_type
            self.is_placeholder = True
        
        def predict(self, X):
            # Always predict benign (0)
            if isinstance(X, (list, np.ndarray)):
                return np.zeros(len(X) if hasattr(X, '__len__') else 1)
            return np.array([0])
        
        def predict_proba(self, X):
            # Return neutral probabilities
            if isinstance(X, (list, np.ndarray)):
                n = len(X) if hasattr(X, '__len__') else 1
                return np.array([[0.9, 0.1]] * n)
            return np.array([[0.9, 0.1]])
    
    return PlaceholderModel(model_type)


# Feature Extraction

def extract_features_from_request(
    req: PredictionRequest, 
    model_type: str
) -> np.ndarray:
    """
    Extract and format features for specific model type
    
    Different models may expect different feature sets
    """
    features = req.features.copy()
    
    # Common feature extraction
    feature_dict = {
        # Network features
        'src_port': features.get('src_port', 0),
        'dest_port': features.get('dest_port', 0),
        'protocol_num': features.get('protocol_num', 0),
        'payload_size': features.get('payload_size', 0),
        'packet_length': features.get('packet_length', 0),
        
        # Flow features
        'flow_duration': features.get('flow_duration', 0),
        'total_fwd_packets': features.get('total_fwd_packets', 0),
        'total_bwd_packets': features.get('total_bwd_packets', 0),
        'flow_bytes_per_sec': features.get('flow_bytes_per_sec', 0),
        'flow_packets_per_sec': features.get('flow_packets_per_sec', 0),
        
        # Payload features
        'payload_entropy': features.get('payload_entropy', 0.0),
        'payload_printable_ratio': features.get('payload_printable_ratio', 1.0),
        
        # Protocol flags
        'has_payload': int(features.get('has_payload', False)),
        'is_encrypted': int(features.get('is_encrypted', False)),
    }
    
    # Model-specific features
    if model_type == 'sqli':
        # SQL Injection specific
        payload = features.get('payload', '')
        feature_dict.update({
            'has_sql_keywords': int(any(kw in payload.lower() for kw in ['select', 'union', 'insert', 'delete', 'drop'])),
            'has_quotes': int("'" in payload or '"' in payload),
            'has_comment': int('--' in payload or '/*' in payload),
        })
    
    elif model_type == 'ddos':
        # DDoS specific
        feature_dict.update({
            'packet_rate': features.get('packet_rate', 0),
            'syn_flag': int(features.get('syn_flag', False)),
            'unique_src_ips': features.get('unique_src_ips', 1),
            'is_fragmented': int(features.get('is_fragmented', False)),
        })
    
    elif model_type == 'xss':
        # XSS specific
        payload = features.get('payload', '')
        feature_dict.update({
            'has_script_tag': int('<script' in payload.lower()),
            'has_event_handler': int(any(ev in payload.lower() for ev in ['onclick', 'onerror', 'onload'])),
            'has_javascript': int('javascript:' in payload.lower()),
        })
    
    # Convert to numpy array
    # Note: In production, you'd have a fixed feature order
    feature_vector = np.array([list(feature_dict.values())])
    
    return feature_vector


# API Endpoints

@app.on_event("startup")
async def startup_event():
    """Load models on startup and initialize unified logger"""
    global MAIN_EVENT_LOOP
    
    # Store the event loop for thread-safe operations
    MAIN_EVENT_LOOP = asyncio.get_running_loop()
    
    logger.info("Starting Inference API...")
    load_all_models()
    
    # Initialize unified logger
    try:
        from vajra.pipeline.unified_logger import get_unified_logger
        
        unified_logger = get_unified_logger()
        
        # Register WebSocket broadcast callback
        unified_logger.register_callback(broadcast_event_to_websockets)
        
        # Start unified logger if not already running
        if not unified_logger._running:
            unified_logger.start()
        
        logger.info("[OK] Unified logger integrated with WebSocket streaming")
        logger.info("[OK] Real-time log broadcasting enabled (zero-latency)")
        
    except Exception as e:
        logger.error(f"Failed to initialize unified logger: {e}")
        logger.warning("WebSocket will still work but won't receive unified logs")
    
    logger.info("Inference API ready")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Count real vs placeholder models
    placeholder_count = sum(
        1 for info in MODEL_REGISTRY.values()
        if getattr(info.get('model'), 'is_placeholder', False)
    )
    
    return {
        "status": "healthy",
        "models_loaded": len(MODEL_REGISTRY),
        "real_models": len(MODEL_REGISTRY) - placeholder_count,
        "placeholder_models": placeholder_count,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/models", response_model=List[ModelInfo])
async def list_models():
    """List all loaded models"""
    models_info = []
    
    for name, info in MODEL_REGISTRY.items():
        # Check if model object is a placeholder
        model_obj = info.get('model')
        is_placeholder = getattr(model_obj, 'is_placeholder', False)
        
        models_info.append(ModelInfo(
            name=name,
            type=info['type'],
            loaded=True,
            is_placeholder=is_placeholder,  # <-- Added field
            last_updated=info['loaded_at'],
            version=info['version'],
            metrics=None
        ))
    
    return models_info


@app.post("/predict/{model_type}", response_model=PredictionResponse)
async def predict(model_type: str, request: PredictionRequest):
    """
    Make a prediction using specified model
    
    Args:
        model_type: Type of model (sqli, ddos, xss, general, domain, gnn, backdoor)
        request: Prediction request with features
    
    Returns:
        Prediction response with threat assessment
    """
    start_time = datetime.now()
    
    # Check if model exists
    if model_type not in MODEL_REGISTRY:
        raise HTTPException(
            status_code=404, 
            detail=f"Model '{model_type}' not found"
        )
    
    model_info = MODEL_REGISTRY[model_type]
    model = model_info['model']
    model_format = model_info.get('format', 'pkl')
    
    try:
        # Handle different model formats
        if model_format == 'h5':
            # H5 Keras model (domain classifier)
            result = predict_h5_model(model, request, model_type)
        elif model_format == 'tflite':
            # TFLite model (GNN fingerprint)
            result = predict_tflite_model(model, request, model_type)
        elif model_format == 'multifile':
            # Multi-file model (backdoor detection)
            result = predict_multifile_model(model, request, model_type)
        else:
            # Standard PKL model
            result = predict_pkl_model(model, request, model_type)
        
        # Calculate inference time
        inference_time = (datetime.now() - start_time).total_seconds() * 1000
        
        return PredictionResponse(
            model_name=model_type,
            prediction=result['prediction'],
            confidence=result['confidence'],
            probabilities=result.get('probabilities'),
            is_threat=result['is_threat'],
            threat_type=result.get('threat_type', model_type.upper() if result['is_threat'] else "BENIGN"),
            timestamp=datetime.now().isoformat(),
            inference_time_ms=round(inference_time, 2)
        )
    
    except Exception as e:
        logger.error(f"Prediction error for {model_type}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )


def predict_pkl_model(model, request: PredictionRequest, model_type: str) -> dict:
    """Predict using PKL scikit-learn model"""
    # Extract features
    feature_vector = extract_features_from_request(request, model_type)
    
    # Make prediction
    prediction = int(model.predict(feature_vector)[0])
    
    # Get probabilities if available
    probabilities = None
    confidence = 0.5
    
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(feature_vector)[0]
        probabilities = proba.tolist()
        confidence = float(max(proba))
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'probabilities': probabilities,
        'is_threat': (prediction == 1),
        'threat_type': model_type.upper() if prediction == 1 else "BENIGN"
    }


def predict_h5_model(model, request: PredictionRequest, model_type: str) -> dict:
    """Predict using H5 Keras/TensorFlow model"""
    import numpy as np
    
    # Extract domain-specific features
    features = request.features
    domain = features.get('domain', features.get('query', ''))
    
    # Calculate domain features
    from collections import Counter
    import math
    
    domain_length = len(domain)
    digit_count = sum(c.isdigit() for c in domain)
    special_count = sum(not c.isalnum() and c != '.' for c in domain)
    subdomain_count = domain.count('.')
    
    # Calculate entropy
    if domain:
        counts = Counter(domain)
        total = len(domain)
        entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
    else:
        entropy = 0.0
    
    # Build feature vector
    feature_list = [
        domain_length,
        digit_count / max(domain_length, 1),
        special_count / max(domain_length, 1),
        subdomain_count,
        entropy,
        int(features.get('has_suspicious_tld', False)),
        features.get('query_count', 1),
        features.get('response_time', 0),
    ]
    
    # Pad to match model input
    input_shape = model.input_shape[1]
    if len(feature_list) < input_shape:
        feature_list.extend([0.0] * (input_shape - len(feature_list)))
    elif len(feature_list) > input_shape:
        feature_list = feature_list[:input_shape]
    
    X = np.array([feature_list], dtype=np.float32)
    
    # Make prediction
    predictions = model.predict(X, verbose=0)
    
    # Process output
    if predictions.shape[-1] > 1:
        # Multi-class
        prediction_idx = int(np.argmax(predictions[0]))
        confidence = float(predictions[0][prediction_idx])
        probabilities = predictions[0].tolist()
        class_names = ['benign', 'dga', 'phishing', 'malware']
        threat_type = class_names[prediction_idx] if prediction_idx < len(class_names) else 'unknown'
        is_threat = prediction_idx > 0
    else:
        # Binary
        confidence = float(predictions[0][0])
        probabilities = [1 - confidence, confidence]
        is_threat = confidence > 0.5
        threat_type = 'malicious' if is_threat else 'benign'
        prediction_idx = 1 if is_threat else 0
    
    return {
        'prediction': prediction_idx,
        'confidence': confidence,
        'probabilities': probabilities,
        'is_threat': is_threat,
        'threat_type': threat_type.upper()
    }


def predict_tflite_model(model_dict, request: PredictionRequest, model_type: str) -> dict:
    """Predict using TFLite model"""
    import numpy as np
    
    interpreter = model_dict['interpreter']
    input_details = model_dict['input_details']
    output_details = model_dict['output_details']
    
    # Extract graph features
    features = request.features
    nodes = features.get('nodes', [])
    edges = features.get('edges', [])
    
    # Build input tensor
    input_shape = input_details[0]['shape']
    
    if len(nodes) > 0:
        node_features = []
        for node in nodes:
            node_feat = [
                node.get('port', 0),
                node.get('packet_count', 0),
                node.get('byte_count', 0),
                node.get('connection_count', 0),
            ]
            node_features.append(node_feat)
        
        X = np.array(node_features, dtype=np.float32)
        
        # Reshape to match input
        target_nodes = input_shape[1] if len(input_shape) > 1 else 10
        if X.shape[0] < target_nodes:
            padding = np.zeros((target_nodes - X.shape[0], X.shape[1]), dtype=np.float32)
            X = np.vstack([X, padding])
        elif X.shape[0] > target_nodes:
            X = X[:target_nodes]
        
        X = X.reshape(input_shape)
    else:
        X = np.zeros(input_shape, dtype=np.float32)
    
    # Run inference
    interpreter.set_tensor(input_details[0]['index'], X)
    interpreter.invoke()
    output_data = interpreter.get_tensor(output_details[0]['index'])
    
    # Process output
    if output_data.shape[-1] > 1:
        prediction_idx = int(np.argmax(output_data[0]))
        confidence = float(output_data[0][prediction_idx])
        probabilities = output_data[0].tolist()
        fingerprint_types = ['normal', 'bot', 'scanner', 'exploit']
        threat_type = fingerprint_types[prediction_idx] if prediction_idx < len(fingerprint_types) else 'unknown'
        is_threat = prediction_idx > 0
    else:
        confidence = float(output_data[0][0])
        probabilities = [1 - confidence, confidence]
        is_threat = confidence > 0.5
        threat_type = 'anomalous' if is_threat else 'normal'
        prediction_idx = 1 if is_threat else 0
    
    return {
        'prediction': prediction_idx,
        'confidence': confidence,
        'probabilities': probabilities,
        'is_threat': is_threat,
        'threat_type': threat_type.upper()
    }


def predict_multifile_model(model_dict, request: PredictionRequest, model_type: str) -> dict:
    """Predict using multi-file model (e.g., backdoor detection)"""
    import numpy as np
    from collections import Counter
    import math
    
    classifier = model_dict['classifier']
    encoders = model_dict.get('encoders')
    scaler = model_dict.get('scaler')
    
    features = request.features
    domain = features.get('domain', features.get('query', ''))
    
    # Build feature dictionary
    feature_dict = {
        'domain_length': len(domain),
        'digit_count': sum(c.isdigit() for c in domain),
        'special_char_count': sum(not c.isalnum() and c != '.' for c in domain),
        'subdomain_count': domain.count('.'),
        'has_http': int('http' in domain.lower()),
        'has_https': int('https' in domain.lower()),
    }
    
    # Calculate entropy
    if domain:
        counts = Counter(domain)
        total = len(domain)
        entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
        feature_dict['entropy'] = entropy
    else:
        feature_dict['entropy'] = 0.0
    
    # Add additional features from request
    for key in ['port', 'ip_address', 'protocol', 'packet_count', 'byte_count']:
        if key in features:
            feature_dict[key] = features[key]
    
    # Apply label encoding if available
    if encoders:
        for field, encoder in encoders.items():
            if field in feature_dict and hasattr(encoder, 'transform'):
                try:
                    feature_dict[field] = encoder.transform([feature_dict[field]])[0]
                except:
                    pass
    
    # Get feature order from model
    if hasattr(classifier, 'feature_names_in_'):
        feature_order = classifier.feature_names_in_
    else:
        feature_order = sorted(feature_dict.keys())
    
    # Build feature array
    X = np.array([[feature_dict.get(f, 0) for f in feature_order]])
    
    # Apply scaling if available
    if scaler:
        X = scaler.transform(X)
    
    # Make prediction
    prediction = int(classifier.predict(X)[0])
    
    # Get probabilities
    probabilities = None
    confidence = 0.5
    if hasattr(classifier, 'predict_proba'):
        proba = classifier.predict_proba(X)[0]
        probabilities = proba.tolist()
        confidence = float(max(proba))
    
    is_threat = prediction == 1
    threat_type = 'BACKDOOR' if is_threat else 'BENIGN'
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'probabilities': probabilities,
        'is_threat': is_threat,
        'threat_type': threat_type
    }


@app.post("/reload")
async def reload_models(background_tasks: BackgroundTasks):
    """Reload all models from disk"""
    # Reload in background to avoid blocking
    background_tasks.add_task(load_all_models)
    
    return {
        "status": "reloading",
        "message": "Models are being reloaded in background"
    }


# WebSocket Endpoints for Real-Time Unified Logs

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """
    WebSocket endpoint for real-time unified log streaming
    
    Streams all logs in real-time:
    - Suricata eve.json alerts
    - ML predictions (FL models)
    - SOAR actions
    - Packet inspection (Scapy)
    - System events
    
    Query parameters:
    - event_types: Comma-separated list (e.g., "suricata_alert,ml_prediction")
    - threat_levels: Comma-separated list (e.g., "critical,high")
    - components: Comma-separated list (e.g., "suricata,ml_engine")
    - min_confidence: Minimum confidence threshold (0.0-1.0)
    """
    await manager.connect(websocket)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "message": "Real-time unified log stream connected",
            "timestamp": datetime.now().isoformat()
        })
        
        # Keep connection alive and handle client messages
        while True:
            try:
                # Receive filter updates from client
                data = await websocket.receive_json()
                
                if data.get('type') == 'update_filters':
                    filters = data.get('filters', {})
                    manager.filters[websocket] = filters
                    await websocket.send_json({
                        "type": "filters_updated",
                        "filters": filters,
                        "timestamp": datetime.now().isoformat()
                    })
                    logger.info(f"Updated filters for client: {filters}")
                
                elif data.get('type') == 'ping':
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    })
            
            except asyncio.TimeoutError:
                # Send periodic heartbeat if no client activity
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": datetime.now().isoformat(),
                    "active_connections": len(manager.active_connections)
                })
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)


@app.get("/ws/stats")
async def websocket_stats():
    """Get WebSocket connection statistics"""
    return {
        "active_connections": len(manager.active_connections),
        "timestamp": datetime.now().isoformat()
    }


# Unified Logger Integration

def broadcast_event_to_websockets(event):
    """
    Callback function for UnifiedLogger to broadcast events to WebSocket clients
    This is called BEFORE/DURING disk writes for zero-latency streaming
    """
    global MAIN_EVENT_LOOP
    
    try:
        # Convert dataclass to dict if needed
        if hasattr(event, '__dict__'):
            from dataclasses import asdict
            event_dict = asdict(event)
        else:
            event_dict = event
        
        # Use the saved event loop reference
        if MAIN_EVENT_LOOP is None:
            # API not started yet or shutting down
            return
        
        # Schedule the broadcast in the event loop
        asyncio.run_coroutine_threadsafe(manager.broadcast(event_dict), MAIN_EVENT_LOOP)
        
    except Exception as e:
        logger.error(f"Failed to broadcast event to WebSockets: {e}")


# Removed duplicate startup_event - merged into the first one above


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    try:
        from vajra.pipeline.unified_logger import get_unified_logger
        unified_logger = get_unified_logger()
        unified_logger.stop()
        logger.info("Unified logger stopped")
    except:
        pass


# Main Entry Point

def main():
    """Run the API server"""
    # Ensure logs directory exists
    Path("logs").mkdir(exist_ok=True)
    
    # Run server
    uvicorn.run(
        app,
        host=os.environ.get("VAJRA_API_HOST", "127.0.0.1"),
        port=8001,
        log_level="info"
    )


if __name__ == "__main__":
    main()
