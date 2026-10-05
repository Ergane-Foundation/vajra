#!/usr/bin/env python3
"""
ML Model Manager - Manages multiple ML models for threat detection

Supports loading various models including:
- Insider Threat Detection (CERT dataset trained)
- Network Anomaly Detection
- DDoS Detection
- Custom models

Models are loaded dynamically and can be added at runtime.
"""

import pickle
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict

# Create logs directory if needed
try:
    Path("logs").mkdir(exist_ok=True)
except Exception:
    pass

# Core ML/Data dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: numpy not installed. ML models will not work.")
    # Create a dummy numpy module to prevent AttributeError on type hints
    class DummyNumpyModule:
        """Dummy numpy module when numpy is not installed"""
        class ndarray:
            pass
        @staticmethod
        def array(x):
            return x
    np = DummyNumpyModule()

# Optional imports for specific model types
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import sklearn
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# Setup logging with error handling
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/ml_model_manager.log')
        ]
    )
except Exception:
    # Fallback to console-only logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler()]
    )

logger = logging.getLogger("ml_model_manager")


@dataclass
class MLPrediction:
    """Result of an ML model prediction"""
    model_name: str
    timestamp: str
    prediction: int
    confidence: float
    probabilities: Optional[List[float]]
    is_threat: bool
    threat_type: str
    features_used: Dict[str, Any]
    raw_input: Dict[str, Any]
    inference_time_ms: float


@dataclass  
class ModelConfig:
    """Configuration for a loaded model"""
    name: str
    path: str
    model_type: str  # 'insider_threat', 'anomaly', 'ddos', 'custom'
    feature_names: List[str]
    threshold: float
    enabled: bool
    loaded_at: str


class FeatureExtractor:
    """Extracts features from various data sources for ML models"""
    
    @staticmethod
    def extract_network_features(packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from network packet data"""
        return {
            'src_ip': packet_data.get('src_ip', ''),
            'dst_ip': packet_data.get('dst_ip', ''),
            'src_port': packet_data.get('src_port', 0),
            'dst_port': packet_data.get('dst_port', 0),
            'protocol': packet_data.get('protocol', 0),
            'packet_size': packet_data.get('size', 0),
            'flags': packet_data.get('flags', 0),
            'ttl': packet_data.get('ttl', 64),
            'payload_size': len(packet_data.get('payload', b'')),
            'timestamp': packet_data.get('timestamp', 0),
        }
    
    @staticmethod
    def extract_insider_threat_features(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features for insider threat detection
        Based on CERT dataset structure:
        - logon/logoff events
        - file access patterns  
        - email activity
        - HTTP activity
        - device usage
        """
        features = {
            # User behavior features
            'user_id': event_data.get('user', ''),
            'hour_of_day': 0,
            'day_of_week': 0,
            'is_after_hours': 0,
            'is_weekend': 0,
            
            # Activity features
            'activity_type': event_data.get('activity', ''),
            'pc_id': event_data.get('pc', ''),
            
            # Network features
            'src_ip': event_data.get('src_ip', ''),
            'dst_ip': event_data.get('dest_ip', ''),
            'bytes_sent': event_data.get('bytes_sent', 0),
            'bytes_received': event_data.get('bytes_received', 0),
            
            # Email features
            'email_to_count': len(event_data.get('to', '').split(';')) if event_data.get('to') else 0,
            'email_cc_count': len(event_data.get('cc', '').split(';')) if event_data.get('cc') else 0,
            'email_bcc_count': len(event_data.get('bcc', '').split(';')) if event_data.get('bcc') else 0,
            'email_attachment_count': event_data.get('attachments', 0),
            'email_external': 0,  # 1 if sending to external domain
            
            # File access features
            'file_extension': '',
            'file_operation': event_data.get('operation', ''),
            'sensitive_file': 0,
            
            # USB/Device features
            'device_connected': 1 if event_data.get('activity') == 'Connect' else 0,
            
            # HTTP features
            'url_category': event_data.get('category', ''),
            'data_upload': event_data.get('content_length', 0),
        }
        
        # Parse timestamp for time-based features
        timestamp = event_data.get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                features['hour_of_day'] = dt.hour
                features['day_of_week'] = dt.weekday()
                features['is_after_hours'] = 1 if (dt.hour < 6 or dt.hour > 20) else 0
                features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
            except:
                pass
        
        return features
    
    @staticmethod
    def extract_flow_features(flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from network flow data"""
        return {
            'duration': flow_data.get('duration', 0),
            'bytes_toserver': flow_data.get('bytes_toserver', 0),
            'bytes_toclient': flow_data.get('bytes_toclient', 0),
            'pkts_toserver': flow_data.get('pkts_toserver', 0),
            'pkts_toclient': flow_data.get('pkts_toclient', 0),
            'src_ip': flow_data.get('src_ip', ''),
            'dst_ip': flow_data.get('dest_ip', ''),
            'src_port': flow_data.get('src_port', 0),
            'dst_port': flow_data.get('dest_port', 0),
            'protocol': flow_data.get('proto', ''),
            'app_proto': flow_data.get('app_proto', ''),
        }
    
    @staticmethod
    def features_to_array(features: Dict[str, Any], feature_names: List[str]) -> np.ndarray:
        """Convert feature dict to numpy array based on expected feature names"""
        arr = []
        for name in feature_names:
            val = features.get(name, 0)
            # Convert non-numeric to numeric
            if isinstance(val, str):
                val = hash(val) % 10000  # Simple hash for categorical
            elif isinstance(val, bool):
                val = int(val)
            elif val is None:
                val = 0
            arr.append(float(val))
        return np.array([arr])


class MLModelManager:
    """
    Manages multiple ML models for threat detection
    
    Features:
    - Load multiple models (pickle, joblib)
    - Run predictions with feature extraction
    - Thread-safe operations
    - Combined logging with Suricata alerts
    """
    
    def __init__(self, models_dir: str = "models", log_file: str = "logs/ml_predictions.json"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.models: Dict[str, Any] = {}
        self.configs: Dict[str, ModelConfig] = {}
        self.feature_extractor = FeatureExtractor()
        self._lock = threading.Lock()
        
        # Prediction callbacks (for SOAR integration)
        self.callbacks: List[Callable[[MLPrediction], None]] = []
        
        # Statistics
        self.stats = {
            'total_predictions': 0,
            'threats_detected': 0,
            'by_model': {}
        }
        
        logger.info(f"ML Model Manager initialized. Models dir: {self.models_dir}")
        
        # Auto-load any available models
        self._auto_load_models()
    
    def register_callback(self, callback: Callable[[MLPrediction], None]):
        """Register a callback to be called on each prediction"""
        self.callbacks.append(callback)
    
    def _auto_load_models(self):
        """Auto-load all .pkl and .joblib models from models directory"""
        if not self.models_dir.exists():
            logger.debug(f"Models directory does not exist: {self.models_dir}")
            return
        
        # Find all model files
        pkl_files = list(self.models_dir.glob("*.pkl"))
        joblib_files = list(self.models_dir.glob("*.joblib"))
        
        total_models = len(pkl_files) + len(joblib_files)
        
        if total_models == 0:
            logger.warning(f"No model files found in {self.models_dir}")
            return
        
        logger.info(f"Found {total_models} model file(s) to auto-load")
        
        # Load pickle files
        for model_file in pkl_files:
            model_name = model_file.stem
            model_type = self._infer_model_type(model_name)
            
            try:
                success = self.load_model(
                    name=model_name,
                    model_path=str(model_file),
                    model_type=model_type
                )
                if success:
                    logger.info(f"[OK] Auto-loaded model: {model_name} ({model_type})")
                else:
                    logger.warning(f"[FAIL] Failed to auto-load model: {model_name}")
            except Exception as e:
                logger.error(f"Error auto-loading {model_name}: {e}")
        
        # Load joblib files
        for model_file in joblib_files:
            model_name = model_file.stem
            model_type = self._infer_model_type(model_name)
            
            try:
                success = self.load_model(
                    name=model_name,
                    model_path=str(model_file),
                    model_type=model_type
                )
                if success:
                    logger.info(f"[OK] Auto-loaded model: {model_name} ({model_type})")
                else:
                    logger.warning(f"[FAIL] Failed to auto-load model: {model_name}")
            except Exception as e:
                logger.error(f"Error auto-loading {model_name}: {e}")
        
        logger.info(f"Auto-load complete. Total models loaded: {len(self.models)}")
    
    def _infer_model_type(self, model_name: str) -> str:
        """Infer model type from filename"""
        name_lower = model_name.lower()
        
        if 'insider' in name_lower or 'threat' in name_lower:
            return 'insider_threat'
        elif 'anomaly' in name_lower:
            return 'anomaly'
        elif 'ddos' in name_lower or 'dos' in name_lower:
            return 'ddos'
        else:
            return 'custom'
    
    def _create_placeholder_model(self, name: str, model_type: str):
        """Create a placeholder model that returns neutral predictions"""
        class PlaceholderModel:
            def __init__(self, model_type):
                self.model_type = model_type
            
            def predict(self, X):
                """Return neutral prediction (no threat)"""
                if isinstance(X, list):
                    return [0] * len(X)
                return 0
            
            def predict_proba(self, X):
                """Return neutral probability distribution"""
                if isinstance(X, list):
                    return [[0.7, 0.3]] * len(X)  # 70% benign, 30% threat
                return [0.7, 0.3]
            
            def __repr__(self):
                return f"PlaceholderModel({self.model_type})"
        
        return PlaceholderModel(model_type)
    
    def load_model(
        self, 
        name: str, 
        model_path: str, 
        model_type: str = "custom",
        feature_names: List[str] = None,
        threshold: float = 0.5
    ) -> bool:
        """
        Load a model from file
        
        Args:
            name: Unique name for the model
            model_path: Path to model file (.pkl, .joblib)
            model_type: Type of model ('insider_threat', 'anomaly', 'ddos', 'custom')
            feature_names: List of feature names expected by model
            threshold: Probability threshold for threat classification
        """
        try:
            path = Path(model_path)
            if not path.exists():
                logger.error(f"Model file not found: {model_path}")
                return False
            
            # Load model based on extension
            model = None
            try:
                if path.suffix in ('.pkl', '.pickle'):
                    with open(path, 'rb') as f:
                        model = pickle.load(f)
                elif path.suffix == '.joblib' and JOBLIB_AVAILABLE:
                    model = joblib.load(path)
                else:
                    logger.error(f"Unsupported model format: {path.suffix}")
                    return False
            except (pickle.UnpicklingError, AttributeError, ModuleNotFoundError) as e:
                logger.warning(f"Could not unpickle model (class reference missing): {e}")
                logger.info(f"Creating placeholder model for {name}")
                # Create a placeholder model that returns neutral predictions
                model = self._create_placeholder_model(name, model_type)
                if not model:
                    return False
            
            # Validate model has predict method
            if not hasattr(model, 'predict'):
                logger.warning(f"Loaded object from {path.name} is not a model (type: {type(model).__name__})")
                logger.info(f"Skipping {name} - appears to be a preprocessor or other component, not a trained model")
                return False
            
            # Store model and config
            with self._lock:
                self.models[name] = model
                self.configs[name] = ModelConfig(
                    name=name,
                    path=str(path),
                    model_type=model_type,
                    feature_names=feature_names or [],
                    threshold=threshold,
                    enabled=True,
                    loaded_at=datetime.now(timezone.utc).isoformat()
                )
                self.stats['by_model'][name] = {'predictions': 0, 'threats': 0}
            
            logger.info(f"[OK] Loaded model: {name} ({model_type}) from {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {name}: {e}")
            return False
    
    def unload_model(self, name: str) -> bool:
        """Unload a model"""
        with self._lock:
            if name in self.models:
                del self.models[name]
                del self.configs[name]
                logger.info(f"Unloaded model: {name}")
                return True
        return False
    
    def list_models(self) -> List[Dict[str, Any]]:
        """List all loaded models"""
        with self._lock:
            return [asdict(cfg) for cfg in self.configs.values()]
    
    def predict(
        self, 
        model_name: str, 
        data: Dict[str, Any],
        data_type: str = "network"
    ) -> Optional[MLPrediction]:
        """
        Run prediction on a specific model
        
        Args:
            model_name: Name of the model to use
            data: Input data (packet, flow, event, etc.)
            data_type: Type of data ('network', 'insider', 'flow')
        
        Returns:
            MLPrediction object or None if failed
        """
        with self._lock:
            if model_name not in self.models:
                logger.warning(f"Model not loaded: {model_name}")
                return None
            
            model = self.models[model_name]
            config = self.configs[model_name]
            
            if not config.enabled:
                return None
        
        start_time = datetime.now()
        
        try:
            # Extract features based on data type
            if data_type == "network":
                features = self.feature_extractor.extract_network_features(data)
            elif data_type == "insider":
                features = self.feature_extractor.extract_insider_threat_features(data)
            elif data_type == "flow":
                features = self.feature_extractor.extract_flow_features(data)
            else:
                features = data  # Assume already extracted
            
            # Convert to array
            if config.feature_names:
                X = self.feature_extractor.features_to_array(features, config.feature_names)
            else:
                # Try to use all numeric features
                numeric_features = {k: v for k, v in features.items() 
                                   if isinstance(v, (int, float))}
                X = np.array([list(numeric_features.values())])
            
            # Run prediction with error handling
            pred_result = model.predict(X)
            # Handle both array and scalar returns
            if isinstance(pred_result, (list, np.ndarray)):
                prediction = int(pred_result[0]) if len(pred_result) > 0 else 0
            else:
                prediction = int(pred_result)
            
            # Get probability if available
            probabilities = None
            confidence = 0.0
            if hasattr(model, 'predict_proba'):
                try:
                    proba_result = model.predict_proba(X)
                    if isinstance(proba_result, (list, np.ndarray)):
                        proba = proba_result[0] if len(proba_result) > 0 else [0.5, 0.5]
                    else:
                        proba = [0.5, 0.5]
                    probabilities = [float(p) for p in proba]
                    confidence = float(max(proba))
                except Exception as e:
                    logger.debug(f"predict_proba error: {e}")
                    confidence = 0.5
            elif hasattr(model, 'decision_function'):
                try:
                    decision_result = model.decision_function(X)
                    if isinstance(decision_result, (list, np.ndarray)):
                        decision = decision_result[0] if len(decision_result) > 0 else 0
                    else:
                        decision = decision_result
                    confidence = abs(float(decision))
                except Exception as e:
                    logger.debug(f"decision_function error: {e}")
                    confidence = 0.5
            else:
                confidence = 1.0 if prediction == 1 else 0.0
            
            # Determine if threat based on threshold
            is_threat = prediction == 1 and confidence >= config.threshold
            
            # Determine threat type
            threat_type = self._classify_threat(config.model_type, features, prediction)
            
            inference_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result = MLPrediction(
                model_name=model_name,
                timestamp=datetime.now(timezone.utc).isoformat(),
                prediction=prediction,
                confidence=confidence,
                probabilities=probabilities,
                is_threat=is_threat,
                threat_type=threat_type,
                features_used=features,
                raw_input=data,
                inference_time_ms=round(inference_time, 2)
            )
            
            # Update stats
            with self._lock:
                self.stats['total_predictions'] += 1
                self.stats['by_model'][model_name]['predictions'] += 1
                if is_threat:
                    self.stats['threats_detected'] += 1
                    self.stats['by_model'][model_name]['threats'] += 1
            
            # Log prediction
            self._log_prediction(result)
            
            # Call callbacks
            for callback in self.callbacks:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction error for {model_name}: {e}")
            return None
    
    def predict_all(
        self, 
        data: Dict[str, Any],
        data_type: str = "network"
    ) -> Dict[str, MLPrediction]:
        """Run prediction on all enabled models"""
        results = {}
        for name, config in self.configs.items():
            if config.enabled:
                result = self.predict(name, data, data_type)
                if result:
                    results[name] = result
        return results
    
    def _classify_threat(
        self, 
        model_type: str, 
        features: Dict[str, Any], 
        prediction: int
    ) -> str:
        """Classify threat type based on model and features"""
        if prediction == 0:
            return "none"
        
        if model_type == "insider_threat":
            if features.get('is_after_hours') or features.get('is_weekend'):
                return "suspicious_access_time"
            if features.get('device_connected'):
                return "suspicious_device_usage"
            if features.get('email_external'):
                return "data_exfiltration_email"
            if features.get('data_upload', 0) > 10000:
                return "data_exfiltration_http"
            return "insider_threat"
        
        elif model_type == "anomaly":
            return "network_anomaly"
        
        elif model_type == "ddos":
            return "ddos_attack"
        
        return "ml_detected_threat"
    
    def _log_prediction(self, prediction: MLPrediction):
        """Log prediction to JSON file"""
        try:
            with open(self.log_file, 'a') as f:
                log_entry = asdict(prediction)
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to log prediction: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get prediction statistics"""
        with self._lock:
            return self.stats.copy()


# Singleton instance for global access
_manager_instance: Optional[MLModelManager] = None


def get_model_manager() -> MLModelManager:
    """Get or create the global MLModelManager instance"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = MLModelManager()
    return _manager_instance


def main():
    """Test the model manager"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ML Model Manager")
    parser.add_argument("--load", help="Load a model file")
    parser.add_argument("--name", default="test_model", help="Model name")
    parser.add_argument("--type", default="custom", help="Model type")
    parser.add_argument("--list", action="store_true", help="List loaded models")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    args = parser.parse_args()
    
    manager = get_model_manager()
    
    if args.load:
        success = manager.load_model(args.name, args.load, args.type)
        print(f"Model loaded: {success}")
    
    if args.list:
        print("\nLoaded models:")
        for model in manager.list_models():
            print(f"  - {model['name']} ({model['model_type']})")
    
    if args.stats:
        print("\nStatistics:")
        print(json.dumps(manager.get_stats(), indent=2))


if __name__ == "__main__":
    main()
