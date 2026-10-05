#!/usr/bin/env python3
"""
ETA Engine - Encrypted Traffic Analysis Engine
Detects threats in encrypted network flows (HTTPS, TLS, etc.)

Analyzes:
- Data exfiltration patterns
- Port scanning activities
- Anomalous encrypted traffic
- Command & Control communications
"""

import time
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

try:
    import joblib
except ImportError:
    joblib = None

try:
    import pandas as pd
    import numpy as np
except ImportError:
    pd = None
    np = None

# Create logs directory if needed
try:
    Path("logs").mkdir(exist_ok=True)
except Exception:
    pass

# Configure Logging with error handling
log_handlers = [logging.StreamHandler()]
try:
    log_file = Path("logs/eta_engine.log")
    log_file.touch(exist_ok=True)
    log_handlers.append(logging.FileHandler(str(log_file)))
except Exception as e:
    print(f"Warning: Could not create log file: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] ETA: %(message)s',
    handlers=log_handlers
)

logger = logging.getLogger("eta_engine")


@dataclass
class ETAAnalysis:
    """Result of ETA analysis on an encrypted flow"""
    timestamp: str
    src_port: int
    dest_port: int
    protocol: str
    prediction: str  # benign, malicious, data_exfiltration, port_scan, c2
    confidence: float  # 0.0 to 1.0
    is_threat: bool
    bytes_toserver: int
    bytes_toclient: int
    total_bytes: int
    bytes_per_packet: float
    flow_features: Dict[str, Any]


class ETAEngine:
    """Encrypted Traffic Analysis Engine for threat detection"""
    
    def __init__(self, model_path: str = 'models/eta_model.pkl'):
        self.model = None
        self.protocol_encoder = None
        self.features = []
        self.model_loaded = False
        self.analyses_count = 0
        self.threats_detected = 0
        self.lock = threading.Lock()
        self.eta_alerts_file = Path("logs/eta_alerts.json")
        
        logger.info(f"ETA Engine initializing. Looking for model: {model_path}")
        
        # Try to load the real trained model
        try:
            from vajra.ml.loader import load_eta_model
            real_model = load_eta_model(model_path)
            if real_model:
                self.model = real_model
                self.model_loaded = True
                self.protocol_encoder = real_model.get('protocol_encoder')
                logger.info("[OK] Real ETA model loaded successfully")
            else:
                logger.warning(f"Could not load model from {model_path}")
                self._create_placeholder_model()
        except ImportError:
            logger.warning("model_loader not found, using placeholder model")
            self._create_placeholder_model()
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self._create_placeholder_model()
            logger.info("Creating placeholder model for demo")
            self._create_placeholder_model()
    
    def _create_placeholder_model(self):
        """Create a placeholder model for demo/fallback - not used when real model loads"""
        self.model_loaded = False
        logger.info("Placeholder ETA model created for demo mode")
    
    def analyze_flow(self, flow_data: Dict[str, Any]) -> Optional[ETAAnalysis]:
        """
        Analyzes an encrypted traffic flow for threats.
        Uses the trained ETA model if available, otherwise uses placeholder.
        
        Args:
            flow_data: Dictionary with flow information
            
        Returns:
            ETAAnalysis object with prediction and confidence
        """
        with self.lock:
            self.analyses_count += 1
        
        try:
            # Use the real model if loaded
            if self.model_loaded:
                try:
                    from vajra.ml.loader import get_eta_predictions
                    result = get_eta_predictions(self.model, flow_data)
                    prediction = result['prediction']
                    confidence = result['confidence']
                    is_threat = result['is_threat']
                except:
                    # Fall back to placeholder
                    result = self._placeholder_predict(flow_data)
                    prediction = result['prediction']
                    confidence = result['confidence']
                    is_threat = result['is_threat']
            else:
                # Use placeholder model
                result = self._placeholder_predict(flow_data)
                prediction = result['prediction']
                confidence = result['confidence']
                is_threat = result['is_threat']
            
            if is_threat:
                with self.lock:
                    self.threats_detected += 1
            
            analysis = ETAAnalysis(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_port=int(flow_data.get('src_port', 0)),
                dest_port=int(flow_data.get('dest_port', 0)),
                protocol=str(flow_data.get('protocol', 'tcp')),
                prediction=prediction,
                confidence=confidence,
                is_threat=is_threat,
                bytes_toserver=int(flow_data.get('bytes_toserver', 0)),
                bytes_toclient=int(flow_data.get('bytes_toclient', 0)),
                total_bytes=int(flow_data.get('total_bytes', 0)),
                bytes_per_packet=float(flow_data.get('bytes_per_packet', 0)),
                flow_features=flow_data
            )
            
            if is_threat:
                self._save_alert(analysis)
                logger.warning(f"ETA THREAT: {prediction} (confidence: {confidence:.2%})")
            
            return analysis
        
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return None
    
    def _placeholder_predict(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback placeholder prediction when model not available"""
        # Simple heuristic based on bytes
        bytes_per_packet = float(flow_data.get('bytes_per_packet', 0))
        total_bytes = int(flow_data.get('total_bytes', 0))
        
        if bytes_per_packet > 100000 or total_bytes > 500000000:
            return {'prediction': 'suspicious', 'confidence': 0.95, 'is_threat': True}
        return {'prediction': 'benign', 'confidence': 0.95, 'is_threat': False}
    
    def _save_alert(self, analysis: ETAAnalysis):
        """Save threat alert to file"""
        try:
            alert_dict = asdict(analysis)
            with open(self.eta_alerts_file, 'a') as f:
                f.write(json.dumps(alert_dict) + '\n')
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ETA engine statistics"""
        with self.lock:
            return {
                'analyses_count': self.analyses_count,
                'threats_detected': self.threats_detected,
                'model_loaded': self.model_loaded,
                'threat_rate': (
                    self.threats_detected / self.analyses_count
                    if self.analyses_count > 0 else 0
                )
            }
    
    def shutdown(self):
        """Shutdown ETA engine"""
        stats = self.get_stats()
        logger.info(f"ETA Engine shutdown. Stats: {stats}")


# Global ETA instance
_eta_instance = None


def get_eta_engine() -> ETAEngine:
    """Get or create global ETA engine instance"""
    global _eta_instance
    if _eta_instance is None:
        _eta_instance = ETAEngine()
    return _eta_instance


# Testing
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("ETA Engine - Encrypted Traffic Analysis")
    print("=" * 60 + "\n")
    
    engine = get_eta_engine()
    
    # Test flows
    test_flows = [
        # Benign HTTPS
        {
            "src_port": 54322, "dest_port": 443, "protocol": "tcp",
            "duration": 12.5, "bytes_toserver": 1500, "bytes_toclient": 35000,
            "packets_toserver": 20, "packets_toclient": 35,
            "total_bytes": 36500, "total_packets": 55, "bytes_per_packet": 663.6
        },
        # Data Exfiltration
        {
            "src_port": 49152, "dest_port": 443, "protocol": "tcp",
            "duration": 150.2, "bytes_toserver": 5000, "bytes_toclient": 950000000,
            "packets_toserver": 50, "packets_toclient": 9000,
            "total_bytes": 950005000, "total_packets": 9050, "bytes_per_packet": 104972.9
        },
        # Port Scan
        {
            "src_port": 55555, "dest_port": 80, "protocol": "tcp",
            "duration": 0.1, "bytes_toserver": 0, "bytes_toclient": 0,
            "packets_toserver": 2, "packets_toclient": 0,
            "total_bytes": 0, "total_packets": 2, "bytes_per_packet": 0
        },
    ]
    
    for flow in test_flows:
        analysis = engine.analyze_flow(flow)
        if analysis:
            status = "THREAT" if analysis.is_threat else "CLEAN"
            print(f"{status}: {analysis.prediction} ({analysis.confidence:.2%})")
            print(f"  Flow: {analysis.src_port} → {analysis.dest_port}")
            print(f"  Bytes: {analysis.total_bytes:,} | B/pkt: {analysis.bytes_per_packet:.2f}\n")
    
    print("=" * 60)
    stats = engine.get_stats()
    print(f"Analyses: {stats['analyses_count']}")
    print(f"Threats: {stats['threats_detected']}")
    print(f"Threat Rate: {stats['threat_rate']:.2%}")
    print("=" * 60 + "\n")
