#!/usr/bin/env python3
"""
Advanced Threat Detection Orchestrator
Integrates all detection engines into a unified pipeline

Engines:
1. FlowPrint - Device/App fingerprinting
2. Kitsune - Online anomaly detection (autoencoders)
3. ET-BERT - Encrypted traffic classification
4. Stratosphere - Behavioral IPS
5. Exploit Detection - Vulnerability/exploit detection
6. ML Model Manager - Insider threat, DDoS, etc.
7. UBA - User behavior analytics
"""

import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

# Create logs directory
Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/threat_orchestrator.log')
    ]
)

logger = logging.getLogger("threat_orchestrator")

# Import detection engines
try:
    from flowprint_engine import get_flowprint_engine, FingerprintMatch
    FLOWPRINT_AVAILABLE = True
except ImportError as e:
    FLOWPRINT_AVAILABLE = False
    logger.warning(f"FlowPrint not available: {e}")

try:
    from kitsune_engine import get_kitsune_engine, KitsuneAnomaly
    KITSUNE_AVAILABLE = True
except ImportError as e:
    KITSUNE_AVAILABLE = False
    logger.warning(f"Kitsune not available: {e}")

try:
    from etbert_engine import get_etbert_engine, EncryptedTrafficClassification
    ETBERT_AVAILABLE = True
except ImportError as e:
    ETBERT_AVAILABLE = False
    logger.warning(f"ET-BERT not available: {e}")

try:
    from stratosphere_engine import get_stratosphere_engine, StratosphereAlert
    STRATOSPHERE_AVAILABLE = True
except ImportError as e:
    STRATOSPHERE_AVAILABLE = False
    logger.warning(f"Stratosphere not available: {e}")

try:
    from exploit_detection import get_exploit_detector, ExploitDetection
    EXPLOIT_DETECTION_AVAILABLE = True
except ImportError as e:
    EXPLOIT_DETECTION_AVAILABLE = False
    logger.warning(f"Exploit Detection not available: {e}")

try:
    from ml_model_manager import get_model_manager, MLModelManager
    ML_MANAGER_AVAILABLE = True
except ImportError as e:
    ML_MANAGER_AVAILABLE = False
    logger.warning(f"ML Model Manager not available: {e}")


@dataclass
class ThreatAssessment:
    """Unified threat assessment from all engines"""
    timestamp: str
    src_ip: str
    dst_ip: str
    threat_level: int  # 0-10 scale
    threat_types: List[str]
    confidence: float
    detections: Dict[str, Any]  # Results from each engine
    recommended_action: str
    priority: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'


class AdvancedThreatOrchestrator:
    """
    Orchestrates multiple threat detection engines
    Combines results for comprehensive threat assessment
    """
    
    def __init__(self, 
                 enable_flowprint: bool = True,
                 enable_kitsune: bool = True,
                 enable_etbert: bool = True,
                 enable_stratosphere: bool = True,
                 enable_exploit_detection: bool = True,
                 enable_ml_models: bool = True):
        """
        Initialize Advanced Threat Orchestrator
        
        Args:
            enable_*: Enable/disable specific detection engines
        """
        self.config = {
            'flowprint': enable_flowprint and FLOWPRINT_AVAILABLE,
            'kitsune': enable_kitsune and KITSUNE_AVAILABLE,
            'etbert': enable_etbert and ETBERT_AVAILABLE,
            'stratosphere': enable_stratosphere and STRATOSPHERE_AVAILABLE,
            'exploit': enable_exploit_detection and EXPLOIT_DETECTION_AVAILABLE,
            'ml_models': enable_ml_models and ML_MANAGER_AVAILABLE
        }
        
        # Initialize engines
        self.engines = {}
        
        if self.config['flowprint']:
            self.engines['flowprint'] = get_flowprint_engine()
            logger.info("FlowPrint engine enabled")
        
        if self.config['kitsune']:
            self.engines['kitsune'] = get_kitsune_engine()
            logger.info("Kitsune engine enabled")
        
        if self.config['etbert']:
            self.engines['etbert'] = get_etbert_engine()
            logger.info("ET-BERT engine enabled")
        
        if self.config['stratosphere']:
            self.engines['stratosphere'] = get_stratosphere_engine()
            logger.info("Stratosphere engine enabled")
        
        if self.config['exploit']:
            self.engines['exploit'] = get_exploit_detector()
            logger.info("Exploit Detection engine enabled")
        
        if self.config['ml_models']:
            try:
                self.engines['ml_models'] = get_model_manager()
                logger.info("ML Model Manager enabled")
            except Exception as e:
                logger.warning(f"ML Model Manager initialization failed: {e}")
                self.config['ml_models'] = False
        
        # Statistics
        self.packet_count = 0
        self.threat_count = 0
        self.threat_types_detected = defaultdict(int)
        
        # Threading
        self.lock = threading.Lock()
        
        # Logging
        self.assessment_log = Path("logs/threat_assessments.json")
        
        logger.info(f"Advanced Threat Orchestrator initialized with {len(self.engines)} engines")
    
    def analyze_packet(self, packet_data: Dict[str, Any]) -> Optional[ThreatAssessment]:
        """
        Analyze packet through all enabled engines
        
        Args:
            packet_data: Complete packet information including:
                - src_ip, dst_ip, src_port, dst_port, protocol
                - timestamp, packet_length
                - payload (optional): packet payload
                - is_encrypted (optional): encryption flag
                - http_uri, http_headers (optional): HTTP data
                - state (optional): connection state
        
        Returns:
            ThreatAssessment if threat detected, None otherwise
        """
        with self.lock:
            self.packet_count += 1
            
            detections = {}
            threat_types = []
            threat_scores = []
            
            try:
                # 1. FlowPrint - Device fingerprinting
                if self.config['flowprint']:
                    fp_result = self.engines['flowprint'].process_packet(packet_data)
                    if fp_result:
                        detections['flowprint'] = {
                            'device_type': fp_result.device_type,
                            'app_type': fp_result.app_type,
                            'is_anomaly': fp_result.is_anomaly,
                            'confidence': fp_result.confidence
                        }
                        if fp_result.is_anomaly:
                            threat_types.append('UNKNOWN_DEVICE')
                            threat_scores.append(fp_result.confidence * 3)  # Anomaly weight
                
                # 2. Kitsune - Online anomaly detection
                if self.config['kitsune']:
                    kit_result = self.engines['kitsune'].process_packet(packet_data)
                    if kit_result and kit_result.is_anomaly:
                        detections['kitsune'] = {
                            'anomaly_score': kit_result.anomaly_score,
                            'threshold': kit_result.threshold
                        }
                        threat_types.append('TRAFFIC_ANOMALY')
                        threat_scores.append(min(10, kit_result.anomaly_score))
                
                # 3. ET-BERT - Encrypted traffic classification
                if self.config['etbert'] and packet_data.get('is_encrypted'):
                    etbert_result = self.engines['etbert'].classify_encrypted_traffic(packet_data)
                    if etbert_result and etbert_result.is_suspicious:
                        detections['etbert'] = {
                            'traffic_class': etbert_result.traffic_class,
                            'confidence': etbert_result.confidence
                        }
                        threat_types.append(etbert_result.traffic_class)
                        threat_scores.append(etbert_result.confidence * 8)
                
                # 4. Stratosphere - Behavioral analysis
                if self.config['stratosphere']:
                    # Convert packet to connection format
                    conn_data = {
                        'src_ip': packet_data.get('src_ip'),
                        'dst_ip': packet_data.get('dst_ip'),
                        'dst_port': packet_data.get('dst_port'),
                        'protocol': packet_data.get('protocol'),
                        'timestamp': packet_data.get('timestamp', time.time()),
                        'state': packet_data.get('state', 'Established'),
                        'bytes_sent': packet_data.get('packet_length', 0),
                        'bytes_received': 0
                    }
                    strat_result = self.engines['stratosphere'].process_connection(conn_data)
                    if strat_result:
                        detections['stratosphere'] = {
                            'alert_type': strat_result.alert_type,
                            'severity': strat_result.severity,
                            'confidence': strat_result.confidence,
                            'behavior_pattern': strat_result.behavior_pattern
                        }
                        threat_types.append(strat_result.alert_type)
                        # Severity to score
                        severity_scores = {'LOW': 3, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}
                        threat_scores.append(severity_scores.get(strat_result.severity, 5))
                
                # 5. Exploit Detection
                if self.config['exploit']:
                    exploit_result = self.engines['exploit'].analyze_packet(packet_data)
                    if exploit_result:
                        detections['exploit'] = {
                            'exploit_type': exploit_result.exploit_type,
                            'severity': exploit_result.severity,
                            'confidence': exploit_result.confidence,
                            'cve_references': exploit_result.cve_references
                        }
                        threat_types.append(exploit_result.exploit_type)
                        # Severity to score
                        severity_scores = {'LOW': 4, 'MEDIUM': 6, 'HIGH': 9, 'CRITICAL': 10}
                        threat_scores.append(severity_scores.get(exploit_result.severity, 6))
                
                # 6. ML Models (if available)
                if self.config['ml_models'] and hasattr(self.engines.get('ml_models'), 'predict'):
                    # Extract features for ML
                    ml_features = self._extract_ml_features(packet_data)
                    if ml_features:
                        try:
                            ml_result = self.engines['ml_models'].predict(ml_features)
                            if ml_result and ml_result.is_threat:
                                detections['ml_models'] = {
                                    'threat_type': ml_result.threat_type,
                                    'confidence': ml_result.confidence
                                }
                                threat_types.append(ml_result.threat_type)
                                threat_scores.append(ml_result.confidence * 8)
                        except Exception as e:
                            logger.debug(f"ML prediction error: {e}")
                
                # Combine results
                if detections:
                    assessment = self._create_assessment(
                        packet_data,
                        detections,
                        threat_types,
                        threat_scores
                    )
                    
                    self.threat_count += 1
                    for tt in threat_types:
                        self.threat_types_detected[tt] += 1
                    
                    logger.warning(f"Threat detected: {assessment.src_ip} -> {assessment.dst_ip} "
                                 f"[{', '.join(assessment.threat_types)}] "
                                 f"(level={assessment.threat_level}/10, priority={assessment.priority})")
                    
                    self._log_assessment(assessment)
                    return assessment
                
                return None
                
            except Exception as e:
                logger.error(f"Error in threat orchestration: {e}")
                return None
    
    def _extract_ml_features(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract features for ML models"""
        try:
            return {
                'packet_length': packet_data.get('packet_length', 0),
                'protocol': packet_data.get('protocol', 'TCP'),
                'dst_port': packet_data.get('dst_port', 0),
                'src_port': packet_data.get('src_port', 0),
                'timestamp': packet_data.get('timestamp', time.time())
            }
        except Exception:
            return None
    
    def _create_assessment(self,
                          packet_data: Dict[str, Any],
                          detections: Dict[str, Any],
                          threat_types: List[str],
                          threat_scores: List[float]) -> ThreatAssessment:
        """Create unified threat assessment"""
        # Calculate overall threat level (0-10)
        if threat_scores:
            threat_level = int(sum(threat_scores) / len(threat_scores))
        else:
            threat_level = 5
        
        # Cap at 10
        threat_level = min(10, threat_level)
        
        # Calculate confidence (average of detection confidences)
        confidences = []
        for det in detections.values():
            if isinstance(det, dict) and 'confidence' in det:
                confidences.append(det['confidence'])
        
        overall_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        
        # Determine priority
        if threat_level >= 9:
            priority = "CRITICAL"
            action = "BLOCK_IMMEDIATELY"
        elif threat_level >= 7:
            priority = "HIGH"
            action = "BLOCK_IP"
        elif threat_level >= 5:
            priority = "MEDIUM"
            action = "RATE_LIMIT"
        else:
            priority = "LOW"
            action = "LOG_AND_MONITOR"
        
        return ThreatAssessment(
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip=packet_data.get('src_ip', '0.0.0.0'),
            dst_ip=packet_data.get('dst_ip', '0.0.0.0'),
            threat_level=threat_level,
            threat_types=list(set(threat_types)),  # Unique threat types
            confidence=overall_confidence,
            detections=detections,
            recommended_action=action,
            priority=priority
        )
    
    def _log_assessment(self, assessment: ThreatAssessment):
        """Log threat assessment to file"""
        try:
            with open(self.assessment_log, 'a') as f:
                f.write(json.dumps(asdict(assessment)) + '\n')
        except Exception as e:
            logger.error(f"Error logging assessment: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all engines"""
        with self.lock:
            stats = {
                'orchestrator': {
                    'packet_count': self.packet_count,
                    'threat_count': self.threat_count,
                    'threat_rate': self.threat_count / max(self.packet_count, 1),
                    'threat_types_detected': dict(self.threat_types_detected),
                    'enabled_engines': [k for k, v in self.config.items() if v]
                }
            }
            
            # Get stats from each engine
            for name, engine in self.engines.items():
                if hasattr(engine, 'get_statistics'):
                    try:
                        stats[name] = engine.get_statistics()
                    except Exception as e:
                        logger.error(f"Error getting stats from {name}: {e}")
            
            return stats
    
    def get_enabled_engines(self) -> List[str]:
        """Get list of enabled engines"""
        return [k for k, v in self.config.items() if v]


# Singleton instance
_orchestrator_instance: Optional[AdvancedThreatOrchestrator] = None
_orchestrator_lock = threading.Lock()


def get_threat_orchestrator() -> AdvancedThreatOrchestrator:
    """Get or create threat orchestrator singleton"""
    global _orchestrator_instance
    
    with _orchestrator_lock:
        if _orchestrator_instance is None:
            _orchestrator_instance = AdvancedThreatOrchestrator()
        return _orchestrator_instance


if __name__ == "__main__":
    # Test the orchestrator
    orchestrator = get_threat_orchestrator()
    
    print("=== Advanced Threat Detection Orchestrator ===")
    print(f"Enabled engines: {', '.join(orchestrator.get_enabled_engines())}\n")
    
    # Test with benign traffic
    print("Testing with normal traffic...")
    benign_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP',
        'timestamp': time.time(),
        'packet_length': 1200,
        'is_encrypted': True,
        'payload': b'\x16\x03\x01' + bytes([i % 256 for i in range(100)])
    }
    
    result = orchestrator.analyze_packet(benign_packet)
    if result:
        print(f"  Threat Level: {result.threat_level}/10")
        print(f"  Priority: {result.priority}")
        print(f"  Threat Types: {', '.join(result.threat_types)}\n")
    else:
        print("  No threats detected\n")
    
    # Test with malicious traffic (SQL injection)
    print("Testing with SQL injection attack...")
    malicious_packet = {
        'src_ip': '203.0.113.50',
        'dst_ip': '192.168.1.10',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'timestamp': time.time(),
        'packet_length': 200,
        'http_uri': "/login?user=admin' OR '1'='1",
        'payload': b"username=admin' UNION SELECT * FROM users--",
        'state': 'Established'
    }
    
    result = orchestrator.analyze_packet(malicious_packet)
    if result:
        print(f"  Threat Level: {result.threat_level}/10")
        print(f"  Priority: {result.priority}")
        print(f"  Threat Types: {', '.join(result.threat_types)}")
        print(f"  Recommended Action: {result.recommended_action}\n")
    
    # Print comprehensive statistics
    stats = orchestrator.get_statistics()
    print("=== Comprehensive Statistics ===")
    print(json.dumps(stats, indent=2, default=str))
