#!/usr/bin/env python3
"""
Kitsune Engine - Online Anomaly Detection for Network Traffic
Based on: https://github.com/ymirsky/Kitsune-py

Uses ensemble of autoencoders for incremental learning and real-time anomaly detection.

Features:
- Online/incremental learning (no training phase required)
- Ensemble of autoencoders (KitNET)
- Packet-level feature extraction
- Real-time anomaly scoring
- Low memory footprint
- Adaptive to network changes
"""

import json
import logging
import threading
import time
import math
from collections import deque, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

# Create logs directory
Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/kitsune_engine.log')
    ]
)

logger = logging.getLogger("kitsune_engine")


@dataclass
class KitsuneAnomaly:
    """Anomaly detected by Kitsune"""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    feature_vector: List[float]
    reconstruction_error: float


class AfterImage:
    """
    Incremental statistics tracker for network flows
    Implements the AfterImage algorithm for online feature extraction
    """
    
    def __init__(self, max_host_limit: int = 255, max_session_limit: int = 100000):
        self.max_host_limit = max_host_limit
        self.max_session_limit = max_session_limit
        
        # Flow statistics
        self.host_stats = defaultdict(lambda: {
            'count': 0,
            'total_bytes': 0,
            'total_packets': 0,
            'protocols': set(),
            'ports': set(),
            'last_timestamp': 0.0
        })
        
        # Session-based stats
        self.session_stats = {}
        
    def update_stats(self, flow_key: str, packet_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Update statistics and extract features
        
        Args:
            flow_key: Unique flow identifier
            packet_data: Packet information
            
        Returns:
            Feature vector as dict
        """
        src_ip = packet_data.get('src_ip', '0.0.0.0')
        dst_ip = packet_data.get('dst_ip', '0.0.0.0')
        protocol = packet_data.get('protocol', 'TCP')
        dst_port = packet_data.get('dst_port', 0)
        packet_length = packet_data.get('packet_length', 0)
        timestamp = packet_data.get('timestamp', time.time())
        
        # Update host stats
        host = self.host_stats[src_ip]
        host['count'] += 1
        host['total_bytes'] += packet_length
        host['total_packets'] += 1
        host['protocols'].add(protocol)
        host['ports'].add(dst_port)
        
        # Calculate time-based features
        time_delta = timestamp - host['last_timestamp'] if host['last_timestamp'] > 0 else 0
        host['last_timestamp'] = timestamp
        
        # Extract features (simplified version - full Kitsune has 115 features)
        features = {
            # Flow-based features
            'packet_count': host['count'],
            'byte_count': host['total_bytes'],
            'avg_packet_size': host['total_bytes'] / max(host['count'], 1),
            
            # Time-based features
            'time_delta': time_delta,
            'packet_rate': 1.0 / max(time_delta, 0.001),
            
            # Diversity features
            'protocol_diversity': len(host['protocols']),
            'port_diversity': len(host['ports']),
            
            # Current packet features
            'current_packet_size': packet_length,
            'current_dst_port': dst_port,
        }
        
        # Memory management
        if len(self.host_stats) > self.max_host_limit:
            self._cleanup_old_hosts()
        
        return features
    
    def _cleanup_old_hosts(self):
        """Remove least recently used hosts"""
        sorted_hosts = sorted(
            self.host_stats.items(),
            key=lambda x: x[1]['last_timestamp']
        )
        
        # Remove oldest 20%
        remove_count = len(sorted_hosts) // 5
        for host, _ in sorted_hosts[:remove_count]:
            del self.host_stats[host]


class Autoencoder:
    """
    Simple autoencoder for anomaly detection
    Uses incremental learning (no batch training required)
    """
    
    def __init__(self, input_size: int, hidden_size: int = None, learning_rate: float = 0.1):
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required for Autoencoder")
        
        self.input_size = input_size
        self.hidden_size = hidden_size or max(input_size // 2, 1)
        self.learning_rate = learning_rate
        
        # Initialize weights with small random values
        self.W1 = np.random.randn(input_size, self.hidden_size) * 0.1
        self.b1 = np.zeros(self.hidden_size)
        self.W2 = np.random.randn(self.hidden_size, input_size) * 0.1
        self.b2 = np.zeros(input_size)
        
        # Training statistics
        self.sample_count = 0
        self.mean_error = 0.0
        self.std_error = 1.0
    
    def forward(self, x: np.ndarray) -> np.ndarray:
        """Forward pass through autoencoder"""
        # Encoder
        hidden = np.tanh(np.dot(x, self.W1) + self.b1)
        # Decoder
        output = np.tanh(np.dot(hidden, self.W2) + self.b2)
        return output, hidden
    
    def train_step(self, x: np.ndarray) -> float:
        """
        Single training step with incremental weight update
        
        Returns:
            Reconstruction error
        """
        # Forward pass
        output, hidden = self.forward(x)
        
        # Calculate error
        error = x - output
        reconstruction_error = np.mean(np.square(error))
        
        # Backward pass (simplified gradient descent)
        # Output layer gradients
        d_output = -2 * error * (1 - np.square(output))  # tanh derivative
        dW2 = np.outer(hidden, d_output)
        db2 = d_output
        
        # Hidden layer gradients
        d_hidden = np.dot(d_output, self.W2.T) * (1 - np.square(hidden))
        dW1 = np.outer(x, d_hidden)
        db1 = d_hidden
        
        # Update weights incrementally
        self.W1 -= self.learning_rate * dW1
        self.b1 -= self.learning_rate * db1
        self.W2 -= self.learning_rate * dW2
        self.b2 -= self.learning_rate * db2
        
        # Update statistics
        self.sample_count += 1
        alpha = min(0.01, 1.0 / self.sample_count)  # Decay rate
        self.mean_error = (1 - alpha) * self.mean_error + alpha * reconstruction_error
        self.std_error = (1 - alpha) * self.std_error + alpha * np.sqrt(reconstruction_error)
        
        return reconstruction_error
    
    def predict(self, x: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Predict anomaly score
        
        Returns:
            (anomaly_score, reconstructed_output)
        """
        output, _ = self.forward(x)
        reconstruction_error = np.mean(np.square(x - output))
        
        # Normalized anomaly score (z-score)
        if self.std_error > 0:
            anomaly_score = (reconstruction_error - self.mean_error) / self.std_error
        else:
            anomaly_score = 0.0
        
        return max(0, anomaly_score), output


class KitNET:
    """
    Ensemble of autoencoders (KitNET architecture)
    Combines multiple autoencoders for robust anomaly detection
    """
    
    def __init__(self, feature_size: int, ensemble_size: int = 10, learning_rate: float = 0.1):
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required for KitNET")
        
        self.feature_size = feature_size
        self.ensemble_size = ensemble_size
        
        # Create ensemble of autoencoders
        self.autoencoders = [
            Autoencoder(
                input_size=feature_size,
                hidden_size=max(feature_size // 3, 2),
                learning_rate=learning_rate
            )
            for _ in range(ensemble_size)
        ]
        
        # Meta-autoencoder to combine ensemble outputs
        self.meta_ae = Autoencoder(
            input_size=ensemble_size,
            hidden_size=max(ensemble_size // 2, 1),
            learning_rate=learning_rate
        )
        
        self.is_trained = False
        self.training_samples = 0
        self.min_training_samples = 1000  # Minimum samples for stable detection
    
    def process(self, features: np.ndarray, train: bool = True) -> float:
        """
        Process features through ensemble
        
        Args:
            features: Feature vector
            train: Whether to update weights
            
        Returns:
            Anomaly score
        """
        # Get reconstruction errors from each autoencoder
        ensemble_scores = []
        for ae in self.autoencoders:
            if train:
                error = ae.train_step(features)
                ensemble_scores.append(error)
            else:
                score, _ = ae.predict(features)
                ensemble_scores.append(score)
        
        # Combine using meta-autoencoder
        ensemble_vector = np.array(ensemble_scores)
        
        if train:
            meta_error = self.meta_ae.train_step(ensemble_vector)
            self.training_samples += 1
            
            if self.training_samples >= self.min_training_samples:
                self.is_trained = True
            
            # Return 0 during training phase
            return 0.0
        else:
            anomaly_score, _ = self.meta_ae.predict(ensemble_vector)
            return anomaly_score


class KitsuneEngine:
    """
    Online anomaly detection engine using KitNET ensemble autoencoders
    
    Inspired by Kitsune-py:
    - Incremental learning (no pre-training needed)
    - Ensemble of autoencoders
    - Real-time anomaly detection
    - Adaptive to network changes
    """
    
    def __init__(self, 
                 ensemble_size: int = 10,
                 learning_rate: float = 0.1,
                 anomaly_threshold: float = 3.0,
                 grace_period: int = 1000):
        """
        Initialize Kitsune Engine
        
        Args:
            ensemble_size: Number of autoencoders in ensemble
            learning_rate: Learning rate for incremental updates
            anomaly_threshold: Threshold for anomaly detection (z-score)
            grace_period: Number of initial samples for training
        """
        if not NUMPY_AVAILABLE:
            logger.error("NumPy not available. Kitsune engine will not work.")
            self.enabled = False
            return
        
        self.ensemble_size = ensemble_size
        self.learning_rate = learning_rate
        self.anomaly_threshold = anomaly_threshold
        self.grace_period = grace_period
        self.enabled = True
        
        # Feature extraction
        self.afterimage = AfterImage()
        
        # KitNET model (initialized on first packet)
        self.kitnet: Optional[KitNET] = None
        self.feature_size = 9  # Number of features we extract
        
        # State
        self.packet_count = 0
        self.anomaly_count = 0
        self.training_mode = True
        
        # Threading
        self.lock = threading.Lock()
        
        # Logging
        self.anomaly_log = Path("logs/kitsune_anomalies.json")
        
        logger.info(f"Kitsune Engine initialized (ensemble={ensemble_size}, threshold={anomaly_threshold})")
    
    def process_packet(self, packet_data: Dict[str, Any]) -> Optional[KitsuneAnomaly]:
        """
        Process a packet and detect anomalies
        
        Args:
            packet_data: Packet information dict
            
        Returns:
            KitsuneAnomaly if anomaly detected, None otherwise
        """
        if not self.enabled:
            return None
        
        with self.lock:
            try:
                # Generate flow key
                flow_key = f"{packet_data.get('src_ip')}:{packet_data.get('src_port')}->" \
                          f"{packet_data.get('dst_ip')}:{packet_data.get('dst_port')}"
                
                # Extract features using AfterImage
                features_dict = self.afterimage.update_stats(flow_key, packet_data)
                
                # Convert to numpy array
                feature_vector = np.array(list(features_dict.values()), dtype=np.float32)
                
                # Normalize features
                feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=1e6, neginf=-1e6)
                
                # Initialize KitNET on first packet
                if self.kitnet is None:
                    self.kitnet = KitNET(
                        feature_size=len(feature_vector),
                        ensemble_size=self.ensemble_size,
                        learning_rate=self.learning_rate
                    )
                
                self.packet_count += 1
                
                # Training phase (grace period)
                if self.packet_count <= self.grace_period:
                    self.kitnet.process(feature_vector, train=True)
                    if self.packet_count % 100 == 0:
                        logger.info(f"Training: {self.packet_count}/{self.grace_period} packets processed")
                    return None
                
                # Detection phase
                if self.packet_count == self.grace_period + 1:
                    logger.info(f"Training complete. Switching to detection mode.")
                    self.training_mode = False
                
                # Get anomaly score
                anomaly_score = self.kitnet.process(feature_vector, train=False)
                
                # Check if anomaly
                is_anomaly = anomaly_score > self.anomaly_threshold
                
                if is_anomaly:
                    self.anomaly_count += 1
                    
                    anomaly = KitsuneAnomaly(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        src_ip=packet_data.get('src_ip', '0.0.0.0'),
                        dst_ip=packet_data.get('dst_ip', '0.0.0.0'),
                        src_port=packet_data.get('src_port', 0),
                        dst_port=packet_data.get('dst_port', 0),
                        protocol=packet_data.get('protocol', 'TCP'),
                        anomaly_score=float(anomaly_score),
                        threshold=self.anomaly_threshold,
                        is_anomaly=True,
                        feature_vector=feature_vector.tolist(),
                        reconstruction_error=float(anomaly_score)
                    )
                    
                    logger.warning(f"Anomaly detected: {anomaly.src_ip}:{anomaly.src_port} -> "
                                 f"{anomaly.dst_ip}:{anomaly.dst_port} (score={anomaly_score:.2f})")
                    
                    self._log_anomaly(anomaly)
                    return anomaly
                
                return None
                
            except Exception as e:
                logger.error(f"Error processing packet in Kitsune: {e}")
                return None
    
    def _log_anomaly(self, anomaly: KitsuneAnomaly):
        """Log anomaly to file"""
        try:
            with open(self.anomaly_log, 'a') as f:
                f.write(json.dumps(asdict(anomaly)) + '\n')
        except Exception as e:
            logger.error(f"Error logging anomaly: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self.lock:
            return {
                'enabled': self.enabled,
                'packet_count': self.packet_count,
                'anomaly_count': self.anomaly_count,
                'training_mode': self.training_mode,
                'anomaly_rate': self.anomaly_count / max(self.packet_count, 1),
                'grace_period': self.grace_period,
                'anomaly_threshold': self.anomaly_threshold
            }
    
    def reset(self):
        """Reset the engine (clear learning)"""
        with self.lock:
            self.kitnet = None
            self.afterimage = AfterImage()
            self.packet_count = 0
            self.anomaly_count = 0
            self.training_mode = True
            logger.info("Kitsune engine reset")


# Singleton instance
_kitsune_engine_instance: Optional[KitsuneEngine] = None
_kitsune_lock = threading.Lock()


def get_kitsune_engine() -> KitsuneEngine:
    """Get or create Kitsune engine singleton"""
    global _kitsune_engine_instance
    
    with _kitsune_lock:
        if _kitsune_engine_instance is None:
            _kitsune_engine_instance = KitsuneEngine()
        return _kitsune_engine_instance


if __name__ == "__main__":
    # Test the engine
    engine = get_kitsune_engine()
    
    if not engine.enabled:
        print("Kitsune engine disabled (NumPy not available)")
        exit(1)
    
    # Simulate normal traffic
    print("Simulating normal traffic (training phase)...")
    for i in range(1100):
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 50000 + i,
            'dst_port': 443,
            'protocol': 'TCP',
            'timestamp': time.time(),
            'packet_length': 1200 + (i % 100)
        }
        engine.process_packet(packet)
        time.sleep(0.001)
    
    # Simulate anomalous traffic
    print("\nSimulating anomalous traffic...")
    for i in range(10):
        anomalous_packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': f'10.0.0.{i}',
            'src_port': 60000 + i,
            'dst_port': 22,  # SSH scanning
            'protocol': 'TCP',
            'timestamp': time.time(),
            'packet_length': 64  # Tiny packets (scanning)
        }
        result = engine.process_packet(anomalous_packet)
        if result:
            print(f"  Anomaly: {result.src_ip} -> {result.dst_ip} (score={result.anomaly_score:.2f})")
    
    # Print statistics
    stats = engine.get_statistics()
    print("\n=== Kitsune Engine Statistics ===")
    print(json.dumps(stats, indent=2))
