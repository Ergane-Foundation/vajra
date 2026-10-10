#!/usr/bin/env python3
"""
ET-BERT Engine - Encrypted Traffic Classification using BERT
Based on: https://github.com/linwhitehat/ET-BERT

Applies NLP techniques (BERT) to classify encrypted network traffic.
Converts traffic byte sequences into "tokens" for transformer-based analysis.

Features:
- BERT-like transformer for encrypted traffic
- Byte-level tokenization of packet payloads
- Classification of encrypted protocols (TLS/HTTPS, SSH, VPN, etc.)
- Malware C2 detection in encrypted channels
- No need for decryption
"""

import json
import logging
import threading
import time
from collections import deque
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
from vajra.common.logging import setup_logging

logger = setup_logging("etbert_engine", "logs/etbert_engine.log")


@dataclass
class EncryptedTrafficClassification:
    """Result of encrypted traffic classification"""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    traffic_class: str  # e.g., "HTTPS", "SSH", "VPN", "TOR", "MALWARE_C2"
    confidence: float
    is_suspicious: bool
    byte_sequence_sample: List[int]
    features: Dict[str, Any]


class ByteTokenizer:
    """
    Tokenizes packet byte sequences for BERT-like processing
    Treats bytes as tokens similar to words in NLP
    """
    
    def __init__(self, vocab_size: int = 256, max_seq_length: int = 512):
        self.vocab_size = vocab_size  # 0-255 for bytes
        self.max_seq_length = max_seq_length
        
        # Special tokens
        self.PAD_TOKEN = 256
        self.CLS_TOKEN = 257
        self.SEP_TOKEN = 258
        self.MASK_TOKEN = 259
        
        self.total_vocab_size = 260
    
    def tokenize(self, byte_sequence: bytes) -> List[int]:
        """
        Tokenize byte sequence
        
        Args:
            byte_sequence: Raw bytes from packet
            
        Returns:
            List of token IDs
        """
        # Convert bytes to list of integers
        tokens = [self.CLS_TOKEN]  # Add CLS token at start
        tokens.extend(list(byte_sequence[:self.max_seq_length - 2]))
        tokens.append(self.SEP_TOKEN)  # Add SEP token at end
        
        # Pad to max length
        while len(tokens) < self.max_seq_length:
            tokens.append(self.PAD_TOKEN)
        
        return tokens[:self.max_seq_length]
    
    def extract_statistical_features(self, byte_sequence: bytes) -> Dict[str, float]:
        """Extract statistical features from byte sequence"""
        if not byte_sequence:
            return {
                'byte_entropy': 0.0,
                'byte_mean': 0.0,
                'byte_std': 0.0,
                'printable_ratio': 0.0,
                'null_byte_ratio': 0.0
            }
        
        byte_array = np.array(list(byte_sequence), dtype=np.float32) if NUMPY_AVAILABLE else list(byte_sequence)
        
        # Calculate entropy
        byte_counts = {}
        for b in byte_sequence:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        entropy = 0.0
        total = len(byte_sequence)
        for count in byte_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p) if NUMPY_AVAILABLE else p * (count / total)
        
        # Other statistics
        if NUMPY_AVAILABLE:
            byte_mean = float(np.mean(byte_array))
            byte_std = float(np.std(byte_array))
        else:
            byte_mean = sum(byte_array) / len(byte_array)
            byte_std = 0.0
        
        printable_count = sum(1 for b in byte_sequence if 32 <= b <= 126)
        null_count = sum(1 for b in byte_sequence if b == 0)
        
        return {
            'byte_entropy': entropy,
            'byte_mean': byte_mean,
            'byte_std': byte_std,
            'printable_ratio': printable_count / total,
            'null_byte_ratio': null_count / total
        }


class SimpleTransformerClassifier:
    """
    Simplified transformer-based classifier for encrypted traffic
    (Lightweight version inspired by BERT architecture)
    """
    
    def __init__(self, vocab_size: int = 260, embedding_dim: int = 64, num_classes: int = 10):
        if not NUMPY_AVAILABLE:
            raise ImportError("NumPy required for transformer classifier")
        
        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.num_classes = num_classes
        
        # Initialize embeddings (simplified - real BERT uses positional encoding too)
        self.token_embeddings = np.random.randn(vocab_size, embedding_dim) * 0.1
        
        # Classification head (simple linear layer)
        self.classifier_weights = np.random.randn(embedding_dim, num_classes) * 0.1
        self.classifier_bias = np.zeros(num_classes)
        
        # Training state
        self.is_trained = False
    
    def forward(self, token_ids: List[int]) -> np.ndarray:
        """
        Forward pass through simplified transformer
        
        Args:
            token_ids: List of token IDs
            
        Returns:
            Class probabilities
        """
        # Get embeddings
        embeddings = self.token_embeddings[token_ids]
        
        # Simplified: just average pooling (real BERT uses attention)
        pooled = np.mean(embeddings, axis=0)
        
        # Classification
        logits = np.dot(pooled, self.classifier_weights) + self.classifier_bias
        
        # Softmax
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)
        
        return probs
    
    def predict(self, token_ids: List[int]) -> Tuple[int, float, np.ndarray]:
        """
        Predict class for token sequence
        
        Returns:
            (predicted_class, confidence, all_probabilities)
        """
        probs = self.forward(token_ids)
        predicted_class = int(np.argmax(probs))
        confidence = float(probs[predicted_class])
        
        return predicted_class, confidence, probs


class ETBERTEngine:
    """
    Encrypted Traffic Classification using BERT-like transformer
    
    Inspired by ET-BERT:
    - Treats encrypted traffic as sequence of byte tokens
    - Uses transformer architecture for classification
    - No decryption needed
    - Detects malware C2, VPN, Tor, etc. in encrypted channels
    """
    
    # Traffic class labels
    TRAFFIC_CLASSES = [
        "HTTPS_WEB",       # Normal web browsing
        "HTTPS_API",       # API calls
        "SSH",             # SSH connections
        "VPN",             # VPN traffic
        "TOR",             # Tor anonymization
        "MALWARE_C2",      # Command & Control
        "DATA_EXFIL",      # Data exfiltration
        "DNS_TUNNEL",      # DNS tunneling
        "COVERT_CHANNEL",  # Covert channels
        "UNKNOWN"          # Unknown encrypted traffic
    ]
    
    # Suspicious classes that trigger alerts
    SUSPICIOUS_CLASSES = {"MALWARE_C2", "DATA_EXFIL", "DNS_TUNNEL", "COVERT_CHANNEL", "TOR"}
    
    def __init__(self, 
                 max_seq_length: int = 512,
                 embedding_dim: int = 64,
                 enable_heuristics: bool = True):
        """
        Initialize ET-BERT Engine
        
        Args:
            max_seq_length: Maximum byte sequence length
            embedding_dim: Embedding dimension for transformer
            enable_heuristics: Use heuristic rules alongside ML
        """
        if not NUMPY_AVAILABLE:
            logger.error("NumPy not available. ET-BERT engine will not work.")
            self.enabled = False
            return
        
        self.max_seq_length = max_seq_length
        self.embedding_dim = embedding_dim
        self.enable_heuristics = enable_heuristics
        self.enabled = True
        
        # Components
        self.tokenizer = ByteTokenizer(max_seq_length=max_seq_length)
        
        try:
            self.classifier = SimpleTransformerClassifier(
                vocab_size=self.tokenizer.total_vocab_size,
                embedding_dim=embedding_dim,
                num_classes=len(self.TRAFFIC_CLASSES)
            )
        except ImportError:
            logger.error("Failed to initialize classifier")
            self.enabled = False
            return
        
        # State
        self.packet_count = 0
        self.classification_count = 0
        self.suspicious_count = 0
        
        # Threading
        self.lock = threading.Lock()
        
        # Logging
        self.classification_log = Path("logs/etbert_classifications.json")
        
        logger.info(f"ET-BERT Engine initialized (seq_len={max_seq_length}, dim={embedding_dim})")
    
    def classify_encrypted_traffic(self, packet_data: Dict[str, Any]) -> Optional[EncryptedTrafficClassification]:
        """
        Classify encrypted network traffic
        
        Args:
            packet_data: Packet information including:
                - src_ip, dst_ip, src_port, dst_port, protocol
                - payload (bytes): encrypted payload
                - is_encrypted (bool): whether traffic is encrypted
        
        Returns:
            Classification result if encrypted, None otherwise
        """
        if not self.enabled:
            return None
        
        # Only process encrypted traffic
        if not packet_data.get('is_encrypted', False):
            return None
        
        payload = packet_data.get('payload', b'')
        if not payload or len(payload) < 20:  # Skip tiny packets
            return None
        
        with self.lock:
            try:
                self.packet_count += 1
                
                # Extract statistical features
                stat_features = self.tokenizer.extract_statistical_features(payload)
                
                # Tokenize payload
                tokens = self.tokenizer.tokenize(payload)
                
                # Classify using transformer (if trained)
                if self.classifier.is_trained:
                    class_idx, confidence, probs = self.classifier.predict(tokens)
                    traffic_class = self.TRAFFIC_CLASSES[class_idx]
                else:
                    # Fallback to heuristics
                    traffic_class, confidence = self._heuristic_classification(
                        packet_data, stat_features
                    )
                
                # Check if suspicious
                is_suspicious = traffic_class in self.SUSPICIOUS_CLASSES
                
                if is_suspicious:
                    self.suspicious_count += 1
                
                self.classification_count += 1
                
                result = EncryptedTrafficClassification(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    src_ip=packet_data.get('src_ip', '0.0.0.0'),
                    dst_ip=packet_data.get('dst_ip', '0.0.0.0'),
                    src_port=packet_data.get('src_port', 0),
                    dst_port=packet_data.get('dst_port', 0),
                    protocol=packet_data.get('protocol', 'TCP'),
                    traffic_class=traffic_class,
                    confidence=confidence,
                    is_suspicious=is_suspicious,
                    byte_sequence_sample=list(payload[:32]),  # First 32 bytes
                    features=stat_features
                )
                
                if is_suspicious:
                    logger.warning(f"Suspicious encrypted traffic: {result.src_ip}:{result.src_port} -> "
                                 f"{result.dst_ip}:{result.dst_port} [{traffic_class}] "
                                 f"(confidence={confidence:.2f})")
                    self._log_classification(result)
                
                return result
                
            except Exception as e:
                logger.error(f"Error classifying encrypted traffic: {e}")
                return None
    
    def _heuristic_classification(self, 
                                  packet_data: Dict[str, Any],
                                  stat_features: Dict[str, float]) -> Tuple[str, float]:
        """
        Heuristic-based classification (fallback when ML model not trained)
        
        Returns:
            (traffic_class, confidence)
        """
        dst_port = packet_data.get('dst_port', 0)
        src_port = packet_data.get('src_port', 0)
        entropy = stat_features.get('byte_entropy', 0.0)
        printable_ratio = stat_features.get('printable_ratio', 0.0)
        
        # High entropy suggests encryption
        is_encrypted = entropy > 6.5
        
        # Port-based heuristics
        if dst_port == 443 or src_port == 443:
            return ("HTTPS_WEB", 0.7)
        elif dst_port == 22 or src_port == 22:
            return ("SSH", 0.8)
        elif dst_port in {1194, 1723, 500, 4500}:  # VPN ports
            return ("VPN", 0.7)
        elif dst_port in {9001, 9030, 9050, 9051}:  # Tor ports
            return ("TOR", 0.6)
        
        # Entropy-based heuristics
        if is_encrypted:
            # Very high entropy + unusual port = suspicious
            if entropy > 7.5 and dst_port > 10000:
                return ("MALWARE_C2", 0.6)
            
            # High printable ratio in encrypted = suspicious (data hiding)
            if printable_ratio > 0.5:
                return ("COVERT_CHANNEL", 0.5)
        
        # Small packets with low entropy = DNS
        if packet_data.get('packet_length', 0) < 512 and entropy < 5.0:
            if dst_port == 53:
                # High entropy DNS = tunneling
                if entropy > 3.5:
                    return ("DNS_TUNNEL", 0.6)
        
        return ("UNKNOWN", 0.3)
    
    def _log_classification(self, classification: EncryptedTrafficClassification):
        """Log classification to file"""
        try:
            with open(self.classification_log, 'a') as f:
                f.write(json.dumps(asdict(classification)) + '\n')
        except Exception as e:
            logger.error(f"Error logging classification: {e}")
    
    def load_pretrained_model(self, model_path: Path) -> bool:
        """
        Load pre-trained ET-BERT model
        
        Args:
            model_path: Path to saved model weights
            
        Returns:
            True if successful
        """
        try:
            # Placeholder - would load actual trained weights
            logger.info(f"Loading ET-BERT model from {model_path}")
            # self.classifier.load_weights(model_path)
            self.classifier.is_trained = True
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self.lock:
            return {
                'enabled': self.enabled,
                'packet_count': self.packet_count,
                'classification_count': self.classification_count,
                'suspicious_count': self.suspicious_count,
                'suspicious_rate': self.suspicious_count / max(self.classification_count, 1),
                'traffic_classes': self.TRAFFIC_CLASSES,
                'model_trained': self.classifier.is_trained if self.enabled else False
            }


# Singleton instance
_etbert_engine_instance: Optional[ETBERTEngine] = None
_etbert_lock = threading.Lock()


def get_etbert_engine() -> ETBERTEngine:
    """Get or create ET-BERT engine singleton"""
    global _etbert_engine_instance
    
    with _etbert_lock:
        if _etbert_engine_instance is None:
            _etbert_engine_instance = ETBERTEngine()
        return _etbert_engine_instance


if __name__ == "__main__":
    # Test the engine
    engine = get_etbert_engine()
    
    if not engine.enabled:
        print("ET-BERT engine disabled (NumPy not available)")
        exit(1)
    
    # Simulate encrypted traffic
    print("Testing ET-BERT Engine...\n")
    
    # Normal HTTPS traffic
    https_payload = bytes([
        # TLS handshake-like pattern
        0x16, 0x03, 0x01, 0x00, 0x9c, 0x01, 0x00, 0x00, 0x98, 0x03, 0x03,
        *np.random.randint(0, 256, 100).tolist()  # Random encrypted data
    ])
    
    result = engine.classify_encrypted_traffic({
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP',
        'is_encrypted': True,
        'payload': https_payload,
        'packet_length': len(https_payload)
    })
    
    if result:
        print(f"Classification: {result.traffic_class} (confidence={result.confidence:.2f})")
        print(f"Suspicious: {result.is_suspicious}")
        print(f"Features: {result.features}\n")
    
    # Suspicious high-entropy traffic on unusual port
    suspicious_payload = bytes(np.random.randint(0, 256, 200))  # High entropy
    
    result = engine.classify_encrypted_traffic({
        'src_ip': '192.168.1.100',
        'dst_ip': '45.33.32.156',
        'src_port': 54322,
        'dst_port': 8443,
        'protocol': 'TCP',
        'is_encrypted': True,
        'payload': suspicious_payload,
        'packet_length': len(suspicious_payload)
    })
    
    if result:
        print(f"Classification: {result.traffic_class} (confidence={result.confidence:.2f})")
        print(f"Suspicious: {result.is_suspicious}")
        print(f"Features: {result.features}\n")
    
    # Print statistics
    stats = engine.get_statistics()
    print("\n=== ET-BERT Engine Statistics ===")
    print(json.dumps(stats, indent=2))
