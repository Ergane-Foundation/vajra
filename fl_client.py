#!/usr/bin/env python3
"""
Federated Learning Client

Basic federated learning client for the firewall node.
Reads Suricata eve.json logs, trains models locally,
and sends updates to the central FL server (privacy-preserving).

Features:
- Reads Suricata eve.json alerts
- Extracts features for attack detection
- Trains local models (Random Forest)
- Privacy-preserving: only model weights shared, no raw data

Usage:
    # Start FL client and connect to server
    python3 fl_client.py --server-host localhost:8080
    
    # Dry run (train locally, don't send updates)
    python3 fl_client.py --dry-run
"""

import os
import logging
import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/fl_client.log')
    ]
)
logger = logging.getLogger("fl_client")


# ============================================================================
# Eve.json Parser
# ============================================================================

class EvejsonParser:
    """Parse Suricata eve.json logs"""
    
    def __init__(self, eve_path: str = "logs/eve.json"):
        self.eve_path = Path(eve_path)
        self.parsed_alerts = []
    
    def load_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Load alerts from the last N hours
        
        Args:
            hours: Number of hours to look back
        
        Returns:
            List of alert dictionaries
        """
        if not self.eve_path.exists():
            logger.warning(f"EVE file not found: {self.eve_path}")
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        alerts = []
        
        try:
            with open(self.eve_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        
                        # Only process alerts
                        if event.get('event_type') == 'alert':
                            # Check timestamp
                            timestamp_str = event.get('timestamp', '')
                            if timestamp_str:
                                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                if timestamp >= cutoff_time:
                                    alerts.append(event)
                    except (json.JSONDecodeError, ValueError):
                        continue
            
            logger.info(f"Loaded {len(alerts)} alerts from last {hours} hours")
            return alerts
        
        except Exception as e:
            logger.error(f"Error loading eve.json: {e}")
            return []


# ============================================================================
# Feature Extraction
# ============================================================================

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of string"""
    if not data:
        return 0.0
    
    # Count character frequencies
    counts = Counter(data)
    total = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    
    return entropy


class FeatureExtractor:
    """Extract features from Suricata alerts for ML training"""
    
    @staticmethod
    def extract_features(alert: Dict) -> Dict[str, float]:
        """
        Extract features from a Suricata alert
        
        Args:
            alert: Suricata alert dictionary
        
        Returns:
            Feature dictionary
        """
        features = {}
        
        # Basic network features
        features['src_port'] = float(alert.get('src_port', 0))
        features['dest_port'] = float(alert.get('dest_port', 0))
        features['proto'] = alert.get('proto', 'TCP')
        
        # Protocol encoding
        proto_map = {'TCP': 6.0, 'UDP': 17.0, 'ICMP': 1.0}
        features['protocol_num'] = proto_map.get(features['proto'], 0.0)
        
        # Flow features (if available)
        flow = alert.get('flow', {})
        features['flow_pkts_toserver'] = float(flow.get('pkts_toserver', 0))
        features['flow_pkts_toclient'] = float(flow.get('pkts_toclient', 0))
        features['flow_bytes_toserver'] = float(flow.get('bytes_toserver', 0))
        features['flow_bytes_toclient'] = float(flow.get('bytes_toclient', 0))
        
        # Packet features (if available)
        packet_info = alert.get('packet_info', {})
        features['packet_length'] = float(packet_info.get('length', 0))
        
        # Payload features
        payload = alert.get('payload', '')
        features['payload_length'] = float(len(payload))
        features['has_payload'] = float(len(payload) > 0)
        
        # Calculate entropy if payload exists
        if payload:
            features['payload_entropy'] = calculate_entropy(payload)
        else:
            features['payload_entropy'] = 0.0
        
        # Alert metadata
        features['severity'] = float(alert.get('alert', {}).get('severity', 3))
        
        return features


# ============================================================================
# Local Trainer
# ============================================================================

class LocalTrainer:
    """Train ML models locally on firewall data"""
    
    def __init__(self):
        self.model = None
        self.feature_names = []
    
    def prepare_dataset(self, alerts: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training dataset from alerts
        
        Args:
            alerts: List of Suricata alerts
        
        Returns:
            (X, y) - Features and labels
        """
        X_list = []
        y_list = []
        
        for alert in alerts:
            # Extract features
            features = FeatureExtractor.extract_features(alert)
            
            # Store feature names (first iteration only)
            if not self.feature_names:
                self.feature_names = sorted(features.keys())
            
            # Convert to feature vector
            feature_vector = [features.get(name, 0.0) for name in self.feature_names]
            X_list.append(feature_vector)
            
            # Label: 1 for malicious (all alerts are malicious)
            y_list.append(1)
        
        # Add some benign samples (synthetic for now)
        # In production, you'd have legitimate traffic logs
        num_benign = max(len(X_list) // 2, 10)
        for _ in range(num_benign):
            benign_features = [0.0] * len(self.feature_names)
            X_list.append(benign_features)
            y_list.append(0)
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        logger.info(f"Prepared dataset: {X.shape[0]} samples, {X.shape[1]} features")
        return X, y
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Train local model
        
        Args:
            X: Feature matrix
            y: Labels
        
        Returns:
            Training metrics
        """
        if len(X) < 10:
            logger.warning(f"Insufficient data: {len(X)} samples")
            return {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest
        logger.info("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0)
        }
        
        logger.info(f"Model trained - Accuracy: {metrics['accuracy']:.3f}, "
                   f"Precision: {metrics['precision']:.3f}, "
                   f"Recall: {metrics['recall']:.3f}")
        
        return metrics
    
    def get_model_weights(self) -> bytes:
        """
        Get model weights for federated learning
        
        Returns:
            Serialized model weights
        """
        if self.model is None:
            return b""
        
        # Serialize model
        return pickle.dumps(self.model)
    
    def save_model(self, path: str):
        """Save model to disk"""
        if self.model is None:
            logger.warning("No model to save")
            return
        
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)
        logger.info(f"Model saved to {path}")


# ============================================================================
# FL Client
# ============================================================================


# ============================================================================
# FL Client
# ============================================================================

class FLClient:
    """Federated Learning Client"""

    def __init__(self, server_address: str = "localhost:8080", eve_json_path: str = "logs/eve.json"):
        self.server_address = server_address
        self.eve_json_path = eve_json_path
        self.parser = EvejsonParser(eve_json_path)
        self.trainer = LocalTrainer()
        logger.info(f"FL Client initialized with server: {server_address}")

    def train_local_model(self, hours: int = 24) -> Dict[str, float]:
        """
        Train local model on recent alerts
        
        Args:
            hours: Number of hours of data to use
        
        Returns:
            Training metrics
        """
        logger.info(f"Loading alerts from last {hours} hours...")
        alerts = self.parser.load_recent_alerts(hours=hours)
        
        if len(alerts) < 5:
            logger.warning(f"Insufficient alerts for training: {len(alerts)}")
            return {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0}
        
        logger.info(f"Preparing dataset from {len(alerts)} alerts...")
        X, y = self.trainer.prepare_dataset(alerts)
        
        logger.info("Training local model...")
        metrics = self.trainer.train(X, y)
        
        return metrics

    def send_model_update(self, dry_run: bool = False):
        """
        Send model update to FL server
        
        Args:
            dry_run: If True, don't actually send (for testing)
        """
        if self.trainer.model is None:
            logger.warning("No model to send")
            return
        
        if dry_run:
            logger.info("DRY RUN: Would send model update to FL server")
            logger.info(f"  Server: {self.server_address}")
            logger.info(f"  Model size: {len(self.trainer.get_model_weights())} bytes")
            return
        
        # In production, implement actual network communication here
        logger.info(f"Sending model update to {self.server_address}...")
        logger.info("(Network communication not implemented in basic version)")

    def start(self, hours: int = 24, dry_run: bool = False):
        """
        Start federated learning client
        
        Args:
            hours: Hours of data to use for training
            dry_run: If True, train but don't send updates
        """
        logger.info("Starting FL Client...")
        
        # Train local model
        metrics = self.train_local_model(hours=hours)
        
        if metrics['accuracy'] > 0:
            # Save model locally
            self.trainer.save_model("ml_models/fl_local_model.pkl")
            
            # Send update to server (if not dry run)
            self.send_model_update(dry_run=dry_run)
        
        logger.info("FL Client finished")

    def stop(self):
        """Stop federated learning client"""
        logger.info("FL Client stopped")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Federated Learning Client')
    parser.add_argument('--server-host', default='localhost:8080',
                       help='FL server address (host:port)')
    parser.add_argument('--eve-json', default='logs/eve.json',
                       help='Path to Suricata eve.json')
    parser.add_argument('--hours', type=int, default=24,
                       help='Hours of data to use for training')
    parser.add_argument('--dry-run', action='store_true',
                       help='Train locally but do not send updates')
    
    args = parser.parse_args()
    
    client = FLClient(
        server_address=args.server_host,
        eve_json_path=args.eve_json
    )
    
    try:
        client.start(hours=args.hours, dry_run=args.dry_run)
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        client.stop()
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        client.stop()
