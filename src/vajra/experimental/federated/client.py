#!/usr/bin/env python3
"""
Federated Learning Client Manager

Runs on your firewall. Reads eve.json logs, trains models locally,
and sends updates to the central FL server.

Features:
- Reads Suricata eve.json alerts
- Extracts features for different attack types
- Trains local models (SQLi, DDoS, XSS, General)
- Sends model updates to FL server (privacy-preserving)
- No raw log data is shared

Usage:
    # Train all models and update FL server
    python3 -m vajra.experimental.federated.client --all --server-host 192.168.1.100
    
    # Train specific model
    python3 -m vajra.experimental.federated.client --model sqli --server-host 192.168.1.100
    
    # Dry run (train locally, don't send updates)
    python3 -m vajra.experimental.federated.client --all --dry-run
"""

import os
import logging
import argparse
import json
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score
import flwr as fl

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

# Model configurations (must match server)
MODEL_CONFIGS = {
    'sqli': {
        'port': 8081,
        'signatures': ['SQL', 'INJECTION', 'UNION', 'SELECT'],
    },
    'ddos': {
        'port': 8082,
        'signatures': ['DOS', 'DDOS', 'FLOOD', 'SYN'],
    },
    'xss': {
        'port': 8083,
        'signatures': ['XSS', 'SCRIPT', 'CROSS-SITE'],
    },
    'general': {
        'port': 8084,
        'signatures': [],  # All other attacks
    }
}


# Data Loading & Feature Extraction

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
                    except json.JSONDecodeError:
                        continue
            
            logger.info(f"Loaded {len(alerts)} alerts from last {hours} hours")
            return alerts
        
        except Exception as e:
            logger.error(f"Error loading eve.json: {e}")
            return []


class FeatureExtractor:
    """Extract features from Suricata alerts for ML training"""
    
    @staticmethod
    def extract_features(alert: Dict) -> Dict[str, Any]:
        """
        Extract features from a Suricata alert
        
        Args:
            alert: Suricata alert dictionary
        
        Returns:
            Feature dictionary
        """
        features = {}
        
        # Basic network features
        features['src_port'] = alert.get('src_port', 0)
        features['dest_port'] = alert.get('dest_port', 0)
        features['proto'] = alert.get('proto', 'TCP')
        
        # Protocol encoding
        proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
        features['protocol_num'] = proto_map.get(features['proto'], 0)
        
        # Flow features (if available)
        flow = alert.get('flow', {})
        features['flow_pkts_toserver'] = flow.get('pkts_toserver', 0)
        features['flow_pkts_toclient'] = flow.get('pkts_toclient', 0)
        features['flow_bytes_toserver'] = flow.get('bytes_toserver', 0)
        features['flow_bytes_toclient'] = flow.get('bytes_toclient', 0)
        
        # Packet features (if available)
        packet_info = alert.get('packet_info', {})
        features['packet_length'] = packet_info.get('length', 0)
        
        # Payload features
        payload = alert.get('payload', '')
        features['payload_length'] = len(payload)
        features['has_payload'] = int(len(payload) > 0)
        
        # Calculate entropy if payload exists
        if payload:
            features['payload_entropy'] = calculate_entropy(payload)
        else:
            features['payload_entropy'] = 0.0
        
        # Alert metadata
        features['severity'] = alert.get('alert', {}).get('severity', 3)
        
        return features
    
    @staticmethod
    def classify_attack_type(alert: Dict) -> str:
        """
        Classify attack type from signature
        
        Args:
            alert: Suricata alert dictionary
        
        Returns:
            Attack type (sqli, ddos, xss, general)
        """
        signature = alert.get('alert', {}).get('signature', '').upper()
        
        # Check against each model's signatures
        for model_type, config in MODEL_CONFIGS.items():
            if any(sig in signature for sig in config['signatures']):
                return model_type
        
        return 'general'


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of string"""
    if not data:
        return 0.0
    
    from collections import Counter
    import math
    
    # Count character frequencies
    counts = Counter(data)
    total = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    
    return entropy


# Local Training

class LocalTrainer:
    """Train ML models locally on firewall data"""
    
    def __init__(self, model_type: str):
        self.model_type = model_type
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
            # Check if this alert is relevant for our model type
            attack_type = FeatureExtractor.classify_attack_type(alert)
            
            # For specific models, only use relevant attacks
            if self.model_type != 'general' and attack_type != self.model_type:
                continue
            
            # Extract features
            features = FeatureExtractor.extract_features(alert)
            
            # Store feature names (first iteration only)
            if not self.feature_names:
                self.feature_names = sorted(features.keys())
            
            # Convert to feature vector
            feature_vector = [features.get(name, 0) for name in self.feature_names]
            X_list.append(feature_vector)
            
            # Label: 1 for malicious (all alerts are malicious)
            y_list.append(1)
        
        # Add some benign samples (synthetic for now)
        # In production, you'd have legitimate traffic logs
        num_benign = len(X_list) // 2
        for _ in range(num_benign):
            benign_features = [0.0] * len(self.feature_names)
            X_list.append(benign_features)
            y_list.append(0)
        
        X = np.array(X_list)
        y = np.array(y_list)
        
        logger.info(f"Prepared dataset for {self.model_type}: {X.shape[0]} samples, {X.shape[1]} features")
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
            logger.warning(f"Insufficient data for {self.model_type}: {len(X)} samples")
            return {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        logger.info(f"Training {self.model_type} model...")
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
        }
        
        logger.info(f"[OK] {self.model_type} - Accuracy: {metrics['accuracy']:.3f}, "
                   f"Precision: {metrics['precision']:.3f}, Recall: {metrics['recall']:.3f}")
        
        return metrics
    
    def get_model_parameters(self):
        """Get model parameters for FL"""
        if self.model is None:
            return None
        
        # For sklearn models, we can serialize the entire model
        # In production FL, you'd extract weights/parameters
        return pickle.dumps(self.model)
    
    def save_model(self, path: Path):
        """Save model to disk"""
        if self.model:
            with open(path, 'wb') as f:
                pickle.dump(self.model, f)
            logger.info(f"Saved {self.model_type} model to {path}")


# Flower Client

class NGFWFlowerClient(fl.client.NumPyClient):
    """Flower client for NGFW federated learning"""
    
    def __init__(self, model_type: str, trainer: LocalTrainer, X: np.ndarray, y: np.ndarray):
        self.model_type = model_type
        self.trainer = trainer
        self.X = X
        self.y = y
    
    def get_parameters(self, config):
        """Return model parameters"""
        params = self.trainer.get_model_parameters()
        if params:
            return [params]  # Return as list
        return []
    
    def set_parameters(self, parameters):
        """Set model parameters from server"""
        if parameters and len(parameters) > 0:
            try:
                # Deserialize parameters and update model
                self.trainer.model = pickle.loads(parameters[0])
                logger.debug(f"Updated {self.model_type} model from server parameters")
            except Exception as e:
                logger.warning(f"Could not set parameters for {self.model_type}: {e}")
    
    def fit(self, parameters, config):
        """Train model on local data"""
        # Update model with server parameters if provided
        if parameters:
            self.set_parameters(parameters)
        
        # Train local model
        metrics = self.trainer.train(self.X, self.y)
        
        # Return updated parameters and metrics
        updated_params = self.trainer.get_model_parameters()
        
        return [updated_params] if updated_params else [], len(self.X), metrics
    
    def evaluate(self, parameters, config):
        """Evaluate model"""
        # Update model with server parameters if provided
        if parameters:
            self.set_parameters(parameters)
        
        if self.trainer.model is None:
            return 0.0, len(self.X), {"accuracy": 0.0}
        
        # Evaluate on local data
        y_pred = self.trainer.model.predict(self.X)
        accuracy = accuracy_score(self.y, y_pred)
        
        return 0.0, len(self.X), {"accuracy": accuracy}


# Main Client Manager

class FLClientManager:
    """Manage FL clients for different model types"""
    
    def __init__(self, server_host: str = "localhost"):
        self.server_host = server_host
        self.parser = EvejsonParser()
    
    def train_and_update(self, model_type: str, dry_run: bool = False):
        """
        Train a model locally and send update to FL server
        
        Args:
            model_type: Type of model (sqli, ddos, xss, general)
            dry_run: If True, train locally but don't send to server
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"Training {model_type.upper()} model")
        logger.info(f"{'='*60}")
        
        # Load recent alerts
        alerts = self.parser.load_recent_alerts(hours=24)
        
        if not alerts:
            logger.warning(f"No alerts found for {model_type}")
            return
        
        # Create trainer
        trainer = LocalTrainer(model_type)
        
        # Prepare dataset
        X, y = trainer.prepare_dataset(alerts)
        
        if len(X) == 0:
            logger.warning(f"No data for {model_type}")
            return
        
        # Train locally
        metrics = trainer.train(X, y)
        
        # Save local model
        local_model_path = Path("fl_models") / f"{model_type}_local.pkl"
        local_model_path.parent.mkdir(exist_ok=True)
        trainer.save_model(local_model_path)
        
        if dry_run:
            logger.info(f"Dry run mode - not sending to FL server")
            return
        
        # Connect to FL server and send update
        try:
            server_address = f"{self.server_host}:{MODEL_CONFIGS[model_type]['port']}"
            logger.info(f"Connecting to FL server: {server_address}")
            
            # Create FL client
            client = NGFWFlowerClient(model_type, trainer, X, y)
            
            # Start FL client
            fl.client.start_numpy_client(
                server_address=server_address,
                client=client,
            )
            
            logger.info(f"[OK] Successfully sent update to FL server for {model_type}")
        
        except Exception as e:
            logger.error(f"Failed to connect to FL server for {model_type}: {e}")
    
    def train_all_models(self, dry_run: bool = False):
        """Train all model types"""
        for model_type in MODEL_CONFIGS.keys():
            self.train_and_update(model_type, dry_run)


# Main Entry Point

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="FL Client Manager for NGFW")
    parser.add_argument('--all', action='store_true', help='Train all models')
    parser.add_argument('--model', type=str, choices=['sqli', 'ddos', 'xss', 'general'],
                        help='Specific model to train')
    parser.add_argument('--server-host', type=str, default='localhost',
                        help='FL server hostname/IP')
    parser.add_argument('--dry-run', action='store_true',
                        help='Train locally but don\'t send to server')
    parser.add_argument('--eve-path', type=str, default='logs/eve.json',
                        help='Path to eve.json file')
    
    args = parser.parse_args()
    
    # Ensure logs directory exists
    Path("logs").mkdir(exist_ok=True)
    
    # Create client manager
    manager = FLClientManager(server_host=args.server_host)
    
    try:
        if args.all:
            # Train all models
            logger.info("Training all models...")
            manager.train_all_models(dry_run=args.dry_run)
        
        elif args.model:
            # Train specific model
            manager.train_and_update(args.model, dry_run=args.dry_run)
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        logger.info("\nTraining interrupted")
    
    except Exception as e:
        logger.error(f"Training failed: {e}")


if __name__ == "__main__":
    main()
