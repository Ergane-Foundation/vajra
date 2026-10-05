#!/usr/bin/env python3
"""
Federated Learning Server Manager

Runs on your central cloud server. Aggregates model updates from multiple
firewall clients using Federated Learning (Flower framework).

Each model type runs on a separate port:
- Port 8081: SQL Injection model
- Port 8082: DDoS model
- Port 8083: XSS model
- Port 8084: General threat model

Architecture:
1. Clients (firewalls) train local models on their eve.json logs
2. Clients send model updates to this server
3. Server aggregates updates using FedAvg algorithm
4. Server saves the global model to fl_models/
5. Inference API loads the latest global models

Usage:
    # Start all FL servers
    python3 -m vajra.experimental.federated.server --all
    
    # Start specific model server
    python3 -m vajra.experimental.federated.server --model sqli --port 8081
"""

import os
import logging
import argparse
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import threading
import time

import flwr as fl
from flwr.server.strategy import FedAvg
from flwr.common import Metrics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/fl_server.log')
    ]
)
logger = logging.getLogger("fl_server")

# Model configurations
MODEL_CONFIGS = {
    'sqli': {
        'port': 8081,
        'name': 'SQL Injection Detector',
        'model_file': 'sqli_model.pkl',
        'min_clients': 2,
        'min_available_clients': 2,
    },
    'ddos': {
        'port': 8082,
        'name': 'DDoS Attack Detector',
        'model_file': 'ddos_model.pkl',
        'min_clients': 2,
        'min_available_clients': 2,
    },
    'xss': {
        'port': 8083,
        'name': 'XSS Attack Detector',
        'model_file': 'xss_model.pkl',
        'min_clients': 2,
        'min_available_clients': 2,
    },
    'general': {
        'port': 8084,
        'name': 'General Threat Detector',
        'model_file': 'general_model.pkl',
        'min_clients': 2,
        'min_available_clients': 2,
    }
}

MODELS_DIR = Path("fl_models")
MODELS_DIR.mkdir(exist_ok=True)


# Federated Learning Strategy

def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
    """
    Aggregate metrics from multiple clients
    
    Args:
        metrics: List of (num_examples, metrics_dict) tuples
    
    Returns:
        Aggregated metrics
    """
    # Calculate weighted averages
    total_examples = sum(num_examples for num_examples, _ in metrics)
    
    if total_examples == 0:
        return {}
    
    # Aggregate accuracy
    accuracies = [num_examples * m.get("accuracy", 0.0) for num_examples, m in metrics]
    weighted_accuracy = sum(accuracies) / total_examples
    
    # Aggregate loss
    losses = [num_examples * m.get("loss", 0.0) for num_examples, m in metrics]
    weighted_loss = sum(losses) / total_examples
    
    return {
        "accuracy": weighted_accuracy,
        "loss": weighted_loss,
        "total_examples": total_examples
    }


def create_strategy(model_type: str, config: Dict) -> FedAvg:
    """
    Create a Federated Averaging strategy for the model
    
    Args:
        model_type: Type of model (sqli, ddos, xss, general)
        config: Model configuration
    
    Returns:
        FedAvg strategy
    """
    strategy = FedAvg(
        # Minimum number of clients to start training
        min_fit_clients=config['min_clients'],
        min_evaluate_clients=config['min_clients'],
        min_available_clients=config['min_available_clients'],
        
        # Aggregation function
        evaluate_metrics_aggregation_fn=weighted_average,
        
        # Fraction of clients to sample
        fraction_fit=1.0,  # Use all available clients
        fraction_evaluate=1.0,
        
        # Initial parameters (optional)
        # initial_parameters=None,
    )
    
    logger.info(f"Created FedAvg strategy for {model_type}")
    return strategy


# Model Persistence

def save_global_model(model_type: str, parameters, round_num: int):
    """
    Save the aggregated global model to disk
    
    Args:
        model_type: Type of model
        parameters: Model parameters
        round_num: Training round number
    """
    try:
        model_file = MODELS_DIR / MODEL_CONFIGS[model_type]['model_file']
        
        # In a real implementation, you'd convert parameters to model format
        # For now, we just save the parameters
        model_data = {
            'parameters': parameters,
            'model_type': model_type,
            'round': round_num,
            'timestamp': time.time()
        }
        
        with open(model_file, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"[OK] Saved global model for {model_type} (round {round_num})")
        
    except Exception as e:
        logger.error(f"Failed to save global model for {model_type}: {e}")


# FL Server

class FLServerManager:
    """Manages Federated Learning servers for different model types"""
    
    def __init__(self):
        self.servers = {}
        self.threads = {}
    
    def start_server(self, model_type: str, port: int, num_rounds: int = 10):
        """
        Start a FL server for a specific model type
        
        Args:
            model_type: Type of model (sqli, ddos, xss, general)
            port: Port to listen on
            num_rounds: Number of federated learning rounds
        """
        config = MODEL_CONFIGS.get(model_type)
        if not config:
            logger.error(f"Unknown model type: {model_type}")
            return
        
        logger.info(f"Starting FL server for {config['name']} on port {port}")
        
        # Create strategy
        strategy = create_strategy(model_type, config)
        
        # Configure server
        server_config = fl.server.ServerConfig(num_rounds=num_rounds)
        
        def run_server():
            try:
                # Start Flower server
                fl.server.start_server(
                    server_address=f"0.0.0.0:{port}",
                    config=server_config,
                    strategy=strategy,
                )
            except Exception as e:
                logger.error(f"FL server error for {model_type}: {e}")
        
        # Start server in thread
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        
        self.servers[model_type] = {
            'port': port,
            'thread': thread,
            'config': config
        }
        
        logger.info(f"[OK] FL server started for {model_type} on port {port}")
    
    def start_all_servers(self, num_rounds: int = 10):
        """Start FL servers for all model types"""
        for model_type, config in MODEL_CONFIGS.items():
            self.start_server(model_type, config['port'], num_rounds)
    
    def stop_server(self, model_type: str):
        """Stop a specific FL server"""
        if model_type in self.servers:
            logger.info(f"Stopping FL server for {model_type}")
            # Note: Flower doesn't have a clean shutdown mechanism
            # Threads will be daemon threads and stop when main thread exits
            del self.servers[model_type]
    
    def stop_all_servers(self):
        """Stop all FL servers"""
        for model_type in list(self.servers.keys()):
            self.stop_server(model_type)
    
    def get_status(self) -> Dict:
        """Get status of all servers"""
        status = {}
        for model_type, server_info in self.servers.items():
            status[model_type] = {
                'running': server_info['thread'].is_alive(),
                'port': server_info['port'],
                'name': server_info['config']['name']
            }
        return status


# Main Entry Point

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="FL Server Manager for Vajra")
    parser.add_argument('--all', action='store_true', help='Start all FL servers')
    parser.add_argument('--model', type=str, choices=['sqli', 'ddos', 'xss', 'general'],
                        help='Model type to start server for')
    parser.add_argument('--port', type=int, help='Port to listen on')
    parser.add_argument('--rounds', type=int, default=10, help='Number of FL rounds')
    
    args = parser.parse_args()
    
    # Ensure logs directory exists
    Path("logs").mkdir(exist_ok=True)
    
    # Create server manager
    manager = FLServerManager()
    
    try:
        if args.all:
            # Start all servers
            logger.info("Starting all FL servers...")
            manager.start_all_servers(num_rounds=args.rounds)
            
            # Print status
            logger.info("\n" + "="*60)
            logger.info("FL Servers Running:")
            logger.info("="*60)
            for model_type, config in MODEL_CONFIGS.items():
                logger.info(f"  {config['name']:30} → localhost:{config['port']}")
            logger.info("="*60)
            
        elif args.model and args.port:
            # Start specific server
            manager.start_server(args.model, args.port, num_rounds=args.rounds)
            
        else:
            parser.print_help()
            return
        
        # Keep running
        logger.info("\nFL servers running. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(10)
            # Periodically log status
            status = manager.get_status()
            active = sum(1 for s in status.values() if s['running'])
            logger.info(f"Status: {active}/{len(status)} servers active")
    
    except KeyboardInterrupt:
        logger.info("\nShutting down FL servers...")
        manager.stop_all_servers()
        logger.info("FL servers stopped")
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        manager.stop_all_servers()


if __name__ == "__main__":
    main()
