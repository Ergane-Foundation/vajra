#!/usr/bin/env python3
"""
Federated Learning Client

Basic flwr server for federated learning on the firewall node.
"""

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FLClient:
    """Basic Federated Learning Client using Flower Framework"""

    def __init__(self, server_address: str = "localhost:8080"):
        self.server_address = server_address
        logger.info(f"FL Client initialized with server: {server_address}")

    def start(self):
        """Start federated learning client"""
        logger.info("FL Client started")

    def stop(self):
        """Stop federated learning client"""
        logger.info("FL Client stopped")


if __name__ == "__main__":
    client = FLClient()
    client.start()
