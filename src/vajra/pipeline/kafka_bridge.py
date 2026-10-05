#!/usr/bin/env python3
"""
Kafka Bridge - Reads Suricata eve.json and pushes alerts to Kafka

This is the "bridge" that connects Suricata logs to the Kafka queue.
It watches eve.json for new alerts and publishes them to Kafka.
"""

import json
import time
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Kafka imports
try:
    from confluent_kafka import Producer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("Warning: confluent_kafka not installed. Run: pip install confluent_kafka")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/kafka_bridge.log')
    ]
)
logger = logging.getLogger("kafka_bridge")


class KafkaBridge:
    """Reads Suricata eve.json and publishes alerts to Kafka"""
    
    def __init__(
        self,
        eve_path: str = "logs/eve.json",
        kafka_broker: str = "localhost:9092",
        topic: str = "suricata-alerts"
    ):
        self.eve_path = Path(eve_path)
        self.topic = topic
        self.last_position = 0
        self.alerts_sent = 0
        
        # Initialize Kafka producer
        if KAFKA_AVAILABLE:
            self.producer = Producer({
                'bootstrap.servers': kafka_broker,
                'client.id': 'vajra-kafka-bridge',
                'acks': 'all',
                'retries': 3,
                'retry.backoff.ms': 500,
            })
            logger.info(f"Kafka producer connected to {kafka_broker}")
        else:
            self.producer = None
            logger.warning("Kafka not available - alerts will only be logged")
    
    def delivery_callback(self, err, msg):
        """Called when message is delivered or fails"""
        if err:
            logger.error(f"Message delivery failed: {err}")
        else:
            logger.debug(f"Alert delivered to {msg.topic()} [{msg.partition()}]")
    
    def parse_alert(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a JSON line from eve.json and extract alert data"""
        try:
            event = json.loads(line.strip())
            
            # Only process alert events
            if event.get("event_type") != "alert":
                return None
            
            alert_data = event.get("alert", {})
            
            # Build standardized alert format
            alert = {
                "alert_id": f"alert-{event.get('timestamp', '')}-{alert_data.get('signature_id', 0)}",
                "timestamp": event.get("timestamp", datetime.utcnow().isoformat()),
                "signature": alert_data.get("signature", "Unknown"),
                "signature_id": alert_data.get("signature_id", 0),
                "severity": self._map_severity(alert_data.get("severity", 3)),
                "category": alert_data.get("category", "Unknown"),
                "src_ip": event.get("src_ip", ""),
                "src_port": event.get("src_port", 0),
                "dest_ip": event.get("dest_ip", ""),
                "dest_port": event.get("dest_port", 0),
                "proto": event.get("proto", ""),
                "app_proto": event.get("app_proto", ""),
                "flow_id": event.get("flow_id", 0),
                "payload": event.get("payload", ""),
                "http": event.get("http", {}),
                "dns": event.get("dns", {}),
                "raw": event  # Include full event for debugging
            }
            
            return alert
            
        except json.JSONDecodeError as e:
            logger.debug(f"Invalid JSON line: {e}")
            return None
    
    def _map_severity(self, suricata_severity: int) -> str:
        """Map Suricata severity (1-4) to string"""
        mapping = {
            1: "CRITICAL",
            2: "HIGH", 
            3: "MEDIUM",
            4: "LOW"
        }
        return mapping.get(suricata_severity, "MEDIUM")
    
    def publish_alert(self, alert: Dict[str, Any]):
        """Publish alert to Kafka topic"""
        if self.producer:
            try:
                self.producer.produce(
                    self.topic,
                    key=alert.get("src_ip", "unknown").encode('utf-8'),
                    value=json.dumps(alert).encode('utf-8'),
                    callback=self.delivery_callback
                )
                self.producer.poll(0)  # Trigger callbacks
                self.alerts_sent += 1
                
                logger.info(
                    f"Alert #{self.alerts_sent}: {alert['signature']} | "
                    f"{alert['src_ip']}:{alert['src_port']} -> {alert['dest_ip']}:{alert['dest_port']}"
                )
                
            except Exception as e:
                logger.error(f"Failed to publish alert: {e}")
        else:
            # Fallback: just log it
            logger.info(f"[NO KAFKA] Alert: {alert['signature']} from {alert['src_ip']}")
    
    def tail_file(self):
        """Tail eve.json and process new lines"""
        logger.info(f"Starting to tail {self.eve_path}")
        
        # Wait for file to exist
        while not self.eve_path.exists():
            logger.info(f"Waiting for {self.eve_path} to be created...")
            time.sleep(2)
        
        # Start from end of file
        self.last_position = self.eve_path.stat().st_size
        logger.info(f"Starting from position {self.last_position}")
        
        while True:
            try:
                current_size = self.eve_path.stat().st_size
                
                if current_size < self.last_position:
                    # File was rotated/truncated
                    logger.info("Log file rotated, starting from beginning")
                    self.last_position = 0
                
                if current_size > self.last_position:
                    with open(self.eve_path, 'r') as f:
                        f.seek(self.last_position)
                        
                        for line in f:
                            alert = self.parse_alert(line)
                            if alert:
                                self.publish_alert(alert)
                        
                        self.last_position = f.tell()
                    
                    # Flush pending Kafka messages
                    if self.producer:
                        self.producer.flush(timeout=1)
                
                time.sleep(0.1)  # Poll every 100ms
                
            except FileNotFoundError:
                logger.warning(f"File {self.eve_path} not found, waiting...")
                time.sleep(2)
            except Exception as e:
                logger.error(f"Error reading file: {e}")
                time.sleep(1)
    
    def run(self):
        """Main run loop"""
        logger.info("=" * 50)
        logger.info("Vajra Kafka Bridge Starting")
        logger.info(f"  Eve file: {self.eve_path}")
        logger.info(f"  Kafka topic: {self.topic}")
        logger.info("=" * 50)
        
        try:
            self.tail_file()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.producer:
                self.producer.flush()
            logger.info(f"Total alerts sent: {self.alerts_sent}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kafka Bridge for Suricata alerts")
    parser.add_argument("--eve", default="logs/eve.json", help="Path to eve.json")
    parser.add_argument("--broker", default="localhost:9092", help="Kafka broker address")
    parser.add_argument("--topic", default="suricata-alerts", help="Kafka topic name")
    args = parser.parse_args()
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    bridge = KafkaBridge(
        eve_path=args.eve,
        kafka_broker=args.broker,
        topic=args.topic
    )
    bridge.run()


if __name__ == "__main__":
    main()
