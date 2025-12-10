#!/usr/bin/env python3
"""
DPDK Feature Consumer - Python bridge to DPDK packet processor

Reads packet features from DPDK shared memory ring buffer and
feeds them to the ML pipeline for threat detection.

This replaces Scapy-based packet capture with DPDK fast-path.
"""

import json
import time
import logging
import ctypes
import mmap
import struct
from pathlib import Path
from typing import Optional, Dict, Any, Iterator
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger("dpdk_consumer")


@dataclass
class DPDKPacketFeatures:
    """
    Packet features extracted by DPDK processor
    Mirrors the C struct packet_features
    """
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    protocol_num: int
    size: int
    payload_size: int
    ttl: int
    
    # TCP specific
    tcp_flags: str
    seq_num: int
    ack_num: int
    window_size: int
    
    # Application layer
    app_proto: str
    http_method: str
    http_uri: str
    http_host: str
    dns_query: str
    
    # Payload analysis
    payload_entropy: float
    payload_printable_ratio: float
    has_payload: bool
    
    # Suspicious flags
    suspicious: bool
    
    # Payload sample
    payload_hex: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for ML models"""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'protocol_num': self.protocol_num,
            'size': self.size,
            'payload_size': self.payload_size,
            'ttl': self.ttl,
            'tcp_flags': self.tcp_flags,
            'seq_num': self.seq_num,
            'ack_num': self.ack_num,
            'window_size': self.window_size,
            'app_proto': self.app_proto,
            'http_method': self.http_method,
            'http_uri': self.http_uri,
            'http_host': self.http_host,
            'dns_query': self.dns_query,
            'payload_entropy': self.payload_entropy,
            'payload_printable_ratio': self.payload_printable_ratio,
            'has_payload': self.has_payload,
            'suspicious': self.suspicious,
            'raw_payload': self.payload_hex
        }


class DPDKFeatureRingConsumer:
    """
    Consumes packet features from DPDK shared memory ring buffer
    
    This uses DPDK's rte_ring for lock-free communication between
    the C++ DPDK packet processor and Python ML pipeline.
    """
    
    # C struct layout (must match dpdk_packet_processor.cpp)
    FEATURE_STRUCT_FORMAT = (
        "32s"    # timestamp
        "46s"    # src_ip
        "46s"    # dst_ip
        "H"      # src_port
        "H"      # dst_port
        "16s"    # protocol
        "B"      # protocol_num
        "I"      # size
        "I"      # payload_size
        "B"      # ttl
        "16s"    # tcp_flags
        "I"      # seq_num
        "I"      # ack_num
        "H"      # window_size
        "16s"    # app_proto
        "16s"    # http_method
        "256s"   # http_uri
        "128s"   # http_host
        "256s"   # dns_query
        "d"      # payload_entropy (double)
        "d"      # payload_printable_ratio (double)
        "B"      # has_payload
        "B"      # suspicious
        "1001s"  # payload_hex (500 * 2 + 1)
    )
    
    FEATURE_STRUCT_SIZE = struct.calcsize(FEATURE_STRUCT_FORMAT)
    
    def __init__(self, ring_name: str = "feature_ring", poll_interval: float = 0.001):
        """
        Initialize DPDK ring consumer
        
        Args:
            ring_name: Name of the DPDK ring (must match C++ code)
            poll_interval: Polling interval in seconds
        """
        self.ring_name = ring_name
        self.poll_interval = poll_interval
        self._running = False
        
        # Try to load DPDK shared library
        try:
            self.dpdk_lib = ctypes.CDLL("librte_ring.so")
            logger.info("Loaded DPDK librte_ring.so")
        except OSError:
            logger.warning("Could not load DPDK library. Ring mode unavailable.")
            self.dpdk_lib = None
    
    def parse_feature_struct(self, data: bytes) -> Optional[DPDKPacketFeatures]:
        """Parse binary feature struct from DPDK"""
        try:
            if len(data) < self.FEATURE_STRUCT_SIZE:
                return None
            
            unpacked = struct.unpack(self.FEATURE_STRUCT_FORMAT, data[:self.FEATURE_STRUCT_SIZE])
            
            # Helper to decode C strings
            def decode_cstr(b):
                return b.decode('utf-8', errors='ignore').rstrip('\x00')
            
            return DPDKPacketFeatures(
                timestamp=decode_cstr(unpacked[0]),
                src_ip=decode_cstr(unpacked[1]),
                dst_ip=decode_cstr(unpacked[2]),
                src_port=unpacked[3],
                dst_port=unpacked[4],
                protocol=decode_cstr(unpacked[5]),
                protocol_num=unpacked[6],
                size=unpacked[7],
                payload_size=unpacked[8],
                ttl=unpacked[9],
                tcp_flags=decode_cstr(unpacked[10]),
                seq_num=unpacked[11],
                ack_num=unpacked[12],
                window_size=unpacked[13],
                app_proto=decode_cstr(unpacked[14]),
                http_method=decode_cstr(unpacked[15]),
                http_uri=decode_cstr(unpacked[16]),
                http_host=decode_cstr(unpacked[17]),
                dns_query=decode_cstr(unpacked[18]),
                payload_entropy=unpacked[19],
                payload_printable_ratio=unpacked[20],
                has_payload=bool(unpacked[21]),
                suspicious=bool(unpacked[22]),
                payload_hex=decode_cstr(unpacked[23])
            )
            
        except Exception as e:
            logger.error(f"Error parsing feature struct: {e}")
            return None
    
    def consume(self) -> Iterator[DPDKPacketFeatures]:
        """
        Consume features from DPDK ring
        
        Yields:
            DPDKPacketFeatures objects
        """
        # TODO: Implement actual DPDK ring reading via ctypes
        # For now, this is a placeholder showing the interface
        
        logger.warning("DPDK ring consumption not yet fully implemented")
        logger.info("Falling back to JSON file mode")
        
        # Fallback: read from JSON file if DPDK ring not available
        # This allows testing the Python side independently
        yield from self._consume_from_json()
    
    def _consume_from_json(self, json_path: str = "/tmp/dpdk_features.json") -> Iterator[DPDKPacketFeatures]:
        """Fallback: consume from JSON file written by DPDK processor"""
        json_file = Path(json_path)
        position = 0
        
        logger.info(f"Consuming from JSON file: {json_path}")
        
        while self._running:
            try:
                if not json_file.exists():
                    time.sleep(self.poll_interval)
                    continue
                
                current_size = json_file.stat().st_size
                
                if current_size < position:
                    position = 0  # File rotated
                
                if current_size > position:
                    with open(json_file, 'r') as f:
                        f.seek(position)
                        
                        for line in f:
                            if not self._running:
                                break
                            
                            try:
                                data = json.loads(line.strip())
                                # Convert JSON to DPDKPacketFeatures
                                features = DPDKPacketFeatures(**data)
                                yield features
                            except (json.JSONDecodeError, TypeError) as e:
                                logger.debug(f"JSON parse error: {e}")
                        
                        position = f.tell()
                
                time.sleep(self.poll_interval)
                
            except Exception as e:
                logger.error(f"Error consuming from JSON: {e}")
                time.sleep(1)
    
    def start(self):
        """Start consuming"""
        self._running = True
    
    def stop(self):
        """Stop consuming"""
        self._running = False


class DPDKJSONConsumer:
    """
    Simpler alternative: consume features from JSON file
    
    The DPDK processor can write features to a JSON file instead of
    using shared memory. This is slower but easier to integrate.
    """
    
    def __init__(self, json_path: str = "/tmp/dpdk_features.json", poll_interval: float = 0.1):
        self.json_path = Path(json_path)
        self.poll_interval = poll_interval
        self._running = False
        self._position = 0
    
    def consume(self) -> Iterator[DPDKPacketFeatures]:
        """
        Consume features from JSON file
        
        Yields:
            DPDKPacketFeatures objects
        """
        logger.info(f"Starting JSON consumer: {self.json_path}")
        
        while self._running:
            try:
                if not self.json_path.exists():
                    time.sleep(self.poll_interval)
                    continue
                
                current_size = self.json_path.stat().st_size
                
                # Handle file rotation
                if current_size < self._position:
                    self._position = 0
                
                if current_size > self._position:
                    with open(self.json_path, 'r') as f:
                        f.seek(self._position)
                        
                        for line in f:
                            if not self._running:
                                return
                            
                            try:
                                data = json.loads(line.strip())
                                
                                # Convert dict to DPDKPacketFeatures
                                features = DPDKPacketFeatures(
                                    timestamp=data.get('timestamp', ''),
                                    src_ip=data.get('src_ip', ''),
                                    dst_ip=data.get('dst_ip', ''),
                                    src_port=data.get('src_port', 0),
                                    dst_port=data.get('dst_port', 0),
                                    protocol=data.get('protocol', ''),
                                    protocol_num=data.get('protocol_num', 0),
                                    size=data.get('size', 0),
                                    payload_size=data.get('payload_size', 0),
                                    ttl=data.get('ttl', 0),
                                    tcp_flags=data.get('tcp_flags', ''),
                                    seq_num=data.get('seq_num', 0),
                                    ack_num=data.get('ack_num', 0),
                                    window_size=data.get('window_size', 0),
                                    app_proto=data.get('app_proto', ''),
                                    http_method=data.get('http_method', ''),
                                    http_uri=data.get('http_uri', ''),
                                    http_host=data.get('http_host', ''),
                                    dns_query=data.get('dns_query', ''),
                                    payload_entropy=data.get('payload_entropy', 0.0),
                                    payload_printable_ratio=data.get('payload_printable_ratio', 0.0),
                                    has_payload=data.get('has_payload', False),
                                    suspicious=data.get('suspicious', False),
                                    payload_hex=data.get('payload_hex', '')
                                )
                                
                                yield features
                                
                            except (json.JSONDecodeError, KeyError, TypeError) as e:
                                logger.debug(f"JSON parse error: {e}")
                        
                        self._position = f.tell()
                
                time.sleep(self.poll_interval)
                
            except Exception as e:
                logger.error(f"Error reading JSON: {e}")
                time.sleep(1)
    
    def start(self):
        """Start consuming"""
        self._running = True
    
    def stop(self):
        """Stop consuming"""
        self._running = False


def test_consumer():
    """Test the DPDK consumer"""
    logging.basicConfig(level=logging.INFO)
    
    # Test JSON consumer
    consumer = DPDKJSONConsumer()
    consumer.start()
    
    print("Waiting for DPDK features...")
    print("Press Ctrl+C to stop")
    
    try:
        for features in consumer.consume():
            print(f"📦 {features.src_ip}:{features.src_port} -> "
                  f"{features.dst_ip}:{features.dst_port} [{features.protocol}] "
                  f"size={features.size} entropy={features.payload_entropy:.2f}")
            
            if features.suspicious:
                print(f"   🚨 SUSPICIOUS")
    
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        consumer.stop()


if __name__ == "__main__":
    test_consumer()
