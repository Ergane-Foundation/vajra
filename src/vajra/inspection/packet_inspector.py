#!/usr/bin/env python3
"""
Packet Inspector - Deep packet inspection with DPDK or Scapy

Captures network packets and extracts features for ML analysis.
Works alongside Suricata to provide enhanced ML-based threat detection.

Features:
- High-performance packet capture using DPDK (recommended)
- Legacy packet capture using Scapy (deprecated, fallback only)
- Feature extraction for ML models
- Integration with ML Model Manager
- Combined logging with Suricata events

Performance Modes:
- DPDK mode (--dpdk): Uses DPDK C++ packet processor for line-rate capture
- Scapy mode (default): Legacy Python-based capture (DEPRECATED)
"""

import json
import time
import logging
import os
import sys
import threading
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict
import queue

# DPDK consumer (recommended)
try:
    from vajra.inspection.dpdk_consumer import DPDKJSONConsumer, DPDKPacketFeatures
    DPDK_AVAILABLE = True
except ImportError:
    DPDK_AVAILABLE = False
    print("Warning: dpdk_consumer not available. Install DPDK support.")

# Scapy imports (DEPRECATED - legacy fallback only)
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, Raw,
        Ether, ARP, IPv6, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. DPDK mode recommended.")

# Local imports
try:
    from vajra.ml.manager import get_model_manager, MLPrediction
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from vajra.common.logging import setup_logging

logger = setup_logging("packet_inspector", "logs/packet_inspector.log")


@dataclass
class PacketFeatures:
    """Extracted features from a network packet"""
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    protocol_num: int
    size: int
    payload_size: int
    flags: str
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
    
    # Raw data for ML
    raw_payload: str


class FlowTracker:
    """Tracks network flows for feature aggregation"""
    
    def __init__(self, flow_timeout: int = 60):
        self.flows: Dict[str, Dict] = {}
        self.flow_timeout = flow_timeout
        self._lock = threading.Lock()
    
    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
        """Generate a unique flow key"""
        # Normalize flow key (bidirectional)
        if (src_ip, src_port) > (dst_ip, dst_port):
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
    
    def update_flow(self, packet_features: PacketFeatures) -> Dict[str, Any]:
        """Update flow statistics with new packet"""
        flow_key = self.get_flow_key(
            packet_features.src_ip,
            packet_features.dst_ip,
            packet_features.src_port,
            packet_features.dst_port,
            packet_features.protocol
        )
        
        now = time.time()
        
        with self._lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'start_time': now,
                    'last_seen': now,
                    'src_ip': packet_features.src_ip,
                    'dst_ip': packet_features.dst_ip,
                    'src_port': packet_features.src_port,
                    'dst_port': packet_features.dst_port,
                    'protocol': packet_features.protocol,
                    'packets_forward': 0,
                    'packets_backward': 0,
                    'bytes_forward': 0,
                    'bytes_backward': 0,
                    'flags_seen': set(),
                }
            
            flow = self.flows[flow_key]
            flow['last_seen'] = now
            
            # Determine direction
            is_forward = (packet_features.src_ip, packet_features.src_port) <= \
                        (packet_features.dst_ip, packet_features.dst_port)
            
            if is_forward:
                flow['packets_forward'] += 1
                flow['bytes_forward'] += packet_features.size
            else:
                flow['packets_backward'] += 1
                flow['bytes_backward'] += packet_features.size
            
            if packet_features.tcp_flags:
                flow['flags_seen'].add(packet_features.tcp_flags)
            
            # Calculate duration
            flow['duration'] = flow['last_seen'] - flow['start_time']
            
            # Convert set to list for JSON serialization
            flow_copy = flow.copy()
            flow_copy['flags_seen'] = list(flow['flags_seen'])
            
            return flow_copy
    
    def cleanup_expired(self):
        """Remove expired flows"""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self.flows.items() 
                      if now - v['last_seen'] > self.flow_timeout]
            for k in expired:
                del self.flows[k]
        return len(expired)


class PacketInspector:
    """
    Deep packet inspection engine with DPDK or Scapy
    
    Captures packets, extracts features, and runs ML predictions.
    
    Modes:
    - DPDK mode (recommended): High-performance capture with DPDK processor
    - Scapy mode (legacy): Python-based capture (DEPRECATED)
    """
    
    def __init__(
        self,
        interface: str = None,
        bpf_filter: str = "ip",
        ml_enabled: bool = True,
        log_file: str = "logs/packet_inspector.json",
        dpdk_mode: bool = False,
        dpdk_json_path: str = "/tmp/dpdk_features.json"
    ):
        self.dpdk_mode = dpdk_mode
        self.dpdk_json_path = dpdk_json_path
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.ml_enabled = ml_enabled and ML_AVAILABLE
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Check availability
        if self.dpdk_mode:
            if not DPDK_AVAILABLE:
                logger.error("DPDK mode requested but dpdk_consumer not available!")
                logger.error("Install DPDK support or use --no-dpdk for Scapy mode")
                self._running = False
                self.stats = {'status': 'disabled', 'reason': 'dpdk not available'}
                return
            logger.info("DPDK MODE ENABLED - High-performance packet processing")
            logger.info(f"  Reading features from: {dpdk_json_path}")
            self.dpdk_consumer = DPDKJSONConsumer(dpdk_json_path)
        else:
            # Legacy Scapy mode (DEPRECATED)
            logger.warning("[WARN]  SCAPY MODE (DEPRECATED) - Consider switching to DPDK for better performance")
            if not SCAPY_AVAILABLE:
                logger.error("Scapy is not available. Packet inspection will be disabled.")
                logger.error("Install with: pip install scapy (or use DPDK mode)")
                self._running = False
                self.stats = {'status': 'disabled', 'reason': 'scapy not available'}
                return
        
        # Flow tracking
        self.flow_tracker = FlowTracker()
        
        # ML Model Manager
        self.model_manager = get_model_manager() if self.ml_enabled else None
        
        # Packet queue for async processing
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        
        # Statistics
        self.stats = {
            'mode': 'dpdk' if self.dpdk_mode else 'scapy',
            'packets_captured': 0,
            'packets_processed': 0,
            'ml_predictions': 0,
            'threats_detected': 0,
            'errors': 0
        }
        
        # Control flags
        self._running = False
        self._stop_event = threading.Event()
        
        # Callbacks for threat detection
        self.threat_callbacks: List[Callable[[PacketFeatures, Optional[MLPrediction]], None]] = []
        
        logger.info(f"Packet Inspector initialized")
        logger.info(f"  Mode: {'DPDK' if self.dpdk_mode else 'Scapy (legacy)'}")
        logger.info(f"  Interface: {interface or 'all (DPDK handles)'}" if not self.dpdk_mode else f"  DPDK JSON: {dpdk_json_path}")
        logger.info(f"  BPF Filter: {bpf_filter}" if not self.dpdk_mode else "  (filtering done by DPDK)")
        logger.info(f"  ML Enabled: {self.ml_enabled}")
    
    def register_threat_callback(self, callback: Callable):
        """Register a callback for threat detection"""
        if not hasattr(self, 'threat_callbacks'):
            self.threat_callbacks = []
        self.threat_callbacks.append(callback)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                import math
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable ASCII characters"""
        if not data:
            return 0.0
        
        printable = sum(1 for b in data if 32 <= b <= 126)
        return printable / len(data)
    
    def _extract_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string"""
        if not tcp_layer:
            return ""
        
        flags = []
        if tcp_layer.flags.S:
            flags.append('S')
        if tcp_layer.flags.A:
            flags.append('A')
        if tcp_layer.flags.F:
            flags.append('F')
        if tcp_layer.flags.R:
            flags.append('R')
        if tcp_layer.flags.P:
            flags.append('P')
        if tcp_layer.flags.U:
            flags.append('U')
        
        return ''.join(flags)
    
    def extract_features(self, packet) -> Optional[PacketFeatures]:
        """Extract features from a Scapy packet"""
        try:
            if not packet.haslayer(IP) and not packet.haslayer(IPv6):
                return None
            
            # Basic IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ttl = ip.ttl
                proto_num = ip.proto
            else:
                ip6 = packet[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                ttl = ip6.hlim
                proto_num = ip6.nh
            
            # Protocol and ports
            src_port = 0
            dst_port = 0
            protocol = "OTHER"
            tcp_flags = ""
            seq_num = 0
            ack_num = 0
            window_size = 0
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = self._extract_tcp_flags(tcp)
                seq_num = tcp.seq
                ack_num = tcp.ack
                window_size = tcp.window
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            
            # Payload
            payload = b""
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
            
            # Application layer detection
            app_proto = ""
            http_method = ""
            http_uri = ""
            http_host = ""
            dns_query = ""
            
            # HTTP detection
            if payload and dst_port in (80, 8080, 8000) or src_port in (80, 8080, 8000):
                app_proto = "HTTP"
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    lines = payload_str.split('\r\n')
                    if lines:
                        first_line = lines[0]
                        if first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                            parts = first_line.split(' ')
                            if len(parts) >= 2:
                                http_method = parts[0]
                                http_uri = parts[1]
                        
                        for line in lines:
                            if line.lower().startswith('host:'):
                                http_host = line[5:].strip()
                                break
                except:
                    pass
            
            # HTTPS detection
            elif dst_port == 443 or src_port == 443:
                app_proto = "HTTPS"
            
            # DNS detection
            if packet.haslayer(DNS):
                app_proto = "DNS"
                dns = packet[DNS]
                if dns.qd:
                    dns_query = dns.qd.qname.decode('utf-8', errors='ignore')
            
            # SSH detection
            elif dst_port == 22 or src_port == 22:
                app_proto = "SSH"
            
            return PacketFeatures(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                protocol_num=proto_num,
                size=len(packet),
                payload_size=len(payload),
                flags=tcp_flags,
                ttl=ttl,
                tcp_flags=tcp_flags,
                seq_num=seq_num,
                ack_num=ack_num,
                window_size=window_size,
                app_proto=app_proto,
                http_method=http_method,
                http_uri=http_uri,
                http_host=http_host,
                dns_query=dns_query,
                payload_entropy=self._calculate_entropy(payload),
                payload_printable_ratio=self._calculate_printable_ratio(payload),
                has_payload=len(payload) > 0,
                raw_payload=payload[:500].hex() if payload else ""  # First 500 bytes
            )
            
        except Exception as e:
            logger.debug(f"Feature extraction error: {e}")
            self.stats['errors'] += 1
            return None
    
    def _packet_callback(self, packet):
        """Callback for each captured packet"""
        self.stats['packets_captured'] += 1
        
        # Extract features
        features = self.extract_features(packet)
        if not features:
            return
        
        self.stats['packets_processed'] += 1
        
        # Update flow tracker
        flow_data = self.flow_tracker.update_flow(features)
        
        # Run ML prediction if enabled
        ml_prediction = None
        if self.ml_enabled and self.model_manager:
            # Convert features to dict for ML
            feature_dict = asdict(features)
            feature_dict.update(flow_data)  # Add flow features
            
            # Run all models
            predictions = self.model_manager.predict_all(feature_dict, data_type="network")
            
            if predictions:
                self.stats['ml_predictions'] += 1
                
                # Check for threats
                for name, pred in predictions.items():
                    if pred.is_threat:
                        self.stats['threats_detected'] += 1
                        ml_prediction = pred
                        
                        logger.warning(
                            f"[ALERT] ML THREAT: {pred.threat_type} | "
                            f"{features.src_ip}:{features.src_port} -> "
                            f"{features.dst_ip}:{features.dst_port} | "
                            f"Model: {name} | Confidence: {pred.confidence:.2%}"
                        )
                        
                        # Call threat callbacks
                        for callback in self.threat_callbacks:
                            try:
                                callback(features, pred)
                            except Exception as e:
                                logger.error(f"Threat callback error: {e}")
        
        # Log packet (if interesting)
        if features.has_payload or ml_prediction:
            self._log_packet(features, flow_data, ml_prediction)
    
    def _log_packet(
        self, 
        features: PacketFeatures, 
        flow_data: Dict,
        ml_prediction: Optional[MLPrediction] = None
    ):
        """Log packet to JSON file"""
        try:
            log_entry = {
                'packet': asdict(features),
                'flow': flow_data,
                'ml_prediction': asdict(ml_prediction) if ml_prediction else None
            }
            
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Logging error: {e}")
    
    def _process_dpdk_features(self, dpdk_features: DPDKPacketFeatures):
        """Process features extracted by DPDK processor"""
        self.stats['packets_captured'] += 1
        self.stats['packets_processed'] += 1
        
        # Convert DPDK features to dict for compatibility
        feature_dict = dpdk_features.to_dict()
        
        # Create PacketFeatures object for compatibility with existing code
        # (if needed for callbacks, otherwise use feature_dict directly)
        features = PacketFeatures(
            timestamp=dpdk_features.timestamp,
            src_ip=dpdk_features.src_ip,
            dst_ip=dpdk_features.dst_ip,
            src_port=dpdk_features.src_port,
            dst_port=dpdk_features.dst_port,
            protocol=dpdk_features.protocol,
            protocol_num=dpdk_features.protocol_num,
            size=dpdk_features.size,
            payload_size=dpdk_features.payload_size,
            flags=dpdk_features.tcp_flags,
            ttl=dpdk_features.ttl,
            tcp_flags=dpdk_features.tcp_flags,
            seq_num=dpdk_features.seq_num,
            ack_num=dpdk_features.ack_num,
            window_size=dpdk_features.window_size,
            app_proto=dpdk_features.app_proto,
            http_method=dpdk_features.http_method,
            http_uri=dpdk_features.http_uri,
            http_host=dpdk_features.http_host,
            dns_query=dpdk_features.dns_query,
            payload_entropy=dpdk_features.payload_entropy,
            payload_printable_ratio=dpdk_features.payload_printable_ratio,
            has_payload=dpdk_features.has_payload,
            raw_payload=dpdk_features.payload_hex
        )
        
        # Update flow tracker
        flow_data = self.flow_tracker.update_flow(features)
        
        # Run ML prediction if enabled
        ml_prediction = None
        if self.ml_enabled and self.model_manager:
            feature_dict.update(flow_data)  # Add flow features
            
            # Run all models
            predictions = self.model_manager.predict_all(feature_dict, data_type="network")
            
            if predictions:
                self.stats['ml_predictions'] += 1
                
                # Check for threats
                for name, pred in predictions.items():
                    if pred.is_threat:
                        self.stats['threats_detected'] += 1
                        ml_prediction = pred
                        
                        logger.warning(
                            f"[ALERT] ML THREAT: {pred.threat_type} | "
                            f"{features.src_ip}:{features.src_port} -> "
                            f"{features.dst_ip}:{features.dst_port} | "
                            f"Model: {name} | Confidence: {pred.confidence:.2%}"
                        )
                        
                        # Call threat callbacks
                        for callback in self.threat_callbacks:
                            try:
                                callback(features, pred)
                            except Exception as e:
                                logger.error(f"Threat callback error: {e}")
        
        # Log packet (if interesting or suspicious)
        if features.has_payload or ml_prediction or dpdk_features.suspicious:
            self._log_packet(features, flow_data, ml_prediction)
        
        # Log DPDK-flagged suspicious packets
        if dpdk_features.suspicious:
            logger.warning(
                f"[ALERT] DPDK SUSPICIOUS: {features.src_ip}:{features.src_port} -> "
                f"{features.dst_ip}:{features.dst_port} [{features.protocol}]"
            )
    
    def _cleanup_thread(self):
        """Background thread to cleanup expired flows"""
        while not self._stop_event.is_set():
            expired = self.flow_tracker.cleanup_expired()
            if expired > 0:
                logger.debug(f"Cleaned up {expired} expired flows")
            self._stop_event.wait(30)  # Run every 30 seconds
    
    def start(self):
        """Start packet capture (DPDK or Scapy mode)"""
        logger.info("Starting packet capture...")
        self._running = True
        self._stop_event.clear()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_thread, daemon=True)
        cleanup_thread.start()
        
        if self.dpdk_mode:
            # DPDK mode: consume features from DPDK processor
            logger.info("Starting DPDK feature consumer...")
            self.dpdk_consumer.start()
            
            try:
                for dpdk_features in self.dpdk_consumer.consume():
                    if self._stop_event.is_set():
                        break
                    self._process_dpdk_features(dpdk_features)
            
            except KeyboardInterrupt:
                pass
            except Exception as e:
                logger.error(f"DPDK consumer error: {e}")
                raise
            finally:
                self.dpdk_consumer.stop()
        
        else:
            # Legacy Scapy mode (DEPRECATED)
            if not getattr(self, 'scapy_available', False) and not SCAPY_AVAILABLE:
                logger.error("Cannot start packet capture - scapy not available")
                return
            
            try:
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda x: self._stop_event.is_set()
                )
            except PermissionError:
                logger.error("Permission denied. Run as root or with CAP_NET_RAW capability.")
                raise
            except Exception as e:
                logger.error(f"Capture error: {e}")
                raise
            finally:
                self._running = False
    
    def stop(self):
        """Stop packet capture"""
        if not getattr(self, '_stop_event', None):
            return
        logger.info("Stopping packet capture...")
        self._stop_event.set()
        self._running = False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics"""
        stats = self.stats.copy()
        if hasattr(self, 'flow_tracker'):
            stats['active_flows'] = len(self.flow_tracker.flows)
        return stats



def signal_handler(sig, frame):
    """Handle shutdown signals"""
    logger.info("Shutdown signal received")
    sys.exit(0)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Packet Inspector with ML (DPDK or Scapy mode)",
        epilog="Example: sudo python3 -m vajra.inspection.packet_inspector --dpdk --dpdk-json /tmp/dpdk_features.json"
    )
    
    # Capture mode
    parser.add_argument("--dpdk", action="store_true", 
                       help="Use DPDK mode (recommended for production)")
    parser.add_argument("--dpdk-json", default="/tmp/dpdk_features.json",
                       help="Path to DPDK feature JSON file (default: /tmp/dpdk_features.json)")
    
    # Scapy mode (legacy, deprecated)
    parser.add_argument("-i", "--interface", help="Network interface (Scapy mode only)")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter (Scapy mode only, default: ip)")
    
    # ML options
    parser.add_argument("--no-ml", action="store_true", help="Disable ML predictions")
    parser.add_argument("--load-model", help="Path to ML model to load")
    parser.add_argument("--model-name", default="custom", help="Name for loaded model")
    parser.add_argument("--model-type", default="custom", 
                       choices=['insider_threat', 'anomaly', 'ddos', 'custom'],
                       help="Type of model")
    
    args = parser.parse_args()
    
    # Warn if using deprecated Scapy mode
    if not args.dpdk:
        logger.warning("=" * 70)
        logger.warning("[WARN]  WARNING: Scapy mode is DEPRECATED")
        logger.warning("[WARN]  For production, use --dpdk for high-performance packet processing")
        logger.warning("=" * 70)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    # Load model if specified
    if args.load_model and ML_AVAILABLE:
        manager = get_model_manager()
        manager.load_model(args.model_name, args.load_model, args.model_type)
    
    # Create and start inspector
    inspector = PacketInspector(
        interface=args.interface,
        bpf_filter=args.filter,
        ml_enabled=not args.no_ml,
        dpdk_mode=args.dpdk,
        dpdk_json_path=args.dpdk_json
    )
    
    logger.info("=" * 50)
    logger.info(f"Packet Inspector Starting ({'DPDK' if args.dpdk else 'Scapy'})")
    logger.info("=" * 50)
    
    try:
        inspector.start()
    except KeyboardInterrupt:
        pass
    finally:
        inspector.stop()
        
        # Print statistics
        stats = inspector.get_stats()
        logger.info("\nCapture Statistics:")
        for key, value in stats.items():
            logger.info(f"  {key}: {value}")


if __name__ == "__main__":
    main()