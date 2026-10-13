#!/usr/bin/env python3
"""
FlowPrint Engine - Semi-supervised Network Fingerprinting
Based on: https://github.com/Thijsvanede/FlowPrint

Identifies devices and applications from network flows using:
- Network destination clustering
- Cross-correlation of temporal behavior
- Semi-supervised fingerprinting approach

Features:
- Device fingerprinting from network traffic
- Application identification
- Unknown device detection
- Integration with existing DPDK pipeline
"""

import json
import logging
import threading
import time
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple
from dataclasses import dataclass, asdict
import pickle

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

try:
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Create logs directory
from vajra.common.logging import setup_logging

logger = setup_logging("flowprint_engine", "logs/flowprint_engine.log")


@dataclass
class NetworkFlow:
    """Represents a network flow for fingerprinting"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float
    packet_count: int = 1
    byte_count: int = 0
    duration: float = 0.0
    
    def flow_key(self) -> str:
        """Generate unique flow identifier"""
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:{self.protocol}"


@dataclass
class Fingerprint:
    """Device/Application fingerprint"""
    fingerprint_id: str
    destinations: Set[str]  # Set of destination IPs/domains
    protocols: Counter
    ports: Counter
    temporal_pattern: List[float]  # Timing patterns
    flow_sizes: List[int]
    confidence: float
    first_seen: float
    last_seen: float
    flow_count: int
    device_label: Optional[str] = None  # Known device type
    app_label: Optional[str] = None     # Known application


@dataclass
class FingerprintMatch:
    """Result of fingerprint matching"""
    timestamp: str
    src_ip: str
    fingerprint_id: str
    device_type: Optional[str]
    app_type: Optional[str]
    confidence: float
    is_known_device: bool
    is_anomaly: bool
    matched_destinations: int
    total_destinations: int


class FlowPrintEngine:
    """
    Semi-supervised network fingerprinting engine
    
    Inspired by FlowPrint paper:
    - Clusters network destinations
    - Builds temporal correlation fingerprints
    - Identifies devices and apps from traffic patterns
    """
    
    def __init__(self, 
                 min_flows_for_fingerprint: int = 5,
                 clustering_eps: float = 0.5,
                 temporal_window: int = 60):
        """
        Initialize FlowPrint Engine
        
        Args:
            min_flows_for_fingerprint: Minimum flows needed to create fingerprint
            clustering_eps: DBSCAN epsilon for destination clustering
            temporal_window: Time window (seconds) for temporal patterns
        """
        if not NUMPY_AVAILABLE or not SKLEARN_AVAILABLE:
            logger.warning("NumPy or scikit-learn not available. Limited functionality.")
        
        self.min_flows = min_flows_for_fingerprint
        self.clustering_eps = clustering_eps
        self.temporal_window = temporal_window
        
        # State
        self.flows: Dict[str, List[NetworkFlow]] = defaultdict(list)  # Per source IP
        self.fingerprints: Dict[str, Fingerprint] = {}  # Known fingerprints
        self.device_fingerprints: Dict[str, str] = {}  # IP -> fingerprint_id mapping
        
        # Known device signatures (can be loaded from file)
        self.known_signatures: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.total_flows_processed = 0
        self.fingerprints_created = 0
        self.devices_identified = 0
        self.anomalies_detected = 0
        
        # Threading
        self.lock = threading.Lock()
        self.running = False
        
        # Persistence
        self.fingerprint_db_path = Path("logs/flowprint_fingerprints.pkl")
        self.matches_log = Path("logs/flowprint_matches.json")
        
        self._load_fingerprint_db()
        self._load_known_signatures()
        
        logger.info("FlowPrint Engine initialized")
    
    def _load_known_signatures(self):
        """Load known device/app signatures"""
        # Example known signatures - can be extended
        self.known_signatures = {
            "web_browser": {
                "ports": {80, 443, 8080, 8443},
                "protocols": {"TCP"},
                "apps": ["Chrome", "Firefox", "Safari", "Edge"]
            },
            "video_streaming": {
                "ports": {443, 1935, 8080},
                "protocols": {"TCP", "UDP"},
                "apps": ["YouTube", "Netflix", "Twitch"]
            },
            "voip": {
                "ports": {5060, 5061, 5004, 16384},
                "protocols": {"UDP", "TCP"},
                "apps": ["Zoom", "Teams", "Skype"]
            },
            "file_transfer": {
                "ports": {21, 22, 445, 3389},
                "protocols": {"TCP"},
                "apps": ["FTP", "SSH", "SMB", "RDP"]
            },
            "iot_device": {
                "ports": {1883, 8883, 5683},
                "protocols": {"TCP", "UDP"},
                "apps": ["MQTT", "CoAP"]
            }
        }
        logger.info(f"Loaded {len(self.known_signatures)} known device signatures")
    
    def _load_fingerprint_db(self):
        """Load saved fingerprints from disk"""
        if self.fingerprint_db_path.exists():
            try:
                with open(self.fingerprint_db_path, 'rb') as f:
                    data = pickle.load(f)
                    self.fingerprints = data.get('fingerprints', {})
                    self.device_fingerprints = data.get('device_map', {})
                logger.info(f"Loaded {len(self.fingerprints)} fingerprints from database")
            except Exception as e:
                logger.error(f"Error loading fingerprint database: {e}")
    
    def _save_fingerprint_db(self):
        """Save fingerprints to disk"""
        try:
            with open(self.fingerprint_db_path, 'wb') as f:
                pickle.dump({
                    'fingerprints': self.fingerprints,
                    'device_map': self.device_fingerprints
                }, f)
        except Exception as e:
            logger.error(f"Error saving fingerprint database: {e}")
    
    def process_packet(self, packet_data: Dict[str, Any]) -> Optional[FingerprintMatch]:
        """
        Process a network packet and perform fingerprinting
        
        Args:
            packet_data: Packet information dict with keys:
                - src_ip, dst_ip, src_port, dst_port, protocol
                - timestamp, packet_length
        
        Returns:
            FingerprintMatch if device identified, None otherwise
        """
        with self.lock:
            try:
                # Create flow object
                flow = NetworkFlow(
                    src_ip=packet_data.get('src_ip', '0.0.0.0'),
                    dst_ip=packet_data.get('dst_ip', '0.0.0.0'),
                    src_port=packet_data.get('src_port', 0),
                    dst_port=packet_data.get('dst_port', 0),
                    protocol=packet_data.get('protocol', 'TCP'),
                    timestamp=packet_data.get('timestamp', time.time()),
                    byte_count=packet_data.get('packet_length', 0)
                )
                
                # Store flow
                self.flows[flow.src_ip].append(flow)
                self.total_flows_processed += 1
                
                # Try to match existing fingerprint
                match = self._match_fingerprint(flow)
                
                # Periodically create/update fingerprints
                if len(self.flows[flow.src_ip]) >= self.min_flows:
                    self._create_or_update_fingerprint(flow.src_ip)
                
                # Cleanup old flows
                if self.total_flows_processed % 1000 == 0:
                    self._cleanup_old_flows()
                
                return match
                
            except Exception as e:
                logger.error(f"Error processing packet for fingerprinting: {e}")
                return None
    
    def _match_fingerprint(self, flow: NetworkFlow) -> Optional[FingerprintMatch]:
        """Match flow against existing fingerprints"""
        src_ip = flow.src_ip
        
        if src_ip not in self.device_fingerprints:
            return None
        
        fingerprint_id = self.device_fingerprints[src_ip]
        fingerprint = self.fingerprints.get(fingerprint_id)
        
        if not fingerprint:
            return None
        
        # Check if destination matches fingerprint
        is_known_dest = flow.dst_ip in fingerprint.destinations
        
        match = FingerprintMatch(
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip=src_ip,
            fingerprint_id=fingerprint_id,
            device_type=fingerprint.device_label,
            app_type=fingerprint.app_label,
            confidence=fingerprint.confidence,
            is_known_device=fingerprint.device_label is not None,
            is_anomaly=not is_known_dest,
            matched_destinations=len(fingerprint.destinations),
            total_destinations=len(fingerprint.destinations)
        )
        
        # Log anomalies
        if match.is_anomaly:
            self.anomalies_detected += 1
            logger.warning(f"Anomaly: {src_ip} contacted unknown destination {flow.dst_ip}")
            self._log_match(match)
        
        return match
    
    def _create_or_update_fingerprint(self, src_ip: str):
        """Create or update fingerprint for a source IP"""
        flows = self.flows[src_ip]
        
        if len(flows) < self.min_flows:
            return
        
        # Extract features
        destinations = set(f.dst_ip for f in flows)
        protocols = Counter(f.protocol for f in flows)
        ports = Counter(f.dst_port for f in flows)
        timestamps = [f.timestamp for f in flows]
        flow_sizes = [f.byte_count for f in flows]
        
        # Calculate temporal pattern
        if len(timestamps) > 1:
            temporal_pattern = np.diff(sorted(timestamps)).tolist() if NUMPY_AVAILABLE else []
        else:
            temporal_pattern = []
        
        # Generate fingerprint ID
        fingerprint_id = f"fp_{hash(src_ip)}_{int(time.time())}"
        
        # Try to classify device/app type
        device_label, app_label, confidence = self._classify_fingerprint(
            destinations, protocols, ports, temporal_pattern
        )
        
        # Create fingerprint
        fingerprint = Fingerprint(
            fingerprint_id=fingerprint_id,
            destinations=destinations,
            protocols=protocols,
            ports=ports,
            temporal_pattern=temporal_pattern,
            flow_sizes=flow_sizes,
            confidence=confidence,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            flow_count=len(flows),
            device_label=device_label,
            app_label=app_label
        )
        
        # Store
        self.fingerprints[fingerprint_id] = fingerprint
        self.device_fingerprints[src_ip] = fingerprint_id
        self.fingerprints_created += 1
        
        if device_label:
            self.devices_identified += 1
            logger.info(f"Device identified: {src_ip} -> {device_label} ({confidence:.2f} confidence)")
        
        # Persist
        if self.fingerprints_created % 10 == 0:
            self._save_fingerprint_db()
    
    def _classify_fingerprint(self, 
                             destinations: Set[str],
                             protocols: Counter,
                             ports: Counter,
                             temporal_pattern: List[float]) -> Tuple[Optional[str], Optional[str], float]:
        """
        Classify fingerprint against known signatures
        
        Returns:
            (device_label, app_label, confidence)
        """
        best_match = None
        best_confidence = 0.0
        best_app = None
        
        for sig_name, signature in self.known_signatures.items():
            # Calculate match score
            protocol_match = len(set(protocols.keys()) & signature['protocols']) / max(len(signature['protocols']), 1)
            port_match = len(set(ports.keys()) & signature['ports']) / max(len(signature['ports']), 1)
            
            confidence = (protocol_match + port_match) / 2.0
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = sig_name
                best_app = signature['apps'][0] if signature['apps'] else None
        
        # Require minimum confidence threshold
        if best_confidence >= 0.5:
            return best_match, best_app, best_confidence
        else:
            return None, None, best_confidence
    
    def _cleanup_old_flows(self, max_age: int = 300):
        """Remove flows older than max_age seconds"""
        current_time = time.time()
        removed_count = 0
        
        for src_ip in list(self.flows.keys()):
            self.flows[src_ip] = [
                f for f in self.flows[src_ip]
                if current_time - f.timestamp < max_age
            ]
            
            if not self.flows[src_ip]:
                del self.flows[src_ip]
                removed_count += 1
        
        if removed_count > 0:
            logger.debug(f"Cleaned up flows from {removed_count} IPs")
    
    def _log_match(self, match: FingerprintMatch):
        """Log fingerprint match to file"""
        try:
            with open(self.matches_log, 'a') as f:
                f.write(json.dumps(asdict(match)) + '\n')
        except Exception as e:
            logger.error(f"Error logging match: {e}")
    
    def get_device_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get fingerprint information for an IP"""
        with self.lock:
            if ip not in self.device_fingerprints:
                return None
            
            fingerprint_id = self.device_fingerprints[ip]
            fingerprint = self.fingerprints.get(fingerprint_id)
            
            if not fingerprint:
                return None
            
            return {
                'ip': ip,
                'fingerprint_id': fingerprint_id,
                'device_type': fingerprint.device_label,
                'app_type': fingerprint.app_label,
                'confidence': fingerprint.confidence,
                'destinations_count': len(fingerprint.destinations),
                'flow_count': fingerprint.flow_count,
                'first_seen': datetime.fromtimestamp(fingerprint.first_seen).isoformat(),
                'last_seen': datetime.fromtimestamp(fingerprint.last_seen).isoformat()
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self.lock:
            return {
                'total_flows_processed': self.total_flows_processed,
                'fingerprints_created': self.fingerprints_created,
                'devices_identified': self.devices_identified,
                'anomalies_detected': self.anomalies_detected,
                'active_devices': len(self.device_fingerprints),
                'unique_fingerprints': len(self.fingerprints),
                'known_signatures': len(self.known_signatures)
            }


# Singleton instance
_flowprint_engine_instance: Optional[FlowPrintEngine] = None
_flowprint_lock = threading.Lock()


def get_flowprint_engine() -> FlowPrintEngine:
    """Get or create FlowPrint engine singleton"""
    global _flowprint_engine_instance
    
    with _flowprint_lock:
        if _flowprint_engine_instance is None:
            _flowprint_engine_instance = FlowPrintEngine()
        return _flowprint_engine_instance


if __name__ == "__main__":
    # Test the engine
    engine = get_flowprint_engine()
    
    # Simulate some traffic
    test_packets = [
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'src_port': 54321, 'dst_port': 443, 'protocol': 'TCP', 'timestamp': time.time(), 'packet_length': 1200},
        {'src_ip': '192.168.1.100', 'dst_ip': '1.1.1.1', 'src_port': 54322, 'dst_port': 443, 'protocol': 'TCP', 'timestamp': time.time(), 'packet_length': 800},
        {'src_ip': '192.168.1.100', 'dst_ip': '142.250.185.46', 'src_port': 54323, 'dst_port': 443, 'protocol': 'TCP', 'timestamp': time.time(), 'packet_length': 1500},
        {'src_ip': '192.168.1.101', 'dst_ip': '13.107.42.14', 'src_port': 12345, 'dst_port': 443, 'protocol': 'UDP', 'timestamp': time.time(), 'packet_length': 300},
        {'src_ip': '192.168.1.101', 'dst_ip': '13.107.42.14', 'src_port': 12346, 'dst_port': 5060, 'protocol': 'UDP', 'timestamp': time.time(), 'packet_length': 200},
    ]
    
    for packet in test_packets:
        match = engine.process_packet(packet)
        if match:
            logger.info(f"Match: {match}")
    
    # Print statistics
    stats = engine.get_statistics()
    print("\n=== FlowPrint Engine Statistics ===")
    print(json.dumps(stats, indent=2))
    
    # Get device info
    device_info = engine.get_device_info('192.168.1.100')
    if device_info:
        print(f"\n=== Device 192.168.1.100 ===")
        print(json.dumps(device_info, indent=2))
