#!/usr/bin/env python3
"""
Packet Inspector - Network Packet Analysis (Solo, Not Yet Integrated)

Captures and inspects network packets for threat detection.
Uses Scapy for deep packet inspection and feature extraction.
"""

import json
import time
import logging
import signal
from datetime import datetime
from typing import Dict, Any, Optional
from collections import defaultdict

# Scapy imports (optional for first prototype)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("packet_inspector")


class PacketInspector:
    """Network packet inspection engine"""

    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.running = False
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0
        }
        logger.info(f"Packet Inspector initialized on interface: {interface}")

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of payload data"""
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

    def extract_features(self, packet) -> Optional[Dict[str, Any]]:
        """Extract features from a network packet"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            features = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'protocol': 'unknown',
                'src_ip': '',
                'dst_ip': '',
                'src_port': 0,
                'dst_port': 0,
                'flags': '',
                'payload_size': 0,
                'suspicious': False
            }
            
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                features['src_ip'] = ip.src
                features['dst_ip'] = ip.dst
                features['ttl'] = ip.ttl
            
            # TCP layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                features['protocol'] = 'TCP'
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['flags'] = str(tcp.flags)
                self.stats['tcp_packets'] += 1
                
                # Check for suspicious patterns
                if tcp.dport in [22, 23, 3389]:  # SSH, Telnet, RDP
                    features['suspicious'] = True
                    self.stats['suspicious_packets'] += 1
            
            # UDP layer
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                features['protocol'] = 'UDP'
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
                self.stats['udp_packets'] += 1
            
            # ICMP layer
            elif packet.haslayer(ICMP):
                features['protocol'] = 'ICMP'
                self.stats['icmp_packets'] += 1
            
            # Payload analysis
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                features['payload_size'] = len(payload)
                features['entropy'] = self._calculate_entropy(payload)
                
                # High entropy might indicate encrypted/obfuscated data
                if features['entropy'] > 7.0:
                    features['suspicious'] = True
                    self.stats['suspicious_packets'] += 1
            
            self.stats['total_packets'] += 1
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None

    def packet_callback(self, packet):
        """Callback for each captured packet"""
        features = self.extract_features(packet)
        
        if features:
            # Log suspicious packets
            if features['suspicious']:
                logger.warning(f"🚨 Suspicious packet: {features['src_ip']}:{features['src_port']} "
                             f"-> {features['dst_ip']}:{features['dst_port']} "
                             f"[{features['protocol']}]")
            
            # Print packet summary every 100 packets
            if self.stats['total_packets'] % 100 == 0:
                self.print_stats()

    def print_stats(self):
        """Print current statistics"""
        logger.info(f"📊 Stats: Total={self.stats['total_packets']}, "
                   f"TCP={self.stats['tcp_packets']}, "
                   f"UDP={self.stats['udp_packets']}, "
                   f"ICMP={self.stats['icmp_packets']}, "
                   f"Suspicious={self.stats['suspicious_packets']}")

    def start_capture(self, count: int = 0, timeout: int = None):
        """Start packet capture on interface
        
        Args:
            count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds (None = no timeout)
        """
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy not available")
            return
        
        logger.info(f"Starting packet capture on {self.interface}...")
        logger.info("Press Ctrl+C to stop")
        
        self.running = True
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                count=count,
                timeout=timeout
            )
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.stop_capture()

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        logger.info("Packet capture stopped")
        self.print_stats()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Packet Inspector - Network packet analysis')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = infinite)')
    parser.add_argument('-t', '--timeout', type=int, default=None, help='Capture timeout in seconds')
    
    args = parser.parse_args()
    
    inspector = PacketInspector(interface=args.interface)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logger.info("\nStopping capture...")
        inspector.stop_capture()
        exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    inspector.start_capture(count=args.count, timeout=args.timeout)


if __name__ == "__main__":
    main()
