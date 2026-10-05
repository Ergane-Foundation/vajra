#!/usr/bin/env python3
"""
Vajra Load Generator

Simulates various types of network traffic to test firewall performance:
- HTTP/HTTPS traffic
- DNS queries
- TCP connections
- UDP packets
- Attack patterns
- Concurrent connections

Measures:
- Throughput (packets/sec, bytes/sec)
- Latency (response time)
- Connection success rate
- Packet loss
"""

import os
import sys
import time
import socket
import threading
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import json

# Try to import optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests not available. HTTP load testing will be limited.")

@dataclass
class LoadMetrics:
    """Metrics for a load test"""
    timestamp: str
    traffic_type: str
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    requests_per_second: float
    bytes_sent: int
    bytes_received: int
    throughput_mbps: float
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    success_rate: float
    concurrent_connections: int
    errors: Dict[str, int]


class TrafficGenerator:
    """Base class for traffic generators"""
    
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.results = {
            'requests': 0,
            'successes': 0,
            'failures': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'latencies': [],
            'errors': defaultdict(int),
            'start_time': None,
            'end_time': None
        }
        self.lock = threading.Lock()
    
    def record_success(self, latency_ms: float, bytes_sent: int, bytes_received: int):
        """Record a successful request"""
        with self.lock:
            self.results['requests'] += 1
            self.results['successes'] += 1
            self.results['latencies'].append(latency_ms)
            self.results['bytes_sent'] += bytes_sent
            self.results['bytes_received'] += bytes_received
    
    def record_failure(self, error_type: str):
        """Record a failed request"""
        with self.lock:
            self.results['requests'] += 1
            self.results['failures'] += 1
            self.results['errors'][error_type] += 1
    
    def get_metrics(self, traffic_type: str, concurrent: int) -> LoadMetrics:
        """Calculate and return metrics"""
        with self.lock:
            results = self.results.copy()
        
        duration = (results['end_time'] - results['start_time']) if results['start_time'] and results['end_time'] else 0
        
        latencies = sorted(results['latencies'])
        n = len(latencies)
        
        return LoadMetrics(
            timestamp=datetime.now().isoformat(),
            traffic_type=traffic_type,
            duration_seconds=duration,
            total_requests=results['requests'],
            successful_requests=results['successes'],
            failed_requests=results['failures'],
            requests_per_second=results['requests'] / duration if duration > 0 else 0,
            bytes_sent=results['bytes_sent'],
            bytes_received=results['bytes_received'],
            throughput_mbps=(results['bytes_sent'] + results['bytes_received']) / duration / (1024 * 1024) * 8 if duration > 0 else 0,
            avg_latency_ms=sum(latencies) / n if n > 0 else 0,
            min_latency_ms=latencies[0] if n > 0 else 0,
            max_latency_ms=latencies[-1] if n > 0 else 0,
            p50_latency_ms=latencies[n // 2] if n > 0 else 0,
            p95_latency_ms=latencies[int(n * 0.95)] if n > 0 else 0,
            p99_latency_ms=latencies[int(n * 0.99)] if n > 0 else 0,
            success_rate=results['successes'] / results['requests'] if results['requests'] > 0 else 0,
            concurrent_connections=concurrent,
            errors=dict(results['errors'])
        )


class HTTPLoadGenerator(TrafficGenerator):
    """Generate HTTP traffic"""
    
    def __init__(self, target_ip: str, target_port: int = 8080):
        super().__init__(target_ip, target_port)
        self.base_url = f"http://{target_ip}:{target_port}"
    
    def send_request(self):
        """Send a single HTTP request"""
        start = time.time()
        
        try:
            if HAS_REQUESTS:
                response = requests.get(self.base_url, timeout=5)
                latency = (time.time() - start) * 1000
                self.record_success(
                    latency,
                    len(response.request.body or ''),
                    len(response.content)
                )
            else:
                # Fallback: raw socket HTTP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target_ip, self.target_port))
                
                request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(4096)
                latency = (time.time() - start) * 1000
                
                sock.close()
                
                self.record_success(latency, len(request), len(response))
                
        except requests.Timeout:
            self.record_failure("timeout")
        except requests.ConnectionError:
            self.record_failure("connection_error")
        except socket.timeout:
            self.record_failure("timeout")
        except socket.error as e:
            self.record_failure(f"socket_error_{type(e).__name__}")
        except Exception as e:
            self.record_failure(f"error_{type(e).__name__}")
    
    def generate_load(self, duration: int, rate: int, concurrent: int = 10):
        """Generate HTTP load"""
        print(f"[HTTPLoad] Starting: {rate} req/s for {duration}s with {concurrent} threads")
        
        self.running = True
        self.results['start_time'] = time.time()
        
        threads = []
        requests_per_thread = rate // concurrent
        interval = 1.0 / requests_per_thread if requests_per_thread > 0 else 0.1
        
        def worker():
            end_time = time.time() + duration
            while time.time() < end_time and self.running:
                self.send_request()
                time.sleep(interval)
        
        # Start worker threads
        for _ in range(concurrent):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for completion
        for t in threads:
            t.join()
        
        self.results['end_time'] = time.time()
        self.running = False
        
        return self.get_metrics("HTTP", concurrent)


class TCPConnectionGenerator(TrafficGenerator):
    """Generate TCP connections"""
    
    def __init__(self, target_ip: str, target_port: int = 8080):
        super().__init__(target_ip, target_port)
    
    def create_connection(self):
        """Create a TCP connection"""
        start = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            
            # Send some data
            data = b"TEST" * 256  # 1KB
            sock.send(data)
            
            # Try to receive
            try:
                response = sock.recv(4096)
            except:
                response = b""
            
            latency = (time.time() - start) * 1000
            sock.close()
            
            self.record_success(latency, len(data), len(response))
            
        except socket.timeout:
            self.record_failure("timeout")
        except socket.error as e:
            self.record_failure(f"connection_error")
        except Exception as e:
            self.record_failure(f"error_{type(e).__name__}")
    
    def generate_load(self, duration: int, rate: int, concurrent: int = 50):
        """Generate TCP connection load"""
        print(f"[TCPLoad] Starting: {rate} conn/s for {duration}s with {concurrent} threads")
        
        self.running = True
        self.results['start_time'] = time.time()
        
        threads = []
        connections_per_thread = rate // concurrent
        interval = 1.0 / connections_per_thread if connections_per_thread > 0 else 0.1
        
        def worker():
            end_time = time.time() + duration
            while time.time() < end_time and self.running:
                self.create_connection()
                time.sleep(interval)
        
        for _ in range(concurrent):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        self.results['end_time'] = time.time()
        self.running = False
        
        return self.get_metrics("TCP", concurrent)


class UDPPacketGenerator(TrafficGenerator):
    """Generate UDP packets"""
    
    def __init__(self, target_ip: str, target_port: int = 53):
        super().__init__(target_ip, target_port)
    
    def send_packet(self, size: int = 512):
        """Send a UDP packet"""
        start = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Create random payload
            payload = os.urandom(size)
            sock.sendto(payload, (self.target_ip, self.target_port))
            
            # Try to receive (may timeout for UDP)
            try:
                response, _ = sock.recvfrom(4096)
            except socket.timeout:
                response = b""
            
            latency = (time.time() - start) * 1000
            sock.close()
            
            self.record_success(latency, len(payload), len(response))
            
        except Exception as e:
            self.record_failure(f"error_{type(e).__name__}")
    
    def generate_load(self, duration: int, rate: int, packet_size: int = 512, concurrent: int = 20):
        """Generate UDP packet load"""
        print(f"[UDPLoad] Starting: {rate} pkt/s for {duration}s, size={packet_size}B")
        
        self.running = True
        self.results['start_time'] = time.time()
        
        threads = []
        packets_per_thread = rate // concurrent
        interval = 1.0 / packets_per_thread if packets_per_thread > 0 else 0.01
        
        def worker():
            end_time = time.time() + duration
            while time.time() < end_time and self.running:
                self.send_packet(packet_size)
                time.sleep(interval)
        
        for _ in range(concurrent):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        self.results['end_time'] = time.time()
        self.running = False
        
        return self.get_metrics("UDP", concurrent)


class AttackSimulator(TrafficGenerator):
    """Simulate attack patterns"""
    
    def __init__(self, target_ip: str, target_port: int = 8080):
        super().__init__(target_ip, target_port)
    
    def syn_flood(self):
        """Simulate SYN flood (connection attempts)"""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((self.target_ip, self.target_port))
            # Don't complete handshake - just close
            latency = (time.time() - start) * 1000
            sock.close()
            self.record_success(latency, 0, 0)
        except:
            self.record_failure("syn_failed")
    
    def slowloris(self):
        """Simulate slowloris attack (slow HTTP)"""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            
            # Send incomplete HTTP request
            sock.send(b"GET / HTTP/1.1\r\n")
            time.sleep(0.5)
            sock.send(b"Host: " + self.target_ip.encode() + b"\r\n")
            
            latency = (time.time() - start) * 1000
            sock.close()
            self.record_success(latency, 50, 0)
        except:
            self.record_failure("slowloris_failed")
    
    def generate_load(self, duration: int, rate: int, attack_type: str = "syn", concurrent: int = 100):
        """Generate attack traffic"""
        print(f"[Attack] Simulating {attack_type} attack: {rate}/s for {duration}s")
        
        self.running = True
        self.results['start_time'] = time.time()
        
        attack_func = self.syn_flood if attack_type == "syn" else self.slowloris
        
        threads = []
        attacks_per_thread = rate // concurrent
        interval = 1.0 / attacks_per_thread if attacks_per_thread > 0 else 0.01
        
        def worker():
            end_time = time.time() + duration
            while time.time() < end_time and self.running:
                attack_func()
                time.sleep(interval)
        
        for _ in range(concurrent):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        self.results['end_time'] = time.time()
        self.running = False
        
        return self.get_metrics(f"Attack_{attack_type}", concurrent)


def main():
    """Test the load generators"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Vajra Load Generator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP")
    parser.add_argument("--port", type=int, default=8080, help="Target port")
    parser.add_argument("--type", choices=["http", "tcp", "udp", "attack"], default="http")
    parser.add_argument("--duration", type=int, default=30, help="Test duration (seconds)")
    parser.add_argument("--rate", type=int, default=100, help="Requests/connections per second")
    parser.add_argument("--concurrent", type=int, default=10, help="Concurrent threads")
    
    args = parser.parse_args()
    
    print(f"Load Test: {args.type.upper()}")
    print(f"Target: {args.target}:{args.port}")
    print(f"Duration: {args.duration}s, Rate: {args.rate}/s, Concurrent: {args.concurrent}")
    print("-" * 70)
    
    if args.type == "http":
        gen = HTTPLoadGenerator(args.target, args.port)
        metrics = gen.generate_load(args.duration, args.rate, args.concurrent)
    elif args.type == "tcp":
        gen = TCPConnectionGenerator(args.target, args.port)
        metrics = gen.generate_load(args.duration, args.rate, args.concurrent)
    elif args.type == "udp":
        gen = UDPPacketGenerator(args.target, args.port)
        metrics = gen.generate_load(args.duration, args.rate, 512, args.concurrent)
    elif args.type == "attack":
        gen = AttackSimulator(args.target, args.port)
        metrics = gen.generate_load(args.duration, args.rate, "syn", args.concurrent)
    
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total Requests: {metrics.total_requests}")
    print(f"Successful: {metrics.successful_requests} ({metrics.success_rate*100:.1f}%)")
    print(f"Failed: {metrics.failed_requests}")
    print(f"Throughput: {metrics.requests_per_second:.1f} req/s")
    print(f"Bandwidth: {metrics.throughput_mbps:.2f} Mbps")
    print(f"\nLatency:")
    print(f"  Min: {metrics.min_latency_ms:.2f}ms")
    print(f"  Avg: {metrics.avg_latency_ms:.2f}ms")
    print(f"  Max: {metrics.max_latency_ms:.2f}ms")
    print(f"  P95: {metrics.p95_latency_ms:.2f}ms")
    print(f"  P99: {metrics.p99_latency_ms:.2f}ms")
    
    if metrics.errors:
        print(f"\nErrors:")
        for error, count in metrics.errors.items():
            print(f"  {error}: {count}")


if __name__ == "__main__":
    main()
