#!/usr/bin/env python3
"""
Firewall Performance Benchmarker
Measures Detection Latency and Inspection Throughput for the Packet Inspector.
"""

import time
import socket
import json
import threading
import statistics
import random
import string
import os
import subprocess
from datetime import datetime
from pathlib import Path

# Configuration
TARGET_IP = "8.8.8.8"    # External IP to generate traffic (Google DNS)
TARGET_PORT = 53         # DNS port
LOG_FILE = "logs/packet_inspector.json"
TEST_PAYLOAD_SIGNATURE = "BENCHMARK_TEST_SIG"

class FirewallBenchmark:
    def __init__(self):
        self.results = []
        self.running = False
        self.log_file = Path(LOG_FILE)
        # Ensure log dir exists
        self.log_file.parent.mkdir(exist_ok=True, parents=True)

    def generate_random_id(self, length=8):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

    def tail_logs(self, stop_event):
        """Monitors logs for the specific benchmark signature"""
        # Seek to end of file
        if not self.log_file.exists():
            print(f"Waiting for {self.log_file} to be created...")
            while not self.log_file.exists() and not stop_event.is_set():
                time.sleep(0.1)
        
        if stop_event.is_set(): return

        with open(self.log_file, 'r') as f:
            f.seek(0, os.SEEK_END)
            while not stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.01) # Low latency polling
                    continue
                
                try:
                    data = json.loads(line)
                    # Check if this is our benchmark packet
                    payload = data.get('packet', {}).get('raw_payload', '')
                    
                    # Convert hex payload back to string to check for signature
                    try:
                        decoded = bytes.fromhex(payload).decode('utf-8', errors='ignore')
                        if TEST_PAYLOAD_SIGNATURE in decoded:
                            # Extract ID: "BENCHMARK_TEST_SIG:<ID>"
                            parts = decoded.split(':')
                            if len(parts) > 1:
                                unique_id = parts[1]
                                detection_time = time.time()
                                self.results.append({
                                    'id': unique_id,
                                    'detected_at': detection_time
                                })
                    except:
                        pass
                except json.JSONDecodeError:
                    pass

    def measure_latency(self, iterations=100, interval=0.1):
        """Measures packet processing latency by monitoring log file growth"""
        print(f"\n[Latency Test] Monitoring packet capture for {iterations} samples...")
        print("Generating real network traffic to measure detection latency...")
        
        latencies = []
        
        try:
            for i in range(iterations):
                # Generate actual network traffic (ICMP ping)
                import subprocess
                
                t_start = time.time()
                
                # Send ICMP packet (will be captured by packet inspector)
                subprocess.run(
                    ['ping', '-c', '1', '-W', '1', '8.8.8.8'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                
                # Small delay to allow packet to be processed
                time.sleep(0.05)
                
                # Check if log file was updated recently
                if self.log_file.exists():
                    mod_time = self.log_file.stat().st_mtime
                    detection_latency = (mod_time - t_start) * 1000  # ms
                    
                    if detection_latency > 0 and detection_latency < 500:  # Sanity check
                        latencies.append(detection_latency)
                
                time.sleep(interval)
                
                if (i + 1) % 10 == 0:
                    print(f"   Progress: {i+1}/{iterations} packets")
            
            if not latencies:
                print("[FAIL] No packet processing detected!")
                print("   Ensure the packet inspector is running with: sudo python3 -m vajra.inspection.packet_inspector -i en0")
                return

            print(f"\nLatency Results (Detection Time):")
            print(f"   Samples: {len(latencies)}/{iterations} detected")
            print(f"   Min: {min(latencies):.2f} ms")
            print(f"   Max: {max(latencies):.2f} ms")
            print(f"   Avg: {statistics.mean(latencies):.2f} ms")
            print(f"   Median: {statistics.median(latencies):.2f} ms")
            if len(latencies) > 1:
                print(f"   Jitter (Stdev): {statistics.stdev(latencies):.2f} ms")

        except KeyboardInterrupt:
            print("\n[WARN]  Test interrupted")

    def measure_throughput(self, duration=10, packet_size=1024):
        """Floods packets to test inspection capacity"""
        print(f"\n[Throughput Test] Flooding {packet_size}B packets for {duration}s...")
        print("Note: This tests the Python ingestion rate. For C++ DPDK limits, use external tools.")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(packet_size)
        
        start_time = time.time()
        packets_sent = 0
        bytes_sent = 0
        
        try:
            while time.time() - start_time < duration:
                # Send burst of 100 to reduce system call overhead
                for _ in range(100):
                    sock.sendto(payload, (TARGET_IP, TARGET_PORT))
                    packets_sent += 1
                    bytes_sent += packet_size
        except KeyboardInterrupt:
            pass
            
        total_time = time.time() - start_time
        pps = packets_sent / total_time
        mbps = (bytes_sent * 8) / (1024 * 1024) / total_time
        
        print(f"\nTraffic Generation Results:")
        print(f"   Duration: {total_time:.2f} s")
        print(f"   Packets Sent: {packets_sent}")
        print(f"   Rate: {pps:.2f} pps")
        print(f"   Bandwidth: {mbps:.2f} Mbps")
        print("\nCheck the Packet Inspector's 'Packets Processed' stat to calculate drop rate.")

if __name__ == "__main__":
    print("=== Firewall Benchmarker ===")
    print("Ensure 'python3 -m vajra.inspection.packet_inspector' (or DPDK) is running in another terminal.")
    
    bm = FirewallBenchmark()
    
    # 1. Latency Test
    bm.measure_latency(iterations=50)
    
    # 2. Throughput Trigger
    # bm.measure_throughput() # Uncomment to run flood test
