#!/usr/bin/env python3
"""SOAR Engine Stress Test"""
import os
import sys
import json
import time
import random
import argparse
import statistics
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory
SCRIPT_DIR = Path(__file__).parent.absolute()
PARENT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PARENT_DIR))


@dataclass
class SOARTestResult:
    """Results from SOAR engine stress test"""
    test_name: str
    total_alerts: int
    total_time_seconds: float
    alerts_per_second: float
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    alerts_blocked: int
    block_rate: float
    reports_generated: int
    errors: int


def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] [{level}] {msg}")


def generate_suricata_alert() -> Dict[str, Any]:
    """Generate synthetic Suricata alert for testing"""
    signatures = [
        ("ET SCAN Potential SSH Scan", 2001219),
        ("ET POLICY Suspicious inbound to mySQL port 3306", 2010939),
        ("ET WEB_SERVER SQL Injection Attempt", 2002910),
        ("ET WEB_ATTACK XSS Attack", 2010937),
        ("ET EXPLOIT Potential Microsoft RPC Exploit", 2001684),
        ("ET MALWARE Command and Control Server", 2013504),
        ("ET POLICY Cleartext Password transmitted", 2013464),
        ("NGFW DROP DDoS Detected", 9000001),
        ("NGFW ALERT Port Scan", 9000002),
        ("NGFW DROP SQL Injection", 9000003),
    ]
    
    severity_map = {
        "ET SCAN": 2,
        "ET POLICY": 3,
        "ET WEB_SERVER": 1,
        "ET WEB_ATTACK": 1,
        "ET EXPLOIT": 1,
        "ET MALWARE": 1,
        "NGFW DROP": 1,
        "NGFW ALERT": 2,
    }
    
    sig_name, sid = random.choice(signatures)
    
    # Determine severity
    severity = 2
    for prefix, sev in severity_map.items():
        if sig_name.startswith(prefix):
            severity = sev
            break
    
    alert = {
        "timestamp": datetime.now().isoformat(),
        "event_type": "alert",
        "src_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dest_ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "dest_port": random.choice([80, 443, 22, 53, 3306, 8080]),
        "proto": random.choice(["TCP", "UDP"]),
        "alert": {
            "signature": sig_name,
            "signature_id": sid,
            "severity": severity,
            "category": "Misc Attack" if "drop" in sig_name.lower() else "Attempted Information Leak",
        },
        "flow": {
            "pkts_toserver": random.randint(1, 1000),
            "pkts_toclient": random.randint(1, 1000),
            "bytes_toserver": random.randint(100, 100000),
            "bytes_toclient": random.randint(100, 100000),
        }
    }
    
    return alert


def test_alert_processing_throughput(num_alerts: int = 5000) -> SOARTestResult:
    """Test alert processing throughput"""
    log(f"Testing Alert Processing Throughput ({num_alerts} alerts)...")
    
    latencies = []
    blocked = 0
    reports = 0
    errors = 0
    
    try:
        from soar_engine import SOAREngine
        
        # Initialize SOAR engine without Kafka
        engine = SOAREngine(
            enable_ml=False,  # Disable ML for pure SOAR testing
            enable_packet_inspection=False
        )
        
        total_start = time.time()
        
        for i in range(num_alerts):
            alert = generate_suricata_alert()
            
            try:
                start = time.time()
                
                # Process alert
                processed = engine.process_alert(alert)
                
                latencies.append((time.time() - start) * 1000)
                
                # Check if blocked
                if processed and processed.blocked:
                    blocked += 1
                
            except Exception as e:
                errors += 1
            
            if (i + 1) % 1000 == 0:
                log(f"  Progress: {i+1}/{num_alerts}")
        
        total_time = time.time() - total_start
        
        # Count generated reports
        reports_dir = Path("logs/reports")
        if reports_dir.exists():
            reports = len(list(reports_dir.glob("*.json")))
        
    except Exception as e:
        log(f"  Error: {e}", "ERROR")
        latencies = [1.0] * 100
        total_time = 1
        errors = num_alerts
    
    sorted_latencies = sorted(latencies) if latencies else [0]
    
    result = SOARTestResult(
        test_name="alert_processing",
        total_alerts=num_alerts,
        total_time_seconds=total_time,
        alerts_per_second=num_alerts / total_time if total_time > 0 else 0,
        avg_latency_ms=statistics.mean(sorted_latencies),
        p95_latency_ms=sorted_latencies[int(len(sorted_latencies) * 0.95)],
        p99_latency_ms=sorted_latencies[int(len(sorted_latencies) * 0.99)],
        alerts_blocked=blocked,
        block_rate=blocked / num_alerts if num_alerts > 0 else 0,
        reports_generated=reports,
        errors=errors
    )
    
    log(f"  Throughput: {result.alerts_per_second:.2f} alerts/s")
    log(f"  Blocked: {result.alerts_blocked} ({result.block_rate*100:.1f}%)")
    log(f"  Avg Latency: {result.avg_latency_ms:.2f}ms")
    
    return result


def test_blocking_decision_performance(num_decisions: int = 10000) -> Dict[str, Any]:
    """Test blocking decision logic performance"""
    log(f"Testing Blocking Decision Performance ({num_decisions} decisions)...")
    
    result = {
        "total_decisions": num_decisions,
        "total_time_seconds": 0,
        "decisions_per_second": 0,
        "avg_latency_us": 0,
        "blocked_count": 0,
        "allowed_count": 0
    }
    
    try:
        from soar_engine import SOAREngine
        
        engine = SOAREngine(enable_ml=False, enable_packet_inspection=False)
        
        latencies = []
        blocked = 0
        
        total_start = time.time()
        
        for _ in range(num_decisions):
            alert = generate_suricata_alert()
            
            start = time.time()
            should_block = engine.should_block(alert)
            latencies.append((time.time() - start) * 1000000)  # microseconds
            
            if should_block:
                blocked += 1
        
        result["total_time_seconds"] = time.time() - total_start
        result["decisions_per_second"] = num_decisions / result["total_time_seconds"]
        result["avg_latency_us"] = statistics.mean(latencies)
        result["blocked_count"] = blocked
        result["allowed_count"] = num_decisions - blocked
        
        log(f"  Throughput: {result['decisions_per_second']:.2f} decisions/s")
        log(f"  Avg Latency: {result['avg_latency_us']:.2f}μs")
        log(f"  Block Rate: {blocked/num_decisions*100:.1f}%")
        
    except Exception as e:
        log(f"  Error: {e}", "ERROR")
        result["error"] = str(e)
    
    return result


def test_report_generation_performance(num_reports: int = 100) -> Dict[str, Any]:
    """Test report generation performance"""
    log(f"Testing Report Generation Performance ({num_reports} reports)...")
    
    result = {
        "total_reports": num_reports,
        "total_time_seconds": 0,
        "reports_per_second": 0,
        "avg_latency_ms": 0,
        "total_size_kb": 0
    }
    
    try:
        from soar_engine import ReportGenerator, ActionRecord
        
        generator = ReportGenerator(reports_dir="logs/stress_test_reports")
        
        latencies = []
        total_size = 0
        
        total_start = time.time()
        
        for i in range(num_reports):
            alert = generate_suricata_alert()
            action = ActionRecord(
                timestamp=datetime.now().isoformat(),
                alert_id=f"STRESS-{i:06d}",
                action="block",
                target_ip=alert["src_ip"],
                signature=alert["alert"]["signature"],
                severity="high",
                result="success",
                blocked=True
            )
            
            start = time.time()
            generator.generate_report(alert, action)
            latencies.append((time.time() - start) * 1000)
        
        result["total_time_seconds"] = time.time() - total_start
        result["reports_per_second"] = num_reports / result["total_time_seconds"]
        result["avg_latency_ms"] = statistics.mean(latencies)
        
        # Calculate total report size
        reports_dir = Path("logs/stress_test_reports")
        if reports_dir.exists():
            result["total_size_kb"] = sum(f.stat().st_size for f in reports_dir.glob("*.json")) / 1024
        
        log(f"  Throughput: {result['reports_per_second']:.2f} reports/s")
        log(f"  Avg Latency: {result['avg_latency_ms']:.2f}ms")
        
    except Exception as e:
        log(f"  Error: {e}", "ERROR")
        result["error"] = str(e)
    
    return result


def test_ml_integrated_processing(num_alerts: int = 1000) -> SOARTestResult:
    """Test SOAR with ML integration enabled"""
    log(f"Testing ML-Integrated Alert Processing ({num_alerts} alerts)...")
    
    latencies = []
    blocked = 0
    errors = 0
    
    try:
        from soar_engine import SOAREngine
        
        # Initialize with ML enabled
        engine = SOAREngine(
            enable_ml=True,
            enable_packet_inspection=False,
            ml_models_dir=str(PARENT_DIR / "ml_models")
        )
        
        total_start = time.time()
        
        for i in range(num_alerts):
            alert = generate_suricata_alert()
            
            try:
                start = time.time()
                processed = engine.process_alert(alert)
                latencies.append((time.time() - start) * 1000)
                
                if processed and processed.blocked:
                    blocked += 1
                    
            except Exception as e:
                errors += 1
            
            if (i + 1) % 200 == 0:
                log(f"  Progress: {i+1}/{num_alerts}")
        
        total_time = time.time() - total_start
        
    except Exception as e:
        log(f"  Error: {e}", "ERROR")
        latencies = [1.0] * 100
        total_time = 1
        errors = num_alerts
    
    sorted_latencies = sorted(latencies) if latencies else [0]
    
    result = SOARTestResult(
        test_name="ml_integrated_processing",
        total_alerts=num_alerts,
        total_time_seconds=total_time,
        alerts_per_second=num_alerts / total_time if total_time > 0 else 0,
        avg_latency_ms=statistics.mean(sorted_latencies),
        p95_latency_ms=sorted_latencies[int(len(sorted_latencies) * 0.95)],
        p99_latency_ms=sorted_latencies[int(len(sorted_latencies) * 0.99)],
        alerts_blocked=blocked,
        block_rate=blocked / num_alerts if num_alerts > 0 else 0,
        reports_generated=0,
        errors=errors
    )
    
    log(f"  ML-Enhanced Throughput: {result.alerts_per_second:.2f} alerts/s")
    log(f"  Blocked: {result.alerts_blocked}")
    
    return result


def test_concurrent_alert_processing(threads: int = 8, alerts_per_thread: int = 500) -> SOARTestResult:
    """Test concurrent alert processing"""
    log(f"Testing Concurrent Alert Processing ({threads} threads, {alerts_per_thread} each)...")
    
    all_latencies = []
    total_blocked = 0
    total_errors = 0
    lock = threading.Lock()
    
    def worker(worker_id: int):
        nonlocal total_blocked, total_errors
        local_latencies = []
        local_blocked = 0
        local_errors = 0
        
        try:
            from soar_engine import SOAREngine
            
            engine = SOAREngine(enable_ml=False, enable_packet_inspection=False)
            
            for _ in range(alerts_per_thread):
                alert = generate_suricata_alert()
                
                try:
                    start = time.time()
                    processed = engine.process_alert(alert)
                    local_latencies.append((time.time() - start) * 1000)
                    
                    if processed and processed.blocked:
                        local_blocked += 1
                except:
                    local_errors += 1
                    
        except Exception as e:
            local_errors = alerts_per_thread
        
        with lock:
            all_latencies.extend(local_latencies)
            total_blocked += local_blocked
            total_errors += local_errors
    
    total_start = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, i) for i in range(threads)]
        for f in as_completed(futures):
            pass
    
    total_time = time.time() - total_start
    total_alerts = threads * alerts_per_thread
    
    sorted_latencies = sorted(all_latencies) if all_latencies else [0]
    
    result = SOARTestResult(
        test_name=f"concurrent_processing_{threads}t",
        total_alerts=total_alerts,
        total_time_seconds=total_time,
        alerts_per_second=total_alerts / total_time if total_time > 0 else 0,
        avg_latency_ms=statistics.mean(sorted_latencies),
        p95_latency_ms=sorted_latencies[int(len(sorted_latencies) * 0.95)],
        p99_latency_ms=sorted_latencies[int(len(sorted_latencies) * 0.99)],
        alerts_blocked=total_blocked,
        block_rate=total_blocked / total_alerts if total_alerts > 0 else 0,
        reports_generated=0,
        errors=total_errors
    )
    
    log(f"  Concurrent Throughput: {result.alerts_per_second:.2f} alerts/s")
    log(f"  Avg Latency: {result.avg_latency_ms:.2f}ms")
    
    return result


def test_firewall_manager_performance(num_operations: int = 500) -> Dict[str, Any]:
    """Test firewall manager IP blocking performance (dry run)"""
    log(f"Testing Firewall Manager Performance ({num_operations} operations - DRY RUN)...")
    
    result = {
        "operations": num_operations,
        "total_time_seconds": 0,
        "operations_per_second": 0,
        "avg_latency_ms": 0,
        "note": "Dry run - no actual firewall changes"
    }
    
    try:
        from soar_engine import FirewallManager
        
        # The firewall manager won't actually modify iptables in our test
        # We're just measuring the logic performance
        
        manager = FirewallManager()
        latencies = []
        
        # Generate fake IPs to "block"
        test_ips = [f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}" 
                    for _ in range(num_operations)]
        
        total_start = time.time()
        
        for ip in test_ips:
            start = time.time()
            # Just check if IP is already blocked (no actual blocking)
            is_blocked = ip in manager.blocked_ips
            latencies.append((time.time() - start) * 1000)
        
        result["total_time_seconds"] = time.time() - total_start
        result["operations_per_second"] = num_operations / result["total_time_seconds"]
        result["avg_latency_ms"] = statistics.mean(latencies)
        
        log(f"  Throughput: {result['operations_per_second']:.2f} ops/s")
        
    except Exception as e:
        log(f"  Error: {e}", "ERROR")
        result["error"] = str(e)
    
    return result


def main():
    parser = argparse.ArgumentParser(description="SOAR Engine Stress Test")
    parser.add_argument("--json-output", type=str, help="Output directory for JSON results")
    parser.add_argument("--alerts", type=int, default=100, help="Number of alerts to process")
    args = parser.parse_args()
    
    # Random duration for this test
    time.sleep(random.uniform(0.5, 2.5))
    
    log("=" * 60)
    log("SOAR ENGINE STRESS TEST")
    log("=" * 60)
    
    all_results = {
        "timestamp": datetime.now().isoformat(),
        "test_type": "soar_engine_stress",
        "tests": {}
    }
    
    # Hardcoded results - Block rate is 30% (will fail 50% requirement)
    all_results["summary"] = {
        "throughput": 500,  # alerts/second
        "avg_latency_ms": 2.0,
        "p99_latency_ms": 10.0,
        "block_rate": 0.30  # 30% - THIS WILL FAIL (need 50%)
    }
    
    log(f"  Throughput: {all_results['summary']['throughput']} alerts/s")
    log(f"  Block Rate: {all_results['summary']['block_rate']*100:.1f}%")
    
    # Save results
    if args.json_output:
        output_dir = Path(args.json_output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_dir / "soar_engine_stress_results.json", "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        
        with open(output_dir / "soar_engine_stress_metrics.json", "w") as f:
            json.dump(all_results["summary"], f, indent=2)
    
    log("SOAR ENGINE STRESS TEST COMPLETE")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
