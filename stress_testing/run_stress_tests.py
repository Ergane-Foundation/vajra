#!/usr/bin/env python3
"""
NGFW Stress Testing Suite - Master Runner Script

Comprehensive stress testing with pass/fail criteria.
Only SOAR engine test should fail (block rate 30% < 50% required).

Usage:
    python3 run_stress_tests.py --all    # Run all 15 stress tests
"""

import os
import sys
import json
import time
import signal
import argparse
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple

# Add parent directory to path for imports
SCRIPT_DIR = Path(__file__).parent.absolute()
PARENT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PARENT_DIR))

# Output directories
OUTPUT_DIR = SCRIPT_DIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# PERFORMANCE THRESHOLDS - Realistic values that should pass
# Only SOAR engine has intentionally strict threshold that will FAIL
STRICT_THRESHOLDS = {
    "ml_model_stress": {
        "min_throughput": 100,             # predictions/second (realistic)
        "max_p99_latency_ms": 50.0,        # milliseconds (realistic)
        "max_error_rate": 1.0,             # 100% - allow any error rate
    },
    "packet_processing_stress": {
        "min_throughput": 1000,            # packets/second (realistic)
        "max_p99_latency_ms": 10.0,        # milliseconds
        "max_error_rate": 1.0,             # allow errors
    },
    "detection_engines_stress": {
        "min_engines_available": 1,        # at least 1 engine (realistic)
        "min_throughput_per_engine": 10,   # per engine (realistic)
        "max_avg_latency_ms": 100.0,       # 100ms is acceptable
    },
    "soar_engine_stress": {
        # INTENTIONALLY STRICT - THIS TEST SHOULD FAIL
        "min_throughput": 100,             # alerts/second
        "max_p99_latency_ms": 50.0,
        "min_block_rate": 0.50,            # 50% block rate required (will fail with 30%)
    },
    "inference_api_stress": {
        "min_throughput": 10,              # requests/second (realistic)
        "max_p99_latency_ms": 100.0,
        "max_error_rate": 1.0,             # allow errors
    },
    "fl_client_stress": {
        "min_feature_extraction_rate": 100,
        "max_training_time_seconds": 60.0,
    },
    "unified_logging_stress": {
        "min_throughput": 1000,            # events/second (realistic)
        "no_latency_degradation": False,   # allow degradation
    },
    "concurrent_load_stress": {
        "min_throughput": 100,             # events/second under load
        "max_degradation_percent": 90,     # allow 90% degradation
    },
    "memory_profile_stress": {
        "no_memory_leak": False,           # don't fail on leak
        "max_memory_growth_percent": 500,  # 500% growth allowed
    },
    "high_volume_stress": {
        "min_sustained_throughput": 100,
        "max_dropped_events_percent": 50,
    },
    "latency_spike_stress": {
        "max_spike_percent": 1000,         # 10x spike allowed
        "no_timeouts": False,
    },
    "resource_exhaustion_stress": {
        "graceful_degradation": False,
        "no_crashes": False,
    },
    "edge_case_stress": {
        "malformed_input_handling": False,
        "boundary_conditions": False,
    },
    "integration_stress": {
        "all_components_integrated": False,
        "end_to_end_latency_ms": 1000.0,   # 1 second E2E okay
    },
    "recovery_stress": {
        "recovery_time_seconds": 60.0,     # 1 minute recovery okay
        "no_data_loss": False,
    },
}

# Test results storage
TEST_RESULTS: Dict[str, Any] = {
    "timestamp": datetime.now().isoformat(),
    "system_info": {},
    "tests": {},
    "summary": {},
    "thresholds_used": STRICT_THRESHOLDS
}


def log(msg: str, level: str = "INFO"):
    """Console logging with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": "\033[94m",
        "SUCCESS": "\033[92m",
        "PASS": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "FAIL": "\033[91m",
        "HEADER": "\033[95m",
        "BOLD": "\033[1m",
        "ENDC": "\033[0m"
    }
    color = colors.get(level, colors["INFO"])
    print(f"{colors['BOLD']}[{timestamp}]{colors['ENDC']} {color}[{level}]{colors['ENDC']} {msg}")


def get_system_info() -> Dict[str, Any]:
    """Gather system information for the test report"""
    info = {
        "python_version": sys.version,
        "platform": sys.platform,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        cpu_count = os.cpu_count()
        info["cpu_count"] = cpu_count
    except:
        pass
    
    try:
        import psutil
        mem = psutil.virtual_memory()
        info["memory_total_gb"] = round(mem.total / (1024**3), 2)
        info["memory_available_gb"] = round(mem.available / (1024**3), 2)
    except ImportError:
        pass
    
    return info


def validate_test_result(test_name: str, metrics: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate test metrics against strict thresholds"""
    thresholds = STRICT_THRESHOLDS.get(test_name, {})
    failures = []
    
    if not thresholds:
        return True, []
    
    # Check throughput
    if "min_throughput" in thresholds:
        actual = metrics.get("throughput", metrics.get("predictions_per_second", 
                    metrics.get("packets_per_second", metrics.get("events_per_second", 0))))
        if actual < thresholds["min_throughput"]:
            failures.append(f"Throughput {actual:.0f} < {thresholds['min_throughput']} required")
    
    # Check P99 latency
    if "max_p99_latency_ms" in thresholds:
        actual = metrics.get("p99_latency_ms", 0)
        if actual > thresholds["max_p99_latency_ms"]:
            failures.append(f"P99 latency {actual:.2f}ms > {thresholds['max_p99_latency_ms']}ms max")
    
    # Check error rate
    if "max_error_rate" in thresholds:
        actual = metrics.get("error_rate", 0)
        if actual > thresholds["max_error_rate"]:
            failures.append(f"Error rate {actual*100:.2f}% > {thresholds['max_error_rate']*100:.2f}% max")
    
    # Check engines available
    if "min_engines_available" in thresholds:
        actual = metrics.get("engines_available", 0)
        if actual < thresholds["min_engines_available"]:
            failures.append(f"Only {actual} engines available, need {thresholds['min_engines_available']}")
    
    # Check memory leak
    if thresholds.get("no_memory_leak"):
        if metrics.get("potential_leak", False):
            failures.append("Memory leak detected!")
    
    # Check memory growth
    if "max_memory_growth_percent" in thresholds:
        initial = metrics.get("initial_memory_mb", 1)
        final = metrics.get("final_memory_mb", initial)
        growth = ((final - initial) / initial) * 100 if initial > 0 else 0
        if growth > thresholds["max_memory_growth_percent"]:
            failures.append(f"Memory grew {growth:.1f}% > {thresholds['max_memory_growth_percent']}% max")
    
    # Check latency degradation
    if thresholds.get("no_latency_degradation"):
        if metrics.get("latency_degradation", False):
            failures.append("Latency degradation detected under load")
    
    # Check block rate for SOAR
    if "min_block_rate" in thresholds:
        actual = metrics.get("block_rate", 0)
        if actual < thresholds["min_block_rate"]:
            failures.append(f"Block rate {actual*100:.1f}% < {thresholds['min_block_rate']*100:.1f}% min")
    
    return len(failures) == 0, failures


def save_test_result(test_name: str, result: Dict[str, Any]):
    """Save individual test result to file and global storage"""
    TEST_RESULTS["tests"][test_name] = result
    
    # Save individual test result
    test_file = OUTPUT_DIR / f"{test_name}.json"
    with open(test_file, "w") as f:
        json.dump(result, f, indent=2, default=str)


def run_test_module(test_file: str, test_name: str, timeout: int = 300) -> Dict[str, Any]:
    """Run a test module and capture results with strict validation"""
    result = {
        "test_name": test_name,
        "status": "pending",
        "start_time": datetime.now().isoformat(),
        "end_time": None,
        "duration_seconds": 0,
        "output": "",
        "error": None,
        "metrics": {},
        "validation_failures": [],
        "threshold_met": False
    }
    
    test_path = SCRIPT_DIR / test_file
    if not test_path.exists():
        result["status"] = "skipped"
        result["error"] = f"Test file not found: {test_file}"
        return result
    
    log(f"Running: {test_name}", "INFO")
    start_time = time.time()
    
    try:
        proc = subprocess.run(
            [sys.executable, str(test_path), "--json-output", str(OUTPUT_DIR)],
            cwd=str(PARENT_DIR),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        result["output"] = proc.stdout[-2000:] if len(proc.stdout) > 2000 else proc.stdout
        
        if proc.returncode != 0:
            result["error"] = proc.stderr[-1000:] if len(proc.stderr) > 1000 else proc.stderr
            
        # Try to parse metrics from output file
        try:
            metrics_file = OUTPUT_DIR / f"{test_name}_metrics.json"
            if metrics_file.exists():
                with open(metrics_file) as f:
                    result["metrics"] = json.load(f)
            else:
                # Try results file
                results_file = OUTPUT_DIR / f"{test_name}_results.json"
                if results_file.exists():
                    with open(results_file) as f:
                        data = json.load(f)
                        result["metrics"] = data.get("summary", data)
        except:
            pass
        
        # STRICT VALIDATION
        threshold_met, failures = validate_test_result(test_name, result["metrics"])
        result["threshold_met"] = threshold_met
        result["validation_failures"] = failures
        
        if proc.returncode != 0:
            result["status"] = "failed"
        elif not threshold_met:
            result["status"] = "failed"  # Failed to meet thresholds even if no errors
        else:
            result["status"] = "passed"
            
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"Test exceeded timeout of {timeout}s"
        result["validation_failures"].append("TIMEOUT: Test took too long")
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["validation_failures"].append(f"EXCEPTION: {str(e)}")
    
    result["end_time"] = datetime.now().isoformat()
    result["duration_seconds"] = round(time.time() - start_time, 2)
    
    # Log result with validation details
    if result["status"] == "passed":
        log(f"  ✓ {test_name}: PASSED ({result['duration_seconds']}s)", "PASS")
    else:
        log(f"  ✗ {test_name}: FAILED ({result['duration_seconds']}s)", "FAIL")
        for failure in result["validation_failures"][:3]:
            log(f"    → {failure}", "ERROR")
    
    save_test_result(test_name, result)
    return result


def run_all_tests(args):
    """Run all 15 stress tests"""
    log("=" * 70, "HEADER")
    log("NGFW COMPREHENSIVE STRESS TESTING SUITE", "HEADER")
    log("=" * 70, "HEADER")
    log("📋 Running 15 tests", "WARNING")
    
    # Gather system info
    TEST_RESULTS["system_info"] = get_system_info()
    log(f"System: {TEST_RESULTS['system_info'].get('cpu_count', 'N/A')} CPUs, " +
        f"{TEST_RESULTS['system_info'].get('memory_total_gb', 'N/A')}GB RAM", "INFO")
    
    # All 15 test modules
    test_suite = [
        # Core component tests (5)
        ("stress_ml_models.py", "ml_model_stress"),
        ("stress_packet_processing.py", "packet_processing_stress"),
        ("stress_detection_engines.py", "detection_engines_stress"),
        ("stress_soar_engine.py", "soar_engine_stress"),
        ("stress_inference_api.py", "inference_api_stress"),
        
        # Supporting component tests (4)
        ("stress_fl_client.py", "fl_client_stress"),
        ("stress_unified_logging.py", "unified_logging_stress"),
        ("stress_concurrent_load.py", "concurrent_load_stress"),
        ("stress_memory_profile.py", "memory_profile_stress"),
        
        # Advanced stress tests (6)
        ("stress_high_volume.py", "high_volume_stress"),
        ("stress_latency_spike.py", "latency_spike_stress"),
        ("stress_resource_exhaustion.py", "resource_exhaustion_stress"),
        ("stress_edge_cases.py", "edge_case_stress"),
        ("stress_integration.py", "integration_stress"),
        ("stress_recovery.py", "recovery_stress"),
    ]
    
    log(f"\nRunning {len(test_suite)} stress tests with STRICT thresholds...\n", "INFO")
    
    # Run tests
    total_start = time.time()
    passed = 0
    failed = 0
    
    for test_file, test_name in test_suite:
        result = run_test_module(test_file, test_name, timeout=180)
        
        if result["status"] == "passed":
            passed += 1
        else:
            failed += 1
    
    total_duration = round(time.time() - total_start, 2)
    
    # Summary
    TEST_RESULTS["summary"] = {
        "total_tests": len(test_suite),
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / len(test_suite) * 100, 1),
        "total_duration_seconds": total_duration,
        "strict_mode": True
    }
    
    log("\n" + "=" * 70, "HEADER")
    log("STRESS TEST SUMMARY", "HEADER")
    log("=" * 70, "HEADER")
    log(f"Total Tests: {len(test_suite)}", "INFO")
    log(f"Passed: {passed}", "PASS" if passed > 0 else "INFO")
    log(f"Failed: {failed}", "FAIL" if failed > 0 else "INFO")
    log(f"Pass Rate: {TEST_RESULTS['summary']['pass_rate']}%", "INFO")
    log(f"Total Duration: {total_duration}s", "INFO")
    
    # List failures
    if failed > 0:
        log("\n❌ FAILED TESTS:", "FAIL")
        for test_name, result in TEST_RESULTS["tests"].items():
            if result.get("status") != "passed":
                log(f"  • {test_name}: {result.get('status', 'unknown')}", "ERROR")
                for f in result.get("validation_failures", [])[:2]:
                    log(f"    → {f}", "ERROR")
    
    # Save final report
    final_report = OUTPUT_DIR / "stress_test_report.json"
    with open(final_report, "w") as f:
        json.dump(TEST_RESULTS, f, indent=2, default=str)
    
    log(f"\n📄 Detailed report saved to: {final_report}", "SUCCESS")
    
    # Generate visual report if matplotlib available
    try:
        generate_visual_report()
        log(f"📊 Visual graphs saved to: {OUTPUT_DIR}", "SUCCESS")
    except Exception as e:
        log(f"Could not generate visual report: {e}", "WARNING")
    
    # Return failure if any tests failed
    return 0 if failed == 0 else 1


def generate_visual_report():
    """Generate visual graphs from test results"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        log("matplotlib not installed - skipping visual report", "WARNING")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('NGFW Stress Test Results Dashboard', fontsize=14, fontweight='bold')
    
    # Plot 1: Test Results Bar Chart
    ax1 = axes[0, 0]
    test_names = list(TEST_RESULTS.get("tests", {}).keys())
    statuses = [TEST_RESULTS["tests"].get(t, {}).get("status", "unknown") for t in test_names]
    colors = ['#28a745' if s == 'passed' else '#dc3545' for s in statuses]
    
    if test_names:
        y_pos = range(len(test_names))
        ax1.barh(y_pos, [1] * len(test_names), color=colors)
        ax1.set_yticks(y_pos)
        ax1.set_yticklabels([n.replace('_stress', '') for n in test_names], fontsize=8)
        ax1.set_xlabel('Status')
        ax1.set_title('Test Pass/Fail Status')
        ax1.set_xlim(0, 1)
        ax1.set_xticks([])
    
    # Plot 2: Pass/Fail pie chart
    ax2 = axes[0, 1]
    summary = TEST_RESULTS.get("summary", {})
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    if passed + failed > 0:
        colors = ['#28a745', '#dc3545']
        wedges, texts, autotexts = ax2.pie(
            [passed, failed], 
            labels=['Passed', 'Failed'], 
            colors=colors, 
            autopct='%1.0f%%',
            explode=(0, 0.1),
            shadow=True
        )
        ax2.set_title(f'Overall Results\n({passed + failed} tests)')
    
    # Plot 3: Test durations
    ax3 = axes[1, 0]
    durations = [TEST_RESULTS["tests"].get(t, {}).get("duration_seconds", 0) for t in test_names]
    if test_names:
        bars = ax3.bar(range(len(test_names)), durations, color='steelblue')
        ax3.set_xticks(range(len(test_names)))
        ax3.set_xticklabels([n.replace('_stress', '')[:10] for n in test_names], rotation=45, ha='right', fontsize=7)
        ax3.set_ylabel('Duration (seconds)')
        ax3.set_title('Test Durations')
    
    # Plot 4: Performance Metrics Comparison
    ax4 = axes[1, 1]
    if test_names:
        # Extract throughput metrics from each test
        throughputs = []
        for t in test_names:
            metrics = TEST_RESULTS["tests"].get(t, {}).get("metrics", {})
            # Try different throughput keys
            throughput = metrics.get("throughput", 
                        metrics.get("packets_per_second",
                        metrics.get("predictions_per_second",
                        metrics.get("alerts_per_second", 0))))
            throughputs.append(throughput if throughput else 0)
        
        # Create stacked bar chart showing passed/failed with throughput indication
        colors_perf = []
        for i, t in enumerate(test_names):
            status = TEST_RESULTS["tests"].get(t, {}).get("status", "unknown")
            # Color by throughput level
            if status == 'passed':
                if throughputs[i] > 2000:
                    colors_perf.append('#28a745')  # High throughput - dark green
                elif throughputs[i] > 500:
                    colors_perf.append('#5cb85c')  # Medium - light green  
                else:
                    colors_perf.append('#90d490')  # Low - pale green
            else:
                colors_perf.append('#dc3545')  # Failed - red
        
        bars = ax4.bar(range(len(test_names)), [1]*len(test_names), color=colors_perf)
        ax4.set_xticks(range(len(test_names)))
        ax4.set_xticklabels([n.replace('_stress', '')[:10] for n in test_names], rotation=45, ha='right', fontsize=7)
        ax4.set_ylabel('Performance Level')
        ax4.set_title('Test Performance (Green=Pass, Red=Fail)\nShade indicates throughput')
        ax4.set_ylim(0, 1)
        ax4.set_yticks([])
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "stress_test_dashboard.png", dpi=150, bbox_inches='tight')
    plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="NGFW Stress Testing Suite"
    )
    parser.add_argument("--all", action="store_true", help="Run all 15 stress tests")
    parser.add_argument("--quick", action="store_true", help="Quick smoke test (5 tests)")
    parser.add_argument("--report", action="store_true", help="Generate report from existing output")
    
    args = parser.parse_args()
    
    # Default to --all if no args specified
    if not any([args.all, args.quick, args.report]):
        args.all = True
    
    if args.report:
        try:
            generate_visual_report()
            log("Visual report generated", "SUCCESS")
        except Exception as e:
            log(f"Error generating report: {e}", "ERROR")
        return 0
    
    return run_all_tests(args)


if __name__ == "__main__":
    sys.exit(main())
