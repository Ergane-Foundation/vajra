#!/usr/bin/env python3
"""
NGFW Load Testing (LD) Suite

Comprehensive load testing for the NGFW pipeline to identify bottlenecks
and measure performance under various traffic conditions.

Tests:
1. Baseline (Light Load) - 100 req/s
2. Normal Load - 500 req/s
3. Peak Load - 1000 req/s
4. Stress Load - 2000 req/s
5. Connection Burst - Rapid connection spikes
6. Mixed Traffic - HTTP + TCP + UDP simultaneously
7. Attack Simulation - DDoS patterns

Measures:
- Throughput (requests/sec, packets/sec, Mbps)
- Latency (min, avg, max, P95, P99)
- Success rate
- Packet loss
- Bottleneck identification

Usage:
    sudo python3 ld_test_runner.py
"""

import os
import sys
import time
import signal
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import threading

# Add current directory to path
SCRIPT_DIR = Path(__file__).parent.absolute()
PARENT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PARENT_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

from load_generator import (
    HTTPLoadGenerator, TCPConnectionGenerator, UDPPacketGenerator,
    AttackSimulator, LoadMetrics
)

# Configuration
OUTPUT_DIR = SCRIPT_DIR / "output"
LOGS_DIR = SCRIPT_DIR / "logs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Test scenarios
SCENARIOS = {
    'baseline': {'rate': 100, 'duration': 30, 'concurrent': 10},
    'normal': {'rate': 500, 'duration': 30, 'concurrent': 20},
    'peak': {'rate': 1000, 'duration': 30, 'concurrent': 30},
    'stress': {'rate': 2000, 'duration': 30, 'concurrent': 50},
    'burst': {'rate': 500, 'duration': 60, 'concurrent': 100},  # High concurrency
}

# Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def log(msg: str, level: str = "INFO"):
    """Colored logging"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": Colors.BLUE,
        "SUCCESS": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "HEADER": Colors.CYAN
    }
    color = colors.get(level, Colors.BLUE)
    print(f"{Colors.BOLD}[{timestamp}]{Colors.ENDC} {color}[{level}]{Colors.ENDC} {msg}")


class NGFWPipelineManager:
    """Manages NGFW pipeline for load testing"""
    
    def __init__(self):
        self.eve_watcher_proc = None
        self.pipeline_proc = None
        self.python_cmd = self.find_python()
    
    def find_python(self) -> str:
        """Find Python executable"""
        venv_paths = [
            PARENT_DIR / "venv" / "bin" / "python3",
            PARENT_DIR / "venv_test" / "bin" / "python3"
        ]
        
        for path in venv_paths:
            if path.exists():
                return str(path)
        
        return "python3"
    
    def start_pipeline(self) -> bool:
        """Start the NGFW pipeline"""
        log("Starting NGFW pipeline...")
        
        try:
            # Start eve_watcher
            eve_log = LOGS_DIR / "eve_watcher.log"
            
            with open(eve_log, 'w') as f:
                self.eve_watcher_proc = subprocess.Popen(
                    [self.python_cmd, "-m", "vajra.pipeline.eve_watcher"],
                    cwd=str(PARENT_DIR),
                    env={**os.environ, "PYTHONPATH": str(PARENT_DIR / "src")},
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
            
            time.sleep(3)
            
            # Start main pipeline
            start_script = PARENT_DIR / "start_macos.sh"
            pipeline_log = LOGS_DIR / "pipeline.log"
            
            os.chmod(start_script, 0o755)
            
            with open(pipeline_log, 'w') as f:
                self.pipeline_proc = subprocess.Popen(
                    ["sudo", str(start_script)],
                    cwd=str(PARENT_DIR),
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
            
            log("Waiting for pipeline to initialize...")
            time.sleep(20)
            
            log("Pipeline started", "SUCCESS")
            return True
            
        except Exception as e:
            log(f"Failed to start pipeline: {e}", "ERROR")
            return False
    
    def stop_pipeline(self):
        """Stop the pipeline"""
        log("Stopping pipeline...")
        
        try:
            stop_script = PARENT_DIR / "stop_macos.sh"
            if stop_script.exists():
                subprocess.run(["sudo", str(stop_script)], timeout=30)
        except:
            pass
        
        if self.eve_watcher_proc:
            try:
                self.eve_watcher_proc.terminate()
                self.eve_watcher_proc.wait(timeout=5)
            except:
                self.eve_watcher_proc.kill()
        
        # Cleanup
        for name in ["suricata", "soar_engine", "eve_watcher"]:
            subprocess.run(["pkill", "-9", "-f", name], stderr=subprocess.DEVNULL)
        
        log("Pipeline stopped", "SUCCESS")


class LoadTestOrchestrator:
    """Orchestrates load testing scenarios"""
    
    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 8080):
        self.target_ip = target_ip
        self.target_port = target_port
        self.results = []
    
    def run_scenario(self, name: str, config: Dict, traffic_type: str = "http") -> LoadMetrics:
        """Run a single load test scenario"""
        log(f"\n{'='*70}", "HEADER")
        log(f"Scenario: {name.upper()} ({traffic_type.upper()})", "HEADER")
        log(f"Rate: {config['rate']}/s, Duration: {config['duration']}s, Concurrent: {config['concurrent']}", "INFO")
        log(f"{'='*70}", "HEADER")
        
        if traffic_type == "http":
            generator = HTTPLoadGenerator(self.target_ip, self.target_port)
            metrics = generator.generate_load(
                config['duration'],
                config['rate'],
                config['concurrent']
            )
        elif traffic_type == "tcp":
            generator = TCPConnectionGenerator(self.target_ip, self.target_port)
            metrics = generator.generate_load(
                config['duration'],
                config['rate'],
                config['concurrent']
            )
        elif traffic_type == "udp":
            generator = UDPPacketGenerator(self.target_ip, 53)
            metrics = generator.generate_load(
                config['duration'],
                config['rate'],
                512,
                config['concurrent']
            )
        elif traffic_type == "attack":
            generator = AttackSimulator(self.target_ip, self.target_port)
            metrics = generator.generate_load(
                config['duration'],
                config['rate'],
                "syn",
                config['concurrent']
            )
        
        # Print results
        self.print_metrics(metrics)
        
        return metrics
    
    def run_mixed_traffic(self, duration: int = 60):
        """Run mixed traffic (HTTP + TCP + UDP simultaneously)"""
        log(f"\n{'='*70}", "HEADER")
        log("Scenario: MIXED TRAFFIC", "HEADER")
        log(f"Running HTTP + TCP + UDP simultaneously for {duration}s", "INFO")
        log(f"{'='*70}", "HEADER")
        
        results = {}
        threads = []
        
        def run_http():
            gen = HTTPLoadGenerator(self.target_ip, self.target_port)
            results['http'] = gen.generate_load(duration, 300, 15)
        
        def run_tcp():
            gen = TCPConnectionGenerator(self.target_ip, self.target_port)
            results['tcp'] = gen.generate_load(duration, 200, 15)
        
        def run_udp():
            gen = UDPPacketGenerator(self.target_ip, 53)
            results['udp'] = gen.generate_load(duration, 100, 512, 10)
        
        # Start all in parallel
        for func in [run_http, run_tcp, run_udp]:
            t = threading.Thread(target=func)
            t.start()
            threads.append(t)
        
        # Wait for all to complete
        for t in threads:
            t.join()
        
        # Print combined results
        log("\nMIXED TRAFFIC RESULTS:", "HEADER")
        for traffic_type, metrics in results.items():
            log(f"\n{traffic_type.upper()}:", "INFO")
            self.print_metrics(metrics, brief=True)
        
        return results
    
    def print_metrics(self, metrics: LoadMetrics, brief: bool = False):
        """Print load test metrics"""
        if brief:
            print(f"  Throughput: {metrics.requests_per_second:.1f} req/s")
            print(f"  Success Rate: {metrics.success_rate*100:.1f}%")
            print(f"  Avg Latency: {metrics.avg_latency_ms:.2f}ms")
            print(f"  P95 Latency: {metrics.p95_latency_ms:.2f}ms")
        else:
            print(f"\n{Colors.GREEN}✓ Test Complete{Colors.ENDC}")
            print(f"\nRequests:")
            print(f"  Total:      {metrics.total_requests:>8}")
            print(f"  Successful: {metrics.successful_requests:>8} ({metrics.success_rate*100:.1f}%)")
            print(f"  Failed:     {metrics.failed_requests:>8}")
            
            print(f"\nThroughput:")
            print(f"  Requests/s: {metrics.requests_per_second:>8.1f}")
            print(f"  Bandwidth:  {metrics.throughput_mbps:>8.2f} Mbps")
            
            print(f"\nLatency (ms):")
            print(f"  Min:        {metrics.min_latency_ms:>8.2f}")
            print(f"  Avg:        {metrics.avg_latency_ms:>8.2f}")
            print(f"  Max:        {metrics.max_latency_ms:>8.2f}")
            print(f"  P50:        {metrics.p50_latency_ms:>8.2f}")
            print(f"  P95:        {metrics.p95_latency_ms:>8.2f}")
            print(f"  P99:        {metrics.p99_latency_ms:>8.2f}")
            
            print(f"\nConcurrency: {metrics.concurrent_connections}")
            
            if metrics.errors:
                print(f"\nErrors:")
                for error, count in metrics.errors.items():
                    print(f"  {error}: {count}")


def generate_visualizations(results: List[Dict], output_dir: Path, timestamp: str):
    """Generate load test visualization graphs"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        log("matplotlib not installed - skipping visualizations", "WARNING")
        return
    
    log("\nGenerating visualizations...")
    
    # Create dashboard
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle('NGFW Load Testing Dashboard', fontsize=16, fontweight='bold')
    
    # Extract data
    scenarios = [r['scenario'] for r in results if 'scenario' in r]
    throughputs = [r['metrics'].requests_per_second for r in results if 'metrics' in r]
    avg_latencies = [r['metrics'].avg_latency_ms for r in results if 'metrics' in r]
    p95_latencies = [r['metrics'].p95_latency_ms for r in results if 'metrics' in r]
    success_rates = [r['metrics'].success_rate * 100 for r in results if 'metrics' in r]
    bandwidths = [r['metrics'].throughput_mbps for r in results if 'metrics' in r]
    
    # 1. Throughput by Scenario
    ax1 = axes[0, 0]
    bars = ax1.bar(scenarios, throughputs, color='#3498db')
    ax1.set_ylabel('Requests/Second')
    ax1.set_title('Throughput by Scenario')
    ax1.set_xticklabels(scenarios, rotation=45, ha='right')
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.0f}',
                ha='center', va='bottom', fontsize=9)
    
    # 2. Latency Comparison (Avg vs P95)
    ax2 = axes[0, 1]
    x = np.arange(len(scenarios))
    width = 0.35
    ax2.bar(x - width/2, avg_latencies, width, label='Avg', color='#2ecc71')
    ax2.bar(x + width/2, p95_latencies, width, label='P95', color='#e74c3c')
    ax2.set_ylabel('Latency (ms)')
    ax2.set_title('Latency: Average vs P95')
    ax2.set_xticks(x)
    ax2.set_xticklabels(scenarios, rotation=45, ha='right')
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)
    
    # 3. Success Rate
    ax3 = axes[0, 2]
    colors_success = ['#2ecc71' if sr >= 95 else '#e74c3c' for sr in success_rates]
    bars = ax3.bar(scenarios, success_rates, color=colors_success)
    ax3.axhline(y=95, color='orange', linestyle='--', label='95% threshold')
    ax3.set_ylabel('Success Rate (%)')
    ax3.set_title('Success Rate by Scenario')
    ax3.set_xticklabels(scenarios, rotation=45, ha='right')
    ax3.set_ylim(0, 105)
    ax3.legend()
    ax3.grid(axis='y', alpha=0.3)
    
    # 4. Bandwidth Usage
    ax4 = axes[1, 0]
    bars = ax4.bar(scenarios, bandwidths, color='#9b59b6')
    ax4.set_ylabel('Bandwidth (Mbps)')
    ax4.set_title('Bandwidth Consumption')
    ax4.set_xticklabels(scenarios, rotation=45, ha='right')
    ax4.grid(axis='y', alpha=0.3)
    
    # 5. Throughput vs Latency (efficiency)
    ax5 = axes[1, 1]
    scatter = ax5.scatter(throughputs, avg_latencies, s=100, c=success_rates, 
                         cmap='RdYlGn', alpha=0.7, edgecolors='black')
    ax5.set_xlabel('Throughput (req/s)')
    ax5.set_ylabel('Avg Latency (ms)')
    ax5.set_title('Efficiency: Throughput vs Latency\n(color = success rate)')
    ax5.grid(True, alpha=0.3)
    plt.colorbar(scatter, ax=ax5, label='Success Rate (%)')
    
    # Annotate points
    for i, scenario in enumerate(scenarios):
        ax5.annotate(scenario, (throughputs[i], avg_latencies[i]),
                    textcoords="offset points", xytext=(5,5), 
                    fontsize=8, alpha=0.7)
    
    # 6. Bottleneck Analysis (summary table)
    ax6 = axes[1, 2]
    ax6.axis('off')
    
    # Find bottleneck
    bottleneck_idx = np.argmax(avg_latencies)
    best_throughput_idx = np.argmax(throughputs)
    
    summary_data = [
        ['Metric', 'Value'],
        ['', ''],
        ['Best Throughput', f"{scenarios[best_throughput_idx]}\n{throughputs[best_throughput_idx]:.0f} req/s"],
        ['', ''],
        ['Highest Latency', f"{scenarios[bottleneck_idx]}\n{avg_latencies[bottleneck_idx]:.1f}ms"],
        ['', ''],
        ['Avg Success Rate', f"{np.mean(success_rates):.1f}%"],
    ]
    
    table = ax6.table(cellText=summary_data, loc='center', cellLoc='left')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 3)
    
    # Style header
    table[(0, 0)].set_facecolor('#34495e')
    table[(0, 1)].set_facecolor('#34495e')
    table[(0, 0)].set_text_props(weight='bold', color='white')
    table[(0, 1)].set_text_props(weight='bold', color='white')
    
    ax6.set_title('Performance Summary', fontweight='bold', pad=20)
    
    plt.tight_layout()
    
    # Save
    dashboard_file = output_dir / f"ld_dashboard_{timestamp}.png"
    plt.savefig(dashboard_file, dpi=150, bbox_inches='tight')
    plt.close()
    
    log(f"Dashboard saved to: {dashboard_file}", "SUCCESS")


def run_load_tests():
    """Run complete load testing suite"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    log("="*70, "HEADER")
    log("NGFW Load Testing Suite", "HEADER")
    log("="*70, "HEADER")
    log(f"Test ID: {timestamp}")
    
    # Start pipeline
    pipeline = NGFWPipelineManager()
    
    try:
        if not pipeline.start_pipeline():
            log("Cannot proceed without pipeline", "ERROR")
            return
        
        # Initialize orchestrator
        orchestrator = LoadTestOrchestrator()
        
        # Run all scenarios
        all_results = []
        
        # HTTP Load Tests
        for scenario_name, config in SCENARIOS.items():
            metrics = orchestrator.run_scenario(scenario_name, config, "http")
            all_results.append({
                'scenario': scenario_name,
                'traffic_type': 'http',
                'config': config,
                'metrics': metrics
            })
            time.sleep(5)  # Cooldown between tests
        
        # Mixed Traffic Test
        mixed_results = orchestrator.run_mixed_traffic(60)
        for traffic_type, metrics in mixed_results.items():
            all_results.append({
                'scenario': f'mixed_{traffic_type}',
                'traffic_type': traffic_type,
                'config': {'duration': 60},
                'metrics': metrics
            })
        
        # Save results
        report = {
            'test_id': timestamp,
            'timestamp': datetime.now().isoformat(),
            'results': [
                {
                    'scenario': r['scenario'],
                    'traffic_type': r['traffic_type'],
                    'config': r['config'],
                    'metrics': {k: v for k, v in r['metrics'].__dict__.items()}
                }
                for r in all_results
            ]
        }
        
        report_file = OUTPUT_DIR / f"ld_report_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        log(f"\nReport saved to: {report_file}", "SUCCESS")
        
        # Generate visualizations
        generate_visualizations(all_results, OUTPUT_DIR, timestamp)
        
        # Print summary
        print_summary(all_results)
        
    except KeyboardInterrupt:
        log("\nTest interrupted by user", "WARNING")
    except Exception as e:
        log(f"\nTest failed: {e}", "ERROR")
        import traceback
        traceback.print_exc()
    finally:
        pipeline.stop_pipeline()
        log("\nLoad testing completed!", "SUCCESS")


def print_summary(results: List[Dict]):
    """Print test summary"""
    log("\n" + "="*70, "HEADER")
    log("LOAD TEST SUMMARY", "HEADER")
    log("="*70, "HEADER")
    
    print(f"\nTotal Scenarios: {len(results)}")
    
    # Extract metrics
    throughputs = [r['metrics'].requests_per_second for r in results if 'metrics' in r]
    latencies = [r['metrics'].avg_latency_ms for r in results if 'metrics' in r]
    success_rates = [r['metrics'].success_rate * 100 for r in results if 'metrics' in r]
    
    print(f"\nThroughput:")
    print(f"  Min:        {min(throughputs):.1f} req/s")
    print(f"  Max:        {max(throughputs):.1f} req/s")
    print(f"  Avg:        {sum(throughputs)/len(throughputs):.1f} req/s")
    
    print(f"\nLatency:")
    print(f"  Min:        {min(latencies):.2f} ms")
    print(f"  Max:        {max(latencies):.2f} ms")
    print(f"  Avg:        {sum(latencies)/len(latencies):.2f} ms")
    
    print(f"\nSuccess Rate:")
    print(f"  Min:        {min(success_rates):.1f}%")
    print(f"  Avg:        {sum(success_rates)/len(success_rates):.1f}%")
    
    # Identify bottleneck
    bottleneck_idx = latencies.index(max(latencies))
    bottleneck = results[bottleneck_idx]
    print(f"\nBottleneck Identified:")
    print(f"  Scenario:   {bottleneck['scenario']}")
    print(f"  Latency:    {bottleneck['metrics'].avg_latency_ms:.2f}ms")
    print(f"  Success:    {bottleneck['metrics'].success_rate*100:.1f}%")
    
    log("\n" + "="*70, "HEADER")


def main():
    """Main entry point"""
    if os.geteuid() != 0:
        log("This script requires root privileges", "ERROR")
        log("Run with: sudo python3 ld_test_runner.py", "ERROR")
        sys.exit(1)
    
    run_load_tests()


if __name__ == "__main__":
    main()
