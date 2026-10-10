#!/usr/bin/env python3
"""
Vajra Resource Consumption (RC) Testing Suite

This script performs comprehensive resource consumption testing of the entire
Vajra pipeline including:
- eve_watcher (WebSocket streaming)
- Suricata IDS
- SOAR Engine (with ML models)
- Packet Inspector
- Inference API (Federated Learning)
- Unified Logger
- Kafka Bridge

The test:
1. Starts the full pipeline (eve_watcher + start_macos.sh)
2. Monitors resource consumption in real-time
3. Simulates realistic traffic/attack scenarios
4. Generates comprehensive reports with visualizations

Usage:
    sudo python3 rc_test_runner.py

Output:
    - tests/perf/resource/output/rc_report_TIMESTAMP.json
    - tests/perf/resource/output/rc_dashboard_TIMESTAMP.png
    - tests/perf/resource/output/resource_timeline_TIMESTAMP.png
"""

import os
import sys
import time
import json
import signal
import subprocess
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import threading

# Add parent directory to path
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

from resource_monitor import ResourceMonitor

# Configuration
OUTPUT_DIR = SCRIPT_DIR / "output"
LOGS_DIR = SCRIPT_DIR / "logs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Test duration
WARMUP_DURATION = 10  # seconds
BASELINE_DURATION = 30  # seconds
LOAD_DURATION = 60  # seconds
COOLDOWN_DURATION = 10  # seconds

# Attack load
ATTACK_SIMULATOR = ROOT_DIR / "tools" / "attack_simulator.py"
ATTACK_SIMULATOR_LOG = LOGS_DIR / "attack_simulator.log"
# Every flag here must exist in the simulator's argparse. The simulator has no
# --quick mode, so the load phase uses its safe mode, which is also what it
# runs by default when neither --safe nor --full is given.
ATTACK_SIMULATOR_FLAGS = ["--safe"]
# Pause between simulator passes and how often the pass is checked for the end
# of the load window
ATTACK_GAP = 0.5  # seconds
ATTACK_POLL_INTERVAL = 0.5  # seconds


def find_python_interpreter() -> str:
    """Find the Python executable that has the project dependencies available"""
    venv_paths = [
        ROOT_DIR / "venv" / "bin" / "python3",
        ROOT_DIR / "venv_test" / "bin" / "python3"
    ]

    for path in venv_paths:
        if path.exists():
            return str(path)

    return "python3"


def build_attack_command(target: str) -> List[str]:
    """Build the command that runs tools/attack_simulator.py against target

    Every flag comes from ATTACK_SIMULATOR_FLAGS, which must stay in sync with
    the simulator's argparse: an unknown flag makes argparse exit before any
    attack is sent.
    """
    return [
        find_python_interpreter(),
        str(ATTACK_SIMULATOR),
        "--target",
        target,
        *ATTACK_SIMULATOR_FLAGS
    ]


# Colors for output
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
        "HEADER": Colors.HEADER
    }
    color = colors.get(level, Colors.BLUE)
    print(f"{Colors.BOLD}[{timestamp}]{Colors.ENDC} {color}[{level}]{Colors.ENDC} {msg}")


class VajraPipelineManager:
    """Manages the Vajra pipeline lifecycle"""
    
    def __init__(self):
        self.eve_watcher_proc = None
        self.start_macos_proc = None
        self.python_cmd = self.find_python()
        
    def find_python(self) -> str:
        """Find the correct Python executable"""
        return find_python_interpreter()
    
    def start_eve_watcher(self) -> bool:
        """Start eve_watcher"""
        log("Starting eve_watcher...")
        
        try:
            log_file = LOGS_DIR / "eve_watcher.log"
            
            with open(log_file, 'w') as f:
                self.eve_watcher_proc = subprocess.Popen(
                    [self.python_cmd, "-m", "vajra.pipeline.eve_watcher"],
                    cwd=str(ROOT_DIR),
                    env={**os.environ, "PYTHONPATH": str(ROOT_DIR / "src")},
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
            
            # Wait for startup
            time.sleep(3)
            
            if self.eve_watcher_proc.poll() is None:
                log(f"eve_watcher started (PID: {self.eve_watcher_proc.pid})", "SUCCESS")
                return True
            else:
                log("eve_watcher failed to start", "ERROR")
                return False
                
        except Exception as e:
            log(f"Failed to start eve_watcher: {e}", "ERROR")
            return False
    
    def start_macos_pipeline(self) -> bool:
        """Start the main pipeline with start_macos.sh"""
        log("Starting main Vajra pipeline (start_macos.sh)...")
        
        try:
            start_script = ROOT_DIR / "scripts" / "start_macos.sh"
            log_file = LOGS_DIR / "start_macos.log"
            
            # Make sure script is executable
            os.chmod(start_script, 0o755)
            
            with open(log_file, 'w') as f:
                self.start_macos_proc = subprocess.Popen(
                    ["sudo", str(start_script)],
                    cwd=str(ROOT_DIR),
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
            
            # Wait for all components to start
            log("Waiting for pipeline components to initialize...")
            time.sleep(15)
            
            # Check if key processes are running
            if self.check_pipeline_health():
                log("Vajra pipeline started successfully", "SUCCESS")
                return True
            else:
                log("Pipeline health check failed", "WARNING")
                return True  # Continue anyway
                
        except Exception as e:
            log(f"Failed to start pipeline: {e}", "ERROR")
            return False
    
    def check_pipeline_health(self) -> bool:
        """Check if key pipeline components are running"""
        required_processes = ["suricata", "soar_engine", "unified_logger"]
        running = []
        
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                for req in required_processes:
                    if req in name or req in cmdline:
                        running.append(req)
                        break
            except:
                continue
        
        log(f"Running components: {', '.join(set(running))}")
        return len(set(running)) >= 2  # At least 2 components
    
    def stop_pipeline(self):
        """Stop all pipeline components"""
        log("Stopping Vajra pipeline...")
        
        # Stop start_macos.sh processes
        try:
            stop_script = ROOT_DIR / "scripts" / "stop_macos.sh"
            if stop_script.exists():
                subprocess.run(["sudo", str(stop_script)], timeout=30)
        except:
            pass
        
        # Kill eve_watcher
        if self.eve_watcher_proc and self.eve_watcher_proc.poll() is None:
            try:
                self.eve_watcher_proc.terminate()
                self.eve_watcher_proc.wait(timeout=5)
            except:
                self.eve_watcher_proc.kill()
        
        # Cleanup any remaining processes
        for name in ["suricata", "soar_engine", "unified_logger", "eve_watcher", "inference_api"]:
            try:
                subprocess.run(["pkill", "-9", "-f", name], stderr=subprocess.DEVNULL)
            except:
                pass
        
        log("Pipeline stopped", "SUCCESS")


class LoadSimulator:
    """Simulates realistic network traffic and attacks"""
    
    def __init__(self, target_ip: str = "127.0.0.1"):
        self.target_ip = target_ip
        self.running = False
        self.threads = []
    
    def generate_http_traffic(self, duration: int):
        """Generate HTTP traffic"""
        import urllib.request
        
        end_time = time.time() + duration
        count = 0
        
        while time.time() < end_time and self.running:
            try:
                # Make HTTP requests
                urllib.request.urlopen(f"http://{self.target_ip}:8080", timeout=1)
                count += 1
            except:
                pass
            time.sleep(0.1)
        
        log(f"Generated {count} HTTP requests")
    
    def generate_attack_traffic(self, duration: int):
        """Simulate attack traffic using tools/attack_simulator.py

        One simulator pass only lasts a few seconds, so it is re-run until the
        load window closes. Its output goes to logs/attack_simulator.log and a
        failed pass is reported, rather than being discarded.
        """
        if not ATTACK_SIMULATOR.exists():
            log(f"Attack simulator not found at {ATTACK_SIMULATOR}", "WARNING")
            return
        
        command = build_attack_command(self.target_ip)
        end_time = time.time() + duration
        runs = 0
        failures = 0
        
        log("Generating attack traffic...")
        while self.running and time.time() < end_time:
            runs += 1
            
            try:
                with open(ATTACK_SIMULATOR_LOG, 'a') as log_file:
                    log_file.write(f"\n--- simulator pass {runs} ({datetime.now().isoformat()}) ---\n")
                    log_file.flush()
                    returncode = self._run_attack_pass(command, log_file, end_time)
            except OSError as e:
                log(f"Could not run the attack simulator: {e}", "ERROR")
                return
            
            if returncode is None:
                # The load window closed before the pass finished
                break
            if returncode != 0:
                failures += 1
                log(f"Attack simulator exited with code {returncode}, see {ATTACK_SIMULATOR_LOG}", "WARNING")
            
            if self.running and time.time() < end_time:
                time.sleep(ATTACK_GAP)
        
        if runs:
            log(f"Attack traffic: {runs} simulator pass(es), {failures} failed")
        else:
            log("No attack traffic generated", "WARNING")
    
    def _run_attack_pass(self, command: List[str], log_file, end_time: float) -> Optional[int]:
        """Run one simulator pass, stopping it when the load window closes

        Returns the exit code, or None if the pass was cut short by the deadline
        or by the load being stopped.
        """
        proc = subprocess.Popen(
            command,
            cwd=str(ROOT_DIR),
            stdout=log_file,
            stderr=subprocess.STDOUT
        )
        
        while True:
            try:
                return proc.wait(timeout=ATTACK_POLL_INTERVAL)
            except subprocess.TimeoutExpired:
                if not self.running or time.time() >= end_time:
                    proc.kill()
                    proc.wait()
                    return None
    
    def start(self, duration: int):
        """Start generating load"""
        self.running = True
        
        # Start HTTP traffic thread
        http_thread = threading.Thread(
            target=self.generate_http_traffic,
            args=(duration,),
            daemon=True
        )
        http_thread.start()
        self.threads.append(http_thread)
        
        # Start attack traffic (in background)
        attack_thread = threading.Thread(
            target=self.generate_attack_traffic,
            args=(duration,),
            daemon=True
        )
        attack_thread.start()
        self.threads.append(attack_thread)
        
        log("Load generation started", "SUCCESS")
    
    def stop(self):
        """Stop generating load"""
        self.running = False
        for thread in self.threads:
            thread.join(timeout=2)
        log("Load generation stopped")


def generate_visualizations(monitor: ResourceMonitor, output_dir: Path, timestamp: str):
    """Generate visualization graphs"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        log("matplotlib not installed - skipping visualizations", "WARNING")
        return
    
    if not monitor.snapshots:
        log("No snapshots to visualize", "WARNING")
        return
    
    log("Generating visualizations...")
    
    # Extract time series data
    elapsed_times = [s.elapsed_seconds for s in monitor.snapshots]
    cpu_values = [s.aggregated.get('total_cpu_percent', 0) for s in monitor.snapshots]
    mem_values = [s.aggregated.get('total_memory_mb', 0) for s in monitor.snapshots]
    thread_values = [s.aggregated.get('total_threads', 0) for s in monitor.snapshots]
    proc_counts = [s.aggregated.get('total_processes', 0) for s in monitor.snapshots]
    
    # Create dashboard with 4 subplots
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle('Vajra Resource Consumption Dashboard', fontsize=16, fontweight='bold')
    
    # Plot 1: CPU Usage Over Time
    ax1 = axes[0, 0]
    ax1.plot(elapsed_times, cpu_values, color='#e74c3c', linewidth=2)
    ax1.fill_between(elapsed_times, cpu_values, alpha=0.3, color='#e74c3c')
    ax1.set_xlabel('Time (seconds)')
    ax1.set_ylabel('CPU Usage (%)')
    ax1.set_title('CPU Usage Over Time')
    ax1.grid(True, alpha=0.3)
    
    # Add statistics
    avg_cpu = sum(cpu_values) / len(cpu_values)
    max_cpu = max(cpu_values)
    ax1.axhline(y=avg_cpu, color='orange', linestyle='--', label=f'Avg: {avg_cpu:.1f}%')
    ax1.axhline(y=max_cpu, color='red', linestyle='--', label=f'Max: {max_cpu:.1f}%')
    ax1.legend()
    
    # Plot 2: Memory Usage Over Time
    ax2 = axes[0, 1]
    ax2.plot(elapsed_times, mem_values, color='#3498db', linewidth=2)
    ax2.fill_between(elapsed_times, mem_values, alpha=0.3, color='#3498db')
    ax2.set_xlabel('Time (seconds)')
    ax2.set_ylabel('Memory (MB)')
    ax2.set_title('Memory Usage Over Time')
    ax2.grid(True, alpha=0.3)
    
    # Add statistics
    avg_mem = sum(mem_values) / len(mem_values)
    max_mem = max(mem_values)
    ax2.axhline(y=avg_mem, color='orange', linestyle='--', label=f'Avg: {avg_mem:.1f}MB')
    ax2.axhline(y=max_mem, color='red', linestyle='--', label=f'Max: {max_mem:.1f}MB')
    ax2.legend()
    
    # Plot 3: Thread Count Over Time
    ax3 = axes[1, 0]
    ax3.plot(elapsed_times, thread_values, color='#2ecc71', linewidth=2, marker='o', markersize=3)
    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Thread Count')
    ax3.set_title('Thread Count Over Time')
    ax3.grid(True, alpha=0.3)
    
    # Plot 4: Process Count Over Time
    ax4 = axes[1, 1]
    ax4.plot(elapsed_times, proc_counts, color='#9b59b6', linewidth=2, marker='s', markersize=3)
    ax4.set_xlabel('Time (seconds)')
    ax4.set_ylabel('Process Count')
    ax4.set_title('Vajra Process Count Over Time')
    ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    # Save dashboard
    dashboard_file = output_dir / f"rc_dashboard_{timestamp}.png"
    plt.savefig(dashboard_file, dpi=150, bbox_inches='tight')
    plt.close()
    
    log(f"Dashboard saved to: {dashboard_file}", "SUCCESS")
    
    # Create per-component breakdown
    if monitor.snapshots:
        create_component_breakdown(monitor.snapshots[-1], output_dir, timestamp)


def create_component_breakdown(snapshot, output_dir: Path, timestamp: str):
    """Create a breakdown chart by component"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        return
    
    by_type = snapshot.aggregated.get('by_process_type', {})
    if not by_type:
        return
    
    # Extract data
    names = list(by_type.keys())
    cpu_vals = [by_type[n]['cpu_percent'] for n in names]
    mem_vals = [by_type[n]['memory_mb'] for n in names]
    
    # Create figure with 2 subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Resource Usage by Component', fontsize=14, fontweight='bold')
    
    # CPU breakdown
    colors = plt.cm.Set3(range(len(names)))
    ax1.pie(cpu_vals, labels=names, autopct='%1.1f%%', colors=colors, startangle=90)
    ax1.set_title('CPU Usage Distribution')
    
    # Memory breakdown
    ax2.pie(mem_vals, labels=names, autopct='%1.1f%%', colors=colors, startangle=90)
    ax2.set_title('Memory Usage Distribution')
    
    plt.tight_layout()
    
    breakdown_file = output_dir / f"rc_component_breakdown_{timestamp}.png"
    plt.savefig(breakdown_file, dpi=150, bbox_inches='tight')
    plt.close()
    
    log(f"Component breakdown saved to: {breakdown_file}", "SUCCESS")


def run_rc_test():
    """Run the complete RC test"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    log("="*70, "HEADER")
    log("Vajra Resource Consumption (RC) Testing Suite", "HEADER")
    log("="*70, "HEADER")
    log(f"Test ID: {timestamp}")
    log(f"Output Directory: {OUTPUT_DIR}")
    
    # Initialize components
    pipeline = VajraPipelineManager()
    monitor = ResourceMonitor(interval=1.0, output_dir=str(OUTPUT_DIR))
    simulator = LoadSimulator()
    
    results = {
        'test_id': timestamp,
        'start_time': datetime.now().isoformat(),
        'phases': {},
        'summary': {}
    }
    
    try:
        # Phase 1: Start eve_watcher
        log("\n[Phase 1/5] Starting eve_watcher...", "HEADER")
        if not pipeline.start_eve_watcher():
            log("Failed to start eve_watcher, continuing anyway...", "WARNING")
        
        time.sleep(WARMUP_DURATION)
        
        # Phase 2: Start main pipeline
        log("\n[Phase 2/5] Starting Vajra pipeline...", "HEADER")
        if not pipeline.start_macos_pipeline():
            log("Failed to start pipeline", "ERROR")
            return
        
        # Start monitoring
        log("\n[Phase 3/5] Starting resource monitoring...", "HEADER")
        monitor.start()
        
        # Phase 3: Baseline measurement
        log(f"\n[Phase 4/5] Baseline measurement ({BASELINE_DURATION}s)...", "HEADER")
        time.sleep(BASELINE_DURATION)
        
        baseline_snapshot = monitor.snapshots[-1] if monitor.snapshots else None
        if baseline_snapshot:
            results['phases']['baseline'] = {
                'cpu_percent': baseline_snapshot.aggregated.get('total_cpu_percent', 0),
                'memory_mb': baseline_snapshot.aggregated.get('total_memory_mb', 0),
                'threads': baseline_snapshot.aggregated.get('total_threads', 0),
                'processes': baseline_snapshot.aggregated.get('total_processes', 0)
            }
        
        # Phase 4: Load testing
        log(f"\n[Phase 5/5] Load testing ({LOAD_DURATION}s)...", "HEADER")
        simulator.start(LOAD_DURATION)
        time.sleep(LOAD_DURATION)
        simulator.stop()
        
        load_snapshot = monitor.snapshots[-1] if monitor.snapshots else None
        if load_snapshot:
            results['phases']['load'] = {
                'cpu_percent': load_snapshot.aggregated.get('total_cpu_percent', 0),
                'memory_mb': load_snapshot.aggregated.get('total_memory_mb', 0),
                'threads': load_snapshot.aggregated.get('total_threads', 0),
                'processes': load_snapshot.aggregated.get('total_processes', 0)
            }
        
        # Cooldown
        log(f"\nCooldown ({COOLDOWN_DURATION}s)...", "INFO")
        time.sleep(COOLDOWN_DURATION)
        
        # Stop monitoring
        log("\nStopping monitoring...", "INFO")
        monitor.stop()
        
        # Generate summary
        summary = monitor.generate_summary()
        results['summary'] = summary
        results['end_time'] = datetime.now().isoformat()
        
        # Save results
        report_file = OUTPUT_DIR / f"rc_report_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        log(f"\nResults saved to: {report_file}", "SUCCESS")
        
        # Generate visualizations
        generate_visualizations(monitor, OUTPUT_DIR, timestamp)
        
        # Print summary
        print_summary(results)
        
    except KeyboardInterrupt:
        log("\nTest interrupted by user", "WARNING")
    
    except Exception as e:
        log(f"\nTest failed with error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        log("\nCleaning up...", "INFO")
        simulator.stop()
        monitor.stop()
        pipeline.stop_pipeline()
        
        log("\nRC Testing completed!", "SUCCESS")


def print_summary(results: Dict):
    """Print formatted summary"""
    summary = results.get('summary', {})
    
    log("\n" + "="*70, "HEADER")
    log("RESOURCE CONSUMPTION TEST SUMMARY", "HEADER")
    log("="*70, "HEADER")
    
    log(f"\nTest Duration: {summary.get('duration_seconds', 0):.1f}s")
    log(f"Total Snapshots: {summary.get('total_snapshots', 0)}")
    
    # CPU
    cpu = summary.get('cpu', {})
    log("\nCPU Usage:", "HEADER")
    log(f"  Min:    {cpu.get('min', 0):.1f}%")
    log(f"  Avg:    {cpu.get('avg', 0):.1f}%")
    log(f"  Max:    {cpu.get('max', 0):.1f}%")
    log(f"  P95:    {cpu.get('p95', 0):.1f}%")
    log(f"  P99:    {cpu.get('p99', 0):.1f}%")
    
    # Memory
    mem = summary.get('memory_mb', {})
    log("\nMemory Usage:", "HEADER")
    log(f"  Min:    {mem.get('min', 0):.1f} MB")
    log(f"  Avg:    {mem.get('avg', 0):.1f} MB")
    log(f"  Max:    {mem.get('max', 0):.1f} MB")
    log(f"  P95:    {mem.get('p95', 0):.1f} MB")
    log(f"  P99:    {mem.get('p99', 0):.1f} MB")
    
    # Threads
    threads = summary.get('threads', {})
    log("\nThread Count:", "HEADER")
    log(f"  Min:    {threads.get('min', 0)}")
    log(f"  Avg:    {threads.get('avg', 0):.1f}")
    log(f"  Max:    {threads.get('max', 0)}")
    
    # Processes
    procs = summary.get('processes', {})
    log("\nProcess Count:", "HEADER")
    log(f"  Min:    {procs.get('min', 0)}")
    log(f"  Avg:    {procs.get('avg', 0):.1f}")
    log(f"  Max:    {procs.get('max', 0)}")
    
    # Phase comparison
    phases = results.get('phases', {})
    if 'baseline' in phases and 'load' in phases:
        baseline = phases['baseline']
        load = phases['load']
        
        log("\nBaseline vs Load:", "HEADER")
        log(f"  CPU:      {baseline['cpu_percent']:.1f}% → {load['cpu_percent']:.1f}% "
            f"({((load['cpu_percent'] - baseline['cpu_percent']) / baseline['cpu_percent'] * 100) if baseline['cpu_percent'] > 0 else 0:.1f}% increase)")
        log(f"  Memory:   {baseline['memory_mb']:.1f}MB → {load['memory_mb']:.1f}MB "
            f"({((load['memory_mb'] - baseline['memory_mb']) / baseline['memory_mb'] * 100) if baseline['memory_mb'] > 0 else 0:.1f}% increase)")
    
    log("\n" + "="*70, "HEADER")


def main():
    """Main entry point"""
    # Check for root privileges
    if os.geteuid() != 0:
        log("This script requires root privileges (for Suricata)", "ERROR")
        log("Please run with: sudo python3 rc_test_runner.py", "ERROR")
        sys.exit(1)
    
    # Run the test
    run_rc_test()


if __name__ == "__main__":
    main()
