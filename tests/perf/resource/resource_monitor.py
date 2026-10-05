#!/usr/bin/env python3
"""
Resource Consumption Monitor for NGFW Pipeline

Monitors real-time resource consumption of the entire NGFW pipeline:
- eve_watcher
- start_macos.sh components (Suricata, SOAR, Inference API, Unified Logger, etc.)
- ML Models loading and inference
- Federated Learning operations
- Packet inspection and processing

Tracks:
- CPU usage per process
- Memory (RSS, VMS) per process
- Disk I/O
- Network I/O
- Thread counts
- File descriptors
- GPU usage (if available)
"""

import os
import sys
import time
import json
import psutil
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import threading

# Add parent directory to path
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(ROOT_DIR))

@dataclass
class ProcessMetrics:
    """Metrics for a single process"""
    pid: int
    name: str
    cmdline: str
    cpu_percent: float
    memory_rss_mb: float
    memory_vms_mb: float
    memory_percent: float
    num_threads: int
    num_fds: int
    io_read_mb: float
    io_write_mb: float
    net_sent_mb: float
    net_recv_mb: float
    create_time: float
    status: str

@dataclass
class SystemMetrics:
    """System-wide metrics"""
    timestamp: str
    cpu_percent_total: float
    cpu_percent_per_core: List[float]
    memory_total_mb: float
    memory_used_mb: float
    memory_percent: float
    swap_used_mb: float
    disk_read_mb: float
    disk_write_mb: float
    net_sent_mb: float
    net_recv_mb: float
    load_average: List[float]
    disk_usage_percent: float

@dataclass
class ResourceSnapshot:
    """Complete snapshot of resource consumption"""
    timestamp: str
    elapsed_seconds: float
    system: SystemMetrics
    processes: Dict[str, ProcessMetrics]
    aggregated: Dict[str, Any]


class ResourceMonitor:
    """Real-time resource consumption monitor"""
    
    def __init__(self, interval: float = 1.0, output_dir: str = "output"):
        self.interval = interval
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.running = False
        self.start_time = None
        self.snapshots: List[ResourceSnapshot] = []
        
        # Track process names we care about
        self.tracked_names = [
            "eve_watcher",
            "suricata",
            "soar_engine",
            "unified_logger",
            "inference_api",
            "packet_inspector",
            "kafka_bridge",
            "fl_client",
            "fl_server",
            "python3",  # Generic Python processes
        ]
        
        # Baseline metrics (first snapshot)
        self.baseline_io = None
        self.baseline_net = None
        
        # Thread for monitoring
        self.monitor_thread = None
        
        print(f"[ResourceMonitor] Initialized with {interval}s interval")
        print(f"[ResourceMonitor] Output directory: {self.output_dir}")
    
    def get_process_metrics(self, proc: psutil.Process) -> Optional[ProcessMetrics]:
        """Get metrics for a single process"""
        try:
            with proc.oneshot():
                # Basic info
                pid = proc.pid
                name = proc.name()
                try:
                    cmdline = " ".join(proc.cmdline()[:5])  # First 5 args
                except:
                    cmdline = name
                
                # CPU
                cpu_percent = proc.cpu_percent()
                
                # Memory
                mem = proc.memory_info()
                mem_rss_mb = mem.rss / (1024 * 1024)
                mem_vms_mb = mem.vms / (1024 * 1024)
                mem_percent = proc.memory_percent()
                
                # Threads
                num_threads = proc.num_threads()
                
                # File descriptors
                try:
                    num_fds = proc.num_fds()
                except:
                    num_fds = 0
                
                # I/O
                try:
                    io = proc.io_counters()
                    io_read_mb = io.read_bytes / (1024 * 1024)
                    io_write_mb = io.write_bytes / (1024 * 1024)
                except:
                    io_read_mb = 0
                    io_write_mb = 0
                
                # Network (system-wide, not per-process)
                net_sent_mb = 0
                net_recv_mb = 0
                
                # Status
                create_time = proc.create_time()
                status = proc.status()
                
                return ProcessMetrics(
                    pid=pid,
                    name=name,
                    cmdline=cmdline,
                    cpu_percent=cpu_percent,
                    memory_rss_mb=mem_rss_mb,
                    memory_vms_mb=mem_vms_mb,
                    memory_percent=mem_percent,
                    num_threads=num_threads,
                    num_fds=num_fds,
                    io_read_mb=io_read_mb,
                    io_write_mb=io_write_mb,
                    net_sent_mb=net_sent_mb,
                    net_recv_mb=net_recv_mb,
                    create_time=create_time,
                    status=status
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get system-wide metrics"""
        # CPU
        cpu_percent_total = psutil.cpu_percent(interval=0)
        cpu_percent_per_core = psutil.cpu_percent(interval=0, percpu=True)
        
        # Memory
        mem = psutil.virtual_memory()
        memory_total_mb = mem.total / (1024 * 1024)
        memory_used_mb = mem.used / (1024 * 1024)
        memory_percent = mem.percent
        
        # Swap
        swap = psutil.swap_memory()
        swap_used_mb = swap.used / (1024 * 1024)
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        disk_read_mb = disk_io.read_bytes / (1024 * 1024) if disk_io else 0
        disk_write_mb = disk_io.write_bytes / (1024 * 1024) if disk_io else 0
        
        # Network I/O
        net_io = psutil.net_io_counters()
        net_sent_mb = net_io.bytes_sent / (1024 * 1024) if net_io else 0
        net_recv_mb = net_io.bytes_recv / (1024 * 1024) if net_io else 0
        
        # Load average (Unix-like systems)
        try:
            load_avg = list(os.getloadavg())
        except:
            load_avg = [0, 0, 0]
        
        # Disk usage
        disk_usage = psutil.disk_usage('/')
        disk_usage_percent = disk_usage.percent
        
        return SystemMetrics(
            timestamp=datetime.now().isoformat(),
            cpu_percent_total=cpu_percent_total,
            cpu_percent_per_core=cpu_percent_per_core,
            memory_total_mb=memory_total_mb,
            memory_used_mb=memory_used_mb,
            memory_percent=memory_percent,
            swap_used_mb=swap_used_mb,
            disk_read_mb=disk_read_mb,
            disk_write_mb=disk_write_mb,
            net_sent_mb=net_sent_mb,
            net_recv_mb=net_recv_mb,
            load_average=load_avg,
            disk_usage_percent=disk_usage_percent
        )
    
    def find_ngfw_processes(self) -> List[psutil.Process]:
        """Find all NGFW-related processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                # Check if process is related to NGFW
                for tracked in self.tracked_names:
                    if tracked.lower() in name or tracked.lower() in cmdline:
                        processes.append(proc)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def take_snapshot(self) -> ResourceSnapshot:
        """Take a snapshot of current resource consumption"""
        timestamp = datetime.now().isoformat()
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        # System metrics
        system = self.get_system_metrics()
        
        # Process metrics
        processes = {}
        ngfw_procs = self.find_ngfw_processes()
        
        for proc in ngfw_procs:
            metrics = self.get_process_metrics(proc)
            if metrics:
                # Use a unique key combining name and pid
                key = f"{metrics.name}_{metrics.pid}"
                processes[key] = metrics
        
        # Aggregated metrics
        aggregated = self.aggregate_metrics(processes)
        
        snapshot = ResourceSnapshot(
            timestamp=timestamp,
            elapsed_seconds=elapsed,
            system=system,
            processes=processes,
            aggregated=aggregated
        )
        
        return snapshot
    
    def aggregate_metrics(self, processes: Dict[str, ProcessMetrics]) -> Dict[str, Any]:
        """Aggregate metrics across all NGFW processes"""
        if not processes:
            return {}
        
        total_cpu = sum(p.cpu_percent for p in processes.values())
        total_memory_mb = sum(p.memory_rss_mb for p in processes.values())
        total_threads = sum(p.num_threads for p in processes.values())
        total_fds = sum(p.num_fds for p in processes.values())
        total_io_read = sum(p.io_read_mb for p in processes.values())
        total_io_write = sum(p.io_write_mb for p in processes.values())
        
        # Group by process type
        by_type = defaultdict(lambda: {
            'count': 0,
            'cpu_percent': 0,
            'memory_mb': 0,
            'threads': 0
        })
        
        for proc in processes.values():
            # Extract base name (without _pid)
            base_name = proc.name
            by_type[base_name]['count'] += 1
            by_type[base_name]['cpu_percent'] += proc.cpu_percent
            by_type[base_name]['memory_mb'] += proc.memory_rss_mb
            by_type[base_name]['threads'] += proc.num_threads
        
        return {
            'total_processes': len(processes),
            'total_cpu_percent': total_cpu,
            'total_memory_mb': total_memory_mb,
            'total_threads': total_threads,
            'total_fds': total_fds,
            'total_io_read_mb': total_io_read,
            'total_io_write_mb': total_io_write,
            'by_process_type': dict(by_type)
        }
    
    def monitor_loop(self):
        """Main monitoring loop"""
        print(f"[ResourceMonitor] Starting monitoring loop (interval={self.interval}s)")
        
        while self.running:
            try:
                snapshot = self.take_snapshot()
                self.snapshots.append(snapshot)
                
                # Print summary
                agg = snapshot.aggregated
                print(f"[{snapshot.elapsed_seconds:>6.1f}s] "
                      f"Procs={agg.get('total_processes', 0):>2} "
                      f"CPU={agg.get('total_cpu_percent', 0):>6.1f}% "
                      f"Mem={agg.get('total_memory_mb', 0):>7.1f}MB "
                      f"Threads={agg.get('total_threads', 0):>3} "
                      f"FDs={agg.get('total_fds', 0):>4}")
                
                # Save snapshot to file every 10 iterations
                if len(self.snapshots) % 10 == 0:
                    self.save_snapshots()
                
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"[ResourceMonitor] Error in monitor loop: {e}")
                time.sleep(self.interval)
        
        print("[ResourceMonitor] Monitoring loop stopped")
    
    def start(self):
        """Start monitoring"""
        if self.running:
            print("[ResourceMonitor] Already running!")
            return
        
        self.running = True
        self.start_time = time.time()
        
        # Take baseline snapshot
        baseline = self.take_snapshot()
        self.snapshots.append(baseline)
        print(f"[ResourceMonitor] Baseline snapshot taken")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print(f"[ResourceMonitor] Monitoring started")
    
    def stop(self):
        """Stop monitoring"""
        if not self.running:
            return
        
        print("[ResourceMonitor] Stopping monitoring...")
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        # Save final snapshots
        self.save_snapshots()
        
        print(f"[ResourceMonitor] Stopped. Collected {len(self.snapshots)} snapshots")
    
    def save_snapshots(self):
        """Save snapshots to JSON file"""
        output_file = self.output_dir / "resource_snapshots.json"
        
        # Convert snapshots to dict
        snapshots_dict = []
        for snapshot in self.snapshots:
            snapshot_dict = {
                'timestamp': snapshot.timestamp,
                'elapsed_seconds': snapshot.elapsed_seconds,
                'system': asdict(snapshot.system),
                'processes': {k: asdict(v) for k, v in snapshot.processes.items()},
                'aggregated': snapshot.aggregated
            }
            snapshots_dict.append(snapshot_dict)
        
        with open(output_file, 'w') as f:
            json.dump(snapshots_dict, f, indent=2)
        
        print(f"[ResourceMonitor] Saved {len(snapshots_dict)} snapshots to {output_file}")
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics from all snapshots"""
        if not self.snapshots:
            return {}
        
        cpu_values = [s.aggregated.get('total_cpu_percent', 0) for s in self.snapshots]
        mem_values = [s.aggregated.get('total_memory_mb', 0) for s in self.snapshots]
        thread_values = [s.aggregated.get('total_threads', 0) for s in self.snapshots]
        proc_counts = [s.aggregated.get('total_processes', 0) for s in self.snapshots]
        
        summary = {
            'total_snapshots': len(self.snapshots),
            'duration_seconds': self.snapshots[-1].elapsed_seconds if self.snapshots else 0,
            'cpu': {
                'min': min(cpu_values),
                'max': max(cpu_values),
                'avg': sum(cpu_values) / len(cpu_values),
                'p50': sorted(cpu_values)[len(cpu_values) // 2],
                'p95': sorted(cpu_values)[int(len(cpu_values) * 0.95)],
                'p99': sorted(cpu_values)[int(len(cpu_values) * 0.99)]
            },
            'memory_mb': {
                'min': min(mem_values),
                'max': max(mem_values),
                'avg': sum(mem_values) / len(mem_values),
                'p50': sorted(mem_values)[len(mem_values) // 2],
                'p95': sorted(mem_values)[int(len(mem_values) * 0.95)],
                'p99': sorted(mem_values)[int(len(mem_values) * 0.99)]
            },
            'threads': {
                'min': min(thread_values),
                'max': max(thread_values),
                'avg': sum(thread_values) / len(thread_values)
            },
            'processes': {
                'min': min(proc_counts),
                'max': max(proc_counts),
                'avg': sum(proc_counts) / len(proc_counts)
            }
        }
        
        return summary


def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print("\n[ResourceMonitor] Received interrupt signal")
    sys.exit(0)


def main():
    """Main entry point for standalone monitoring"""
    import argparse
    
    parser = argparse.ArgumentParser(description="NGFW Resource Monitor")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds")
    parser.add_argument("--duration", type=int, default=60, help="Duration to monitor in seconds")
    parser.add_argument("--output", type=str, default="output", help="Output directory")
    
    args = parser.parse_args()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    monitor = ResourceMonitor(interval=args.interval, output_dir=args.output)
    monitor.start()
    
    print(f"\n[ResourceMonitor] Monitoring for {args.duration} seconds...")
    print("[ResourceMonitor] Press Ctrl+C to stop early\n")
    
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[ResourceMonitor] Interrupted by user")
    
    monitor.stop()
    
    # Generate and print summary
    summary = monitor.generate_summary()
    print("\n" + "="*70)
    print("RESOURCE CONSUMPTION SUMMARY")
    print("="*70)
    print(f"Duration: {summary.get('duration_seconds', 0):.1f}s")
    print(f"Snapshots: {summary.get('total_snapshots', 0)}")
    print(f"\nCPU Usage:")
    print(f"  Min: {summary['cpu']['min']:.1f}%")
    print(f"  Avg: {summary['cpu']['avg']:.1f}%")
    print(f"  Max: {summary['cpu']['max']:.1f}%")
    print(f"  P95: {summary['cpu']['p95']:.1f}%")
    print(f"\nMemory Usage (MB):")
    print(f"  Min: {summary['memory_mb']['min']:.1f}")
    print(f"  Avg: {summary['memory_mb']['avg']:.1f}")
    print(f"  Max: {summary['memory_mb']['max']:.1f}")
    print(f"  P95: {summary['memory_mb']['p95']:.1f}")
    print(f"\nThreads:")
    print(f"  Min: {summary['threads']['min']}")
    print(f"  Avg: {summary['threads']['avg']:.1f}")
    print(f"  Max: {summary['threads']['max']}")
    print("="*70)
    
    # Save summary
    summary_file = Path(args.output) / "resource_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to: {summary_file}")


if __name__ == "__main__":
    main()
