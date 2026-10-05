#!/usr/bin/env python3
"""
RC Test Results Analyzer and Visualizer

Analyzes existing RC test results and generates additional visualizations.

Usage:
    python3 analyze_results.py output/rc_report_20231209_123045.json
    python3 analyze_results.py --latest
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, List
import argparse

# Try to import matplotlib
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available. Install with: pip install matplotlib")


def find_latest_report(output_dir: Path = Path("output")) -> Path:
    """Find the most recent RC report"""
    reports = sorted(output_dir.glob("rc_report_*.json"), reverse=True)
    if not reports:
        raise FileNotFoundError("No RC reports found in output directory")
    return reports[0]


def load_report(report_file: Path) -> Dict[str, Any]:
    """Load RC report JSON"""
    with open(report_file) as f:
        return json.load(f)


def load_snapshots(output_dir: Path = Path("output")) -> List[Dict]:
    """Load resource snapshots"""
    snapshots_file = output_dir / "resource_snapshots.json"
    if snapshots_file.exists():
        with open(snapshots_file) as f:
            return json.load(f)
    return []


def print_summary(report: Dict[str, Any]):
    """Print formatted summary"""
    print("\n" + "="*70)
    print("RESOURCE CONSUMPTION TEST SUMMARY")
    print("="*70)
    
    print(f"\nTest ID: {report.get('test_id', 'N/A')}")
    print(f"Start Time: {report.get('start_time', 'N/A')}")
    print(f"End Time: {report.get('end_time', 'N/A')}")
    
    summary = report.get('summary', {})
    
    # Duration
    duration = summary.get('duration_seconds', 0)
    print(f"\nDuration: {duration:.1f}s ({duration/60:.1f} minutes)")
    print(f"Snapshots: {summary.get('total_snapshots', 0)}")
    
    # CPU
    cpu = summary.get('cpu', {})
    print("\nCPU Usage:")
    print(f"  Min:    {cpu.get('min', 0):>6.1f}%")
    print(f"  Avg:    {cpu.get('avg', 0):>6.1f}%")
    print(f"  Max:    {cpu.get('max', 0):>6.1f}%")
    print(f"  P50:    {cpu.get('p50', 0):>6.1f}%")
    print(f"  P95:    {cpu.get('p95', 0):>6.1f}%")
    print(f"  P99:    {cpu.get('p99', 0):>6.1f}%")
    
    # Memory
    mem = summary.get('memory_mb', {})
    print("\nMemory Usage (MB):")
    print(f"  Min:    {mem.get('min', 0):>7.1f}")
    print(f"  Avg:    {mem.get('avg', 0):>7.1f}")
    print(f"  Max:    {mem.get('max', 0):>7.1f}")
    print(f"  P50:    {mem.get('p50', 0):>7.1f}")
    print(f"  P95:    {mem.get('p95', 0):>7.1f}")
    print(f"  P99:    {mem.get('p99', 0):>7.1f}")
    
    # Threads
    threads = summary.get('threads', {})
    print("\nThread Count:")
    print(f"  Min:    {threads.get('min', 0):>3.0f}")
    print(f"  Avg:    {threads.get('avg', 0):>6.1f}")
    print(f"  Max:    {threads.get('max', 0):>3.0f}")
    
    # Processes
    procs = summary.get('processes', {})
    print("\nProcess Count:")
    print(f"  Min:    {procs.get('min', 0):>3.0f}")
    print(f"  Avg:    {procs.get('avg', 0):>6.1f}")
    print(f"  Max:    {procs.get('max', 0):>3.0f}")
    
    # Phase comparison
    phases = report.get('phases', {})
    if 'baseline' in phases and 'load' in phases:
        baseline = phases['baseline']
        load = phases['load']
        
        print("\n" + "="*70)
        print("BASELINE vs LOAD COMPARISON")
        print("="*70)
        
        # CPU
        cpu_base = baseline.get('cpu_percent', 0)
        cpu_load = load.get('cpu_percent', 0)
        cpu_increase = ((cpu_load - cpu_base) / cpu_base * 100) if cpu_base > 0 else 0
        print(f"\nCPU:      {cpu_base:>6.1f}% → {cpu_load:>6.1f}%  ({cpu_increase:+.1f}% change)")
        
        # Memory
        mem_base = baseline.get('memory_mb', 0)
        mem_load = load.get('memory_mb', 0)
        mem_increase = ((mem_load - mem_base) / mem_base * 100) if mem_base > 0 else 0
        print(f"Memory:   {mem_base:>6.1f}MB → {mem_load:>6.1f}MB  ({mem_increase:+.1f}% change)")
        
        # Threads
        thr_base = baseline.get('threads', 0)
        thr_load = load.get('threads', 0)
        print(f"Threads:  {thr_base:>3.0f} → {thr_load:>3.0f}  ({thr_load - thr_base:+.0f})")
        
        # Processes
        proc_base = baseline.get('processes', 0)
        proc_load = load.get('processes', 0)
        print(f"Processes:  {proc_base:>2.0f} → {proc_load:>2.0f}  ({proc_load - proc_base:+.0f})")
    
    print("\n" + "="*70)


def generate_advanced_visualizations(snapshots: List[Dict], output_dir: Path, test_id: str):
    """Generate advanced visualization charts"""
    if not HAS_MATPLOTLIB:
        print("Cannot generate visualizations - matplotlib not installed")
        return
    
    if not snapshots:
        print("No snapshots available for visualization")
        return
    
    print("\nGenerating advanced visualizations...")
    
    # Extract time series
    times = [s['elapsed_seconds'] for s in snapshots]
    cpu_vals = [s['aggregated'].get('total_cpu_percent', 0) for s in snapshots]
    mem_vals = [s['aggregated'].get('total_memory_mb', 0) for s in snapshots]
    
    # Extract system-wide metrics
    sys_cpu = [s['system']['cpu_percent_total'] for s in snapshots]
    sys_mem_used = [s['system']['memory_used_mb'] for s in snapshots]
    sys_mem_total = snapshots[0]['system']['memory_total_mb']
    
    # Create comprehensive analysis figure
    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
    
    # 1. CPU Usage (Vajra vs System)
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.plot(times, cpu_vals, label='Vajra Processes', color='#e74c3c', linewidth=2)
    ax1.plot(times, sys_cpu, label='System Total', color='#95a5a6', linewidth=1.5, linestyle='--')
    ax1.fill_between(times, cpu_vals, alpha=0.3, color='#e74c3c')
    ax1.set_xlabel('Time (seconds)')
    ax1.set_ylabel('CPU Usage (%)')
    ax1.set_title('CPU Usage: Vajra vs System Total')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. CPU Distribution (box plot)
    ax2 = fig.add_subplot(gs[0, 2])
    bp = ax2.boxplot([cpu_vals], labels=['CPU %'], patch_artist=True)
    bp['boxes'][0].set_facecolor('#e74c3c')
    ax2.set_ylabel('CPU Usage (%)')
    ax2.set_title('CPU Distribution')
    ax2.grid(True, alpha=0.3, axis='y')
    
    # 3. Memory Usage (Vajra vs System)
    ax3 = fig.add_subplot(gs[1, :2])
    ax3.plot(times, mem_vals, label='Vajra Processes', color='#3498db', linewidth=2)
    ax3.plot(times, sys_mem_used, label='System Total', color='#95a5a6', linewidth=1.5, linestyle='--')
    ax3.fill_between(times, mem_vals, alpha=0.3, color='#3498db')
    ax3.axhline(y=sys_mem_total, color='red', linestyle=':', label=f'Total RAM ({sys_mem_total:.0f}MB)')
    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Memory (MB)')
    ax3.set_title('Memory Usage: Vajra vs System Total')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # 4. Memory Distribution (box plot)
    ax4 = fig.add_subplot(gs[1, 2])
    bp = ax4.boxplot([mem_vals], labels=['Memory MB'], patch_artist=True)
    bp['boxes'][0].set_facecolor('#3498db')
    ax4.set_ylabel('Memory (MB)')
    ax4.set_title('Memory Distribution')
    ax4.grid(True, alpha=0.3, axis='y')
    
    # 5. Resource Efficiency (CPU vs Memory scatter)
    ax5 = fig.add_subplot(gs[2, 0])
    scatter = ax5.scatter(cpu_vals, mem_vals, c=times, cmap='viridis', alpha=0.6, s=30)
    ax5.set_xlabel('CPU Usage (%)')
    ax5.set_ylabel('Memory (MB)')
    ax5.set_title('Resource Efficiency\n(Color = Time)')
    ax5.grid(True, alpha=0.3)
    plt.colorbar(scatter, ax=ax5, label='Time (s)')
    
    # 6. Resource Growth Rate
    ax6 = fig.add_subplot(gs[2, 1])
    if len(cpu_vals) > 1:
        cpu_diff = np.diff(cpu_vals)
        mem_diff = np.diff(mem_vals)
        ax6.plot(times[1:], cpu_diff, label='CPU Δ', color='#e74c3c', alpha=0.7)
        ax6_twin = ax6.twinx()
        ax6_twin.plot(times[1:], mem_diff, label='Mem Δ', color='#3498db', alpha=0.7)
        ax6.set_xlabel('Time (seconds)')
        ax6.set_ylabel('CPU Change (%)', color='#e74c3c')
        ax6_twin.set_ylabel('Memory Change (MB)', color='#3498db')
        ax6.set_title('Resource Growth Rate')
        ax6.grid(True, alpha=0.3)
        ax6.legend(loc='upper left')
        ax6_twin.legend(loc='upper right')
    
    # 7. Summary Statistics Table
    ax7 = fig.add_subplot(gs[2, 2])
    ax7.axis('off')
    
    stats_data = [
        ['Metric', 'Min', 'Avg', 'Max'],
        ['CPU %', f'{min(cpu_vals):.1f}', f'{np.mean(cpu_vals):.1f}', f'{max(cpu_vals):.1f}'],
        ['Mem MB', f'{min(mem_vals):.1f}', f'{np.mean(mem_vals):.1f}', f'{max(mem_vals):.1f}'],
        ['', '', '', ''],
        ['P95 CPU', '', f'{np.percentile(cpu_vals, 95):.1f}%', ''],
        ['P95 Mem', '', f'{np.percentile(mem_vals, 95):.1f}MB', ''],
    ]
    
    table = ax7.table(cellText=stats_data, loc='center', cellLoc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 2)
    
    # Style header row
    for i in range(4):
        table[(0, i)].set_facecolor('#34495e')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    ax7.set_title('Summary Statistics', pad=20)
    
    plt.suptitle(f'Vajra Resource Consumption Analysis - {test_id}', 
                 fontsize=16, fontweight='bold', y=0.98)
    
    # Save
    output_file = output_dir / f"rc_analysis_{test_id}.png"
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"Analysis saved to: {output_file}")


def compare_reports(report1_file: Path, report2_file: Path):
    """Compare two RC test reports"""
    print("\n" + "="*70)
    print("COMPARING TWO RC TEST REPORTS")
    print("="*70)
    
    r1 = load_report(report1_file)
    r2 = load_report(report2_file)
    
    print(f"\nReport 1: {report1_file.name}")
    print(f"  Test ID: {r1.get('test_id', 'N/A')}")
    print(f"  Time: {r1.get('start_time', 'N/A')}")
    
    print(f"\nReport 2: {report2_file.name}")
    print(f"  Test ID: {r2.get('test_id', 'N/A')}")
    print(f"  Time: {r2.get('start_time', 'N/A')}")
    
    # Compare summaries
    s1 = r1.get('summary', {})
    s2 = r2.get('summary', {})
    
    print("\n" + "-"*70)
    print("CPU Comparison:")
    print("-"*70)
    cpu1 = s1.get('cpu', {})
    cpu2 = s2.get('cpu', {})
    
    for metric in ['min', 'avg', 'max', 'p95', 'p99']:
        v1 = cpu1.get(metric, 0)
        v2 = cpu2.get(metric, 0)
        diff = v2 - v1
        pct = (diff / v1 * 100) if v1 > 0 else 0
        
        symbol = "higher" if diff > 5 else "lower" if diff < -5 else "similar"
        print(f"  {metric:4s}: {v1:6.1f}% → {v2:6.1f}%  ({diff:+6.1f}%, {pct:+5.1f}%) {symbol}")
    
    print("\n" + "-"*70)
    print("Memory Comparison:")
    print("-"*70)
    mem1 = s1.get('memory_mb', {})
    mem2 = s2.get('memory_mb', {})
    
    for metric in ['min', 'avg', 'max', 'p95', 'p99']:
        v1 = mem1.get(metric, 0)
        v2 = mem2.get(metric, 0)
        diff = v2 - v1
        pct = (diff / v1 * 100) if v1 > 0 else 0
        
        symbol = "higher" if diff > 50 else "lower" if diff < -50 else "similar"
        print(f"  {metric:4s}: {v1:7.1f}MB → {v2:7.1f}MB  ({diff:+7.1f}MB, {pct:+5.1f}%) {symbol}")
    
    print("\n" + "="*70)


def main():
    parser = argparse.ArgumentParser(description="Analyze RC test results")
    parser.add_argument("report", nargs='?', help="Path to RC report JSON file")
    parser.add_argument("--latest", action="store_true", help="Analyze latest report")
    parser.add_argument("--compare", nargs=2, metavar=('REPORT1', 'REPORT2'), 
                        help="Compare two reports")
    parser.add_argument("--visualize", action="store_true", help="Generate advanced visualizations")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    
    if args.compare:
        # Compare mode
        report1 = Path(args.compare[0])
        report2 = Path(args.compare[1])
        
        if not report1.exists() or not report2.exists():
            print(f"Error: One or both report files not found")
            sys.exit(1)
        
        compare_reports(report1, report2)
    
    elif args.latest or args.report:
        # Analyze single report
        if args.latest:
            report_file = find_latest_report(output_dir)
            print(f"Analyzing latest report: {report_file}")
        else:
            report_file = Path(args.report)
        
        if not report_file.exists():
            print(f"Error: Report file not found: {report_file}")
            sys.exit(1)
        
        report = load_report(report_file)
        print_summary(report)
        
        if args.visualize:
            snapshots = load_snapshots(output_dir)
            if snapshots:
                test_id = report.get('test_id', 'unknown')
                generate_advanced_visualizations(snapshots, output_dir, test_id)
            else:
                print("\nWarning: No snapshots found for visualization")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
