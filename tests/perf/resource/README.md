# Vajra Resource Consumption (RC) Testing

Comprehensive resource consumption testing framework for the Next-Generation Firewall (Vajra) pipeline.

## Overview

This testing suite monitors and analyzes the resource consumption of the entire Vajra pipeline including:

### Pipeline Components Tested

1. **eve_watcher** - WebSocket streaming service for real-time event monitoring
2. **start_macos.sh Pipeline**:
   - **Suricata IDS** - Network intrusion detection system
   - **SOAR Engine** - Security Orchestration and Automated Response with ML integration
   - **Packet Inspector** - Deep packet inspection with ML feature extraction
   - **Inference API** - Federated Learning model serving (port 8001)
   - **Unified Logger** - Centralized logging system
   - **Kafka Bridge** - Event streaming bridge
   - **Multiple ML Models** - Real-time threat detection models

### Resources Monitored

- **CPU Usage**: Per-process and aggregate CPU consumption
- **Memory Usage**: RSS (Resident Set Size) and VMS (Virtual Memory Size)
- **Thread Count**: Number of threads per process
- **File Descriptors**: Open file handles
- **Disk I/O**: Read/Write operations in MB
- **Network I/O**: Sent/Received data in MB
- **Process Count**: Number of active Vajra processes

## Quick Start

### Prerequisites

1. **Root Access**: Required for starting Suricata
2. **Python 3.7+** with packages:
   - `psutil` (required)
   - `matplotlib` (optional, for visualizations)
3. **Vajra Pipeline**: All components must be available in parent directory

### Installation

```bash
# Install required Python packages
pip install psutil matplotlib
```

### Running RC Tests

**Option 1: Bash Script (Recommended)**

```bash
# Make script executable
chmod +x run_rc_tests.sh

# Run RC tests
sudo ./run_rc_tests.sh
```

**Option 2: Python Script**

```bash
# Run directly with Python
sudo python3 rc_test_runner.py
```

**Option 3: Standalone Monitor**

```bash
# Monitor for 60 seconds with 1s interval
sudo python3 resource_monitor.py --duration 60 --interval 1.0
```

## Test Workflow

The RC test follows this sequence:

```
1. Warmup (10s)
   ├─ Start eve_watcher
   └─ Initialize monitoring
   
2. Pipeline Startup (15s)
   ├─ Run start_macos.sh
   ├─ Wait for Suricata
   ├─ Wait for SOAR Engine
   └─ Wait for other components
   
3. Baseline Measurement (30s)
   ├─ Monitor idle resource consumption
   └─ Establish performance baseline
   
4. Load Testing (60s)
   ├─ Generate HTTP traffic
   ├─ Simulate attack patterns
   └─ Monitor under load
   
5. Cooldown (10s)
   ├─ Stop load generation
   └─ Final measurements
   
6. Cleanup
   ├─ Stop all components
   └─ Generate reports
```

## Output Files

All output files are saved in `tests/perf/resource/output/` with timestamps:

### JSON Reports

- **`rc_report_TIMESTAMP.json`** - Complete test results including:
  - Test metadata (ID, start/end time)
  - Phase-wise metrics (baseline, load)
  - Summary statistics (min, max, avg, P95, P99)
  - Resource snapshots

- **`resource_snapshots.json`** - Raw time-series data:
  - All resource snapshots taken during test
  - Per-process metrics
  - System-wide metrics
  - 1-second granularity

- **`resource_summary.json`** - Statistical summary:
  - CPU, Memory, Thread statistics
  - Percentile analysis (P50, P95, P99)

### Visualizations

- **`rc_dashboard_TIMESTAMP.png`** - Main dashboard with 4 graphs:
  1. CPU usage over time
  2. Memory usage over time
  3. Thread count over time
  4. Process count over time

- **`rc_component_breakdown_TIMESTAMP.png`** - Pie charts showing:
  1. CPU distribution by component
  2. Memory distribution by component

### Logs

All detailed logs are saved in `tests/perf/resource/logs/`:
- `eve_watcher.log` - eve_watcher output
- `start_macos.log` - Pipeline startup logs

## Understanding the Results

### CPU Usage

- **Min/Avg/Max**: Range of CPU consumption
- **P95/P99**: 95th and 99th percentile (spikes)
- **Expected Values**:
  - Idle: 5-15%
  - Under load: 20-50%
  - Peak: < 80%

### Memory Usage

- **RSS (Resident Set Size)**: Actual physical memory used
- **VMS (Virtual Memory Size)**: Virtual memory allocated
- **Expected Values**:
  - Baseline: 200-500 MB
  - Under load: 500-1000 MB
  - ML models loaded: +100-300 MB per model

### Key Metrics

1. **Process Count**: Should be 5-10 (Suricata, SOAR, Logger, etc.)
2. **Thread Count**: Should be 20-50 total
3. **File Descriptors**: Should be < 1000
4. **I/O Operations**: Varies with traffic volume

### Performance Indicators

**Good Performance**:
- CPU < 60% under load
- Memory growth < 50% during test
- No process crashes
- Stable thread count

**Warning Signs**:
- CPU > 80% sustained
- Memory growing continuously (leak)
- Increasing file descriptors
- Process count fluctuating

**Critical Issues**:
- CPU pinned at 100%
- Memory exhaustion (swap usage)
- Process crashes
- File descriptor exhaustion

## Customization

### Modify Test Duration

Edit `rc_test_runner.py` and change these constants:

```python
WARMUP_DURATION = 10      # Warmup time in seconds
BASELINE_DURATION = 30    # Baseline measurement time
LOAD_DURATION = 60        # Load testing time
COOLDOWN_DURATION = 10    # Cooldown time
```

### Change Sampling Interval

```bash
# Monitor with 0.5s interval (higher granularity)
sudo python3 resource_monitor.py --interval 0.5 --duration 60

# Monitor with 5s interval (lower overhead)
sudo python3 resource_monitor.py --interval 5.0 --duration 300
```

### Custom Load Patterns

Edit the `LoadSimulator` class in `rc_test_runner.py` to customize:
- HTTP request rate
- Attack patterns
- Traffic volume
- Test scenarios

## Troubleshooting

### "psutil not installed"
```bash
pip install psutil
```

### "Must run as root"
```bash
# Run with sudo
sudo ./run_rc_tests.sh
```

### "matplotlib not installed" (visualizations fail)
```bash
# Install matplotlib (optional)
pip install matplotlib

# Or run without visualizations
sudo python3 resource_monitor.py --duration 60
```

### Pipeline fails to start
1. Check if ports are available (8000, 8001, 8080)
2. Verify Suricata is installed: `which suricata`
3. Check logs in `tests/perf/resource/logs/`
4. Ensure you have network interface access

### No processes found
1. Wait longer for pipeline startup (15s may not be enough)
2. Check if components are running: `ps aux | grep -E "suricata|soar_engine"`
3. Verify start_macos.sh works independently

## Advanced Usage

### Monitor Only (No Pipeline Control)

If pipeline is already running:

```python
from resource_monitor import ResourceMonitor

monitor = ResourceMonitor(interval=1.0)
monitor.start()
time.sleep(60)  # Monitor for 60s
monitor.stop()

summary = monitor.generate_summary()
print(summary)
```

### Export Data for Analysis

```python
import json

# Load snapshots
with open('output/resource_snapshots.json') as f:
    snapshots = json.load(f)

# Analyze
for snapshot in snapshots:
    cpu = snapshot['aggregated']['total_cpu_percent']
    mem = snapshot['aggregated']['total_memory_mb']
    print(f"Time: {snapshot['elapsed_seconds']}s, CPU: {cpu}%, Mem: {mem}MB")
```

### Compare Multiple Test Runs

```bash
# Run baseline test
sudo ./run_rc_tests.sh
mv output/rc_report_*.json output/baseline_test.json

# Make configuration changes
# ...

# Run comparison test
sudo ./run_rc_tests.sh
mv output/rc_report_*.json output/optimized_test.json

# Compare results
python3 -c "
import json
with open('output/baseline_test.json') as f: baseline = json.load(f)
with open('output/optimized_test.json') as f: optimized = json.load(f)
print(f'CPU Baseline: {baseline[\"summary\"][\"cpu\"][\"avg\"]:.1f}%')
print(f'CPU Optimized: {optimized[\"summary\"][\"cpu\"][\"avg\"]:.1f}%')
"
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: RC Testing

on: [push]

jobs:
  rc-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: pip install psutil matplotlib
      - name: Run RC tests
        run: |
          cd tests/perf/resource
          sudo python3 rc_test_runner.py
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: rc-test-results
          path: tests/perf/resource/output/
```

## Performance Benchmarks

These are typical values observed on a development machine (M1 Mac, 16GB RAM):

| Metric | Idle | Light Load | Heavy Load |
|--------|------|------------|------------|
| CPU % | 8-12% | 25-35% | 45-65% |
| Memory (MB) | 350-450 | 500-700 | 700-1200 |
| Threads | 25-30 | 30-40 | 40-55 |
| Processes | 6-8 | 7-9 | 8-10 |

**Note**: Values vary significantly based on:
- Number of ML models loaded
- Network traffic volume
- Attack complexity
- System specifications

## Architecture

```
tests/perf/resource/
├── resource_monitor.py      # Core monitoring module
├── rc_test_runner.py        # Main test orchestrator
├── run_rc_tests.sh          # Bash wrapper script
├── README.md                # This file
├── output/                  # Test results
│   ├── rc_report_*.json
│   ├── rc_dashboard_*.png
│   └── resource_snapshots.json
└── logs/                    # Detailed logs
    ├── eve_watcher.log
    └── start_macos.log
```

## Contributing

To add new metrics:

1. Extend `ProcessMetrics` or `SystemMetrics` dataclass
2. Update `get_process_metrics()` or `get_system_metrics()`
3. Modify visualization functions if needed

## License

See the repository root.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review log files in `tests/perf/resource/logs/`
3. Verify all components work independently
4. Contact the development team
