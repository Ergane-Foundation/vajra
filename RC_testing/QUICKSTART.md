# NGFW RC Testing - Quick Reference

## 🚀 Quick Start

```bash
cd /Users/agam1092005/Desktop/Projects/SIH/L5/linux/RC_testing
sudo ./run_rc_tests.sh
```

## 📋 What Gets Tested

### Pipeline Components
- ✅ **eve_watcher** - Real-time event streaming (WebSocket)
- ✅ **Suricata IDS** - Network packet analysis
- ✅ **SOAR Engine** - ML-powered threat response
- ✅ **Packet Inspector** - Deep packet inspection
- ✅ **Inference API** - Federated Learning (FL) models
- ✅ **Unified Logger** - Centralized logging
- ✅ **ML Models** - Multiple threat detection models

### Resources Monitored
- 📊 **CPU Usage** - Per-process and total
- 💾 **Memory (RAM)** - RSS and VMS metrics
- 🔧 **Threads** - Thread count per component
- 📁 **File Descriptors** - Open file handles
- 💿 **Disk I/O** - Read/Write operations
- 🌐 **Network I/O** - Sent/Received data

## 🎯 Test Phases

1. **Warmup** (10s) - Start eve_watcher
2. **Pipeline Start** (15s) - Launch all components via start_macos.sh
3. **Baseline** (30s) - Measure idle resource usage
4. **Load Test** (60s) - Simulate traffic + attacks
5. **Cooldown** (10s) - Final measurements

**Total Duration**: ~2 minutes

## 📊 Output Files

### Location
```
RC_testing/output/
├── rc_report_YYYYMMDD_HHMMSS.json          # Full test results
├── rc_dashboard_YYYYMMDD_HHMMSS.png        # Visual dashboard (4 graphs)
├── rc_component_breakdown_YYYYMMDD_HHMMSS.png  # Component breakdown
├── resource_snapshots.json                  # Raw time-series data
└── resource_summary.json                    # Statistical summary
```

### Dashboard Graphs
1. **CPU Usage Over Time** - Red line chart
2. **Memory Usage Over Time** - Blue line chart
3. **Thread Count** - Green line chart
4. **Process Count** - Purple line chart

### JSON Report Structure
```json
{
  "test_id": "20231209_123045",
  "summary": {
    "cpu": {
      "min": 10.5, "avg": 32.1, "max": 67.8,
      "p95": 58.2, "p99": 65.1
    },
    "memory_mb": {
      "min": 345.2, "avg": 678.9, "max": 892.3,
      "p95": 845.6, "p99": 880.1
    },
    "threads": {"min": 28, "avg": 35.4, "max": 44},
    "processes": {"min": 7, "avg": 8.2, "max": 9}
  },
  "phases": {
    "baseline": {
      "cpu_percent": 12.3,
      "memory_mb": 456.7,
      "threads": 30,
      "processes": 8
    },
    "load": {
      "cpu_percent": 45.6,
      "memory_mb": 789.2,
      "threads": 38,
      "processes": 9
    }
  }
}
```

## 📈 Interpreting Results

### ✅ Good Performance
- CPU < 60% under load
- Memory < 1GB
- Stable process/thread count
- No crashes

### ⚠️ Warning Signs
- CPU > 80% sustained
- Memory growing continuously
- Increasing file descriptors
- Process count fluctuating

### ❌ Critical Issues
- CPU pinned at 100%
- Memory exhaustion
- Process crashes
- File descriptor limit reached

## 🔧 Common Commands

### Run Standard Test
```bash
sudo ./run_rc_tests.sh
```

### Custom Duration (Standalone Monitor)
```bash
# Monitor for 5 minutes with 2s interval
sudo python3 resource_monitor.py --duration 300 --interval 2.0
```

### View Latest Results
```bash
# View JSON report
cat output/rc_report_*.json | jq '.summary'

# View images
open output/rc_dashboard_*.png
```

### Extract Specific Metrics
```bash
# Extract CPU avg
cat output/rc_report_*.json | jq '.summary.cpu.avg'

# Extract memory max
cat output/rc_report_*.json | jq '.summary.memory_mb.max'

# Extract baseline CPU
cat output/rc_report_*.json | jq '.phases.baseline.cpu_percent'
```

## 🐛 Troubleshooting

### Error: "psutil not installed"
```bash
pip install psutil
```

### Error: "Must run as root"
```bash
sudo ./run_rc_tests.sh
```

### Error: "matplotlib not installed"
```bash
# Visualizations will be skipped, but JSON reports still work
# To fix:
pip install matplotlib
```

### Pipeline fails to start
```bash
# Check Suricata
which suricata

# Check ports
lsof -i :8000  # eve_watcher
lsof -i :8001  # inference API
lsof -i :8080  # HTTP server

# View logs
tail -f logs/start_macos.log
tail -f logs/eve_watcher.log
```

### No processes detected
```bash
# Manually check what's running
ps aux | grep -E "suricata|soar_engine|eve_watcher|unified_logger"

# Give pipeline more time to start (increase WARMUP_DURATION in rc_test_runner.py)
```

## 🔬 Advanced Usage

### Monitor Existing Pipeline
If pipeline is already running, use standalone monitor:

```bash
sudo python3 resource_monitor.py --duration 120 --interval 1
```

### Compare Before/After
```bash
# Baseline
sudo ./run_rc_tests.sh
mv output/rc_report_*.json output/before.json

# After changes
sudo ./run_rc_tests.sh
mv output/rc_report_*.json output/after.json

# Compare
sdiff <(cat output/before.json | jq '.summary.cpu') \
      <(cat output/after.json | jq '.summary.cpu')
```

### Continuous Monitoring
```bash
# Run every hour
while true; do
    sudo ./run_rc_tests.sh
    sleep 3600
done
```

## 📊 Expected Values (Reference)

| Component | CPU (Idle) | CPU (Load) | Memory |
|-----------|------------|------------|--------|
| Suricata | 2-5% | 10-25% | 100-200MB |
| SOAR Engine | 1-3% | 8-15% | 80-150MB |
| eve_watcher | 1-2% | 3-7% | 30-50MB |
| Inference API | 0-1% | 5-12% | 100-250MB |
| Unified Logger | 1-2% | 3-8% | 40-80MB |
| Packet Inspector | 2-4% | 10-20% | 60-120MB |
| **TOTAL** | **8-15%** | **35-65%** | **400-900MB** |

*Note: Values vary based on system specs and traffic volume*

## 🎓 Key Metrics Explained

### CPU Percent
- Percentage of CPU time used by process
- Multi-core systems: Can exceed 100% (e.g., 200% = 2 cores fully utilized)

### RSS (Resident Set Size)
- Actual physical RAM used by process
- Does not include swapped-out memory

### VMS (Virtual Memory Size)
- Total virtual memory allocated
- Includes memory-mapped files, shared libraries

### Threads
- Concurrent execution units within a process
- More threads = better parallelism (up to a point)

### File Descriptors
- Open files, sockets, pipes
- System limit typically 1024 per process

## 📞 Support

For issues:
1. Check README.md (detailed docs)
2. Review logs in `RC_testing/logs/`
3. Verify components work individually:
   - `python3 -m vajra.pipeline.eve_watcher`
   - `sudo ./scripts/start_macos.sh`
4. Check system resources: `top`, `htop`

---

**Last Updated**: 2025-12-09
**Project**: SIH L5 - Next Generation Firewall
