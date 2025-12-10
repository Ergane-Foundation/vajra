# NGFW Stress Testing Suite

Comprehensive stress testing framework for the Next-Generation Firewall (NGFW) system.

## 🎯 Overview

This stress testing suite tests the entire NGFW pipeline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NGFW PIPELINE STRESS TESTING                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────────┐      ┌──────────────────┐      ┌────────────────┐   │
│   │ Packet Inspector │──────│    ML Models     │──────│  SOAR Engine   │   │
│   │  (stress_packet) │      │  (stress_ml)     │      │ (stress_soar)  │   │
│   └──────────────────┘      └──────────────────┘      └────────────────┘   │
│            │                         │                         │            │
│            │    ┌────────────────────┼────────────────────┐    │            │
│            │    │                    │                    │    │            │
│            ▼    ▼                    ▼                    ▼    ▼            │
│   ┌──────────────────────────────────────────────────────────────────┐     │
│   │                    Detection Engines                              │     │
│   │  (Kitsune | FlowPrint | Stratosphere | ETA | UBA)                 │     │
│   │                    (stress_detection_engines)                     │     │
│   └──────────────────────────────────────────────────────────────────┘     │
│            │                         │                         │            │
│            ▼                         ▼                         ▼            │
│   ┌────────────────┐      ┌──────────────────┐      ┌────────────────┐     │
│   │ Inference API  │      │  Unified Logger  │      │   FL Client    │     │
│   │ (stress_api)   │      │  (stress_logging)│      │  (stress_fl)   │     │
│   └────────────────┘      └──────────────────┘      └────────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Run All Stress Tests (Quick Mode)
```bash
cd stress_testing
python3 run_stress_tests.py --quick
```

### Run Comprehensive Tests
```bash
python3 run_stress_tests.py --all
```

### Run Specific Test Categories
```bash
# ML model stress tests only
python3 run_stress_tests.py --ml

# Network/packet processing tests only
python3 run_stress_tests.py --network

# Detection engine tests only
python3 run_stress_tests.py --engine
```

### View Results
Results are saved in `output/` directory:
- `stress_test_report.json` - Full test report
- `stress_test_dashboard.png` - Visual summary
- `*_stress_results.json` - Individual test results
- `*_stress_metrics.json` - Summary metrics

## 📁 Test Modules

| Module | Description | Metrics |
|--------|-------------|---------|
| `stress_ml_models.py` | ML model inference testing | Throughput, latency, concurrent inference |
| `stress_packet_processing.py` | Packet inspection & flow tracking | Feature extraction rate, flow table performance |
| `stress_detection_engines.py` | All detection engines | Per-engine throughput, detection rates |
| `stress_soar_engine.py` | SOAR alert processing | Alert throughput, blocking decisions |
| `stress_inference_api.py` | FastAPI inference API | Request rate, API latency |
| `stress_fl_client.py` | Federated learning client | Training speed, serialization |
| `stress_unified_logging.py` | Unified event logging | Logging throughput, file I/O |
| `stress_concurrent_load.py` | Full pipeline under load | E2E throughput, bottleneck ID |
| `stress_memory_profile.py` | Memory usage profiling | Memory growth, leak detection |

## 📊 Metrics Collected

### Performance Metrics
- **Throughput**: Operations/second for each component
- **Latency**: Min, max, avg, P95, P99 latencies
- **Concurrent Performance**: Multi-threaded throughput
- **Batch Processing**: Efficiency at different batch sizes

### Resource Metrics
- **Memory Usage**: Per-component and total
- **Memory Growth**: Detection of potential leaks
- **GC Performance**: Garbage collection timing

### Reliability Metrics
- **Error Rate**: Failures under load
- **Degradation**: Performance over sustained load
- **Detection Rate**: Threat detection accuracy

## 🔧 Individual Test Usage

Each stress test module can be run individually:

```bash
# ML Models
python3 stress_ml_models.py --predictions 5000 --json-output ./output

# Packet Processing
python3 stress_packet_processing.py --packets 10000 --json-output ./output

# Detection Engines
python3 stress_detection_engines.py --packets 3000 --json-output ./output

# SOAR Engine
python3 stress_soar_engine.py --alerts 5000 --json-output ./output

# Inference API
python3 stress_inference_api.py --requests 2000 --json-output ./output

# FL Client
python3 stress_fl_client.py --samples 3000 --json-output ./output

# Unified Logging
python3 stress_unified_logging.py --events 10000 --json-output ./output

# Concurrent Load
python3 stress_concurrent_load.py --threads 8 --duration 30 --json-output ./output

# Memory Profile
python3 stress_memory_profile.py --duration 30 --json-output ./output
```

## 📈 Output Format

### JSON Results
```json
{
  "timestamp": "2024-12-09T12:00:00Z",
  "test_type": "ml_model_stress",
  "tests": {
    "inference_throughput": {
      "total_predictions": 5000,
      "predictions_per_second": 1234.56,
      "avg_latency_ms": 0.81,
      "p99_latency_ms": 2.34,
      "errors": 0
    }
  },
  "summary": {
    "throughput": 1234.56,
    "avg_latency_ms": 0.81
  }
}
```

### Visual Dashboard
The `stress_test_dashboard.png` includes:
1. Test duration comparison
2. Pass/fail distribution
3. Throughput comparison across components
4. Latency comparison across components

## 🛠️ Requirements

### Required
- Python 3.8+
- Running NGFW components (optional - tests will skip unavailable components)

### Optional (for enhanced testing)
```bash
pip install psutil matplotlib httpx
```

## 🔍 Interpreting Results

### Success Criteria

| Component | Target Throughput | Target P99 Latency |
|-----------|------------------|-------------------|
| ML Models | >500 pred/s | <10ms |
| Packet Processing | >5000 pkt/s | <1ms |
| SOAR Engine | >1000 alerts/s | <5ms |
| Inference API | >500 req/s | <20ms |
| Detection Engines | >1000 events/s | <5ms |

### Warning Flags
- **High Error Rate**: >1% errors indicates instability
- **Latency Degradation**: P99 > 10x avg indicates bottleneck
- **Memory Leak**: Continuous growth over sustained load
- **Low Throughput**: Below target indicates performance issue

## 🧪 Test Scenarios

### 1. Normal Load
Tests steady-state performance with moderate traffic.

### 2. Burst Load
Simulates traffic spikes (e.g., DDoS attack beginning).

### 3. Sustained Load
Tests stability over extended periods.

### 4. Mixed Workload
Combines different event types and sizes.

### 5. Concurrent Load
Tests multi-threaded processing capabilities.

## 📝 Adding Custom Tests

Create a new test module following this template:

```python
#!/usr/bin/env python3
"""
Custom Stress Test for [Component]
"""

import sys
from pathlib import Path
SCRIPT_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(SCRIPT_DIR.parent))

def test_custom_feature():
    # Your test logic here
    return {"metric": value}

def main():
    results = {
        "tests": {
            "custom_test": test_custom_feature()
        }
    }
    # Save results
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## 📌 Notes

- Tests are designed to be **non-destructive** (no actual firewall changes)
- Memory tests require the `psutil` library for accurate metrics
- Visual reports require `matplotlib`
- Tests skip gracefully if components are unavailable
- All times are in milliseconds unless otherwise noted

## 🔐 Security Considerations

- Tests generate synthetic traffic - no actual attacks
- Firewall rules are tested in dry-run mode
- No external network connections required
- All test data is generated locally

---

**Author**: NGFW Development Team  
**Version**: 1.0.0  
**Last Updated**: December 2024
