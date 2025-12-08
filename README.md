# First Prototype - ML-Enhanced Firewall

An intelligent network firewall system combining deep packet inspection, federated learning, and automated security orchestration for advanced threat detection and response.

## Overview

This prototype implements a distributed security architecture where:

- Network packets are inspected in real-time for threat patterns (Scapy + Suricata)
- Security alerts trigger automated response actions
- Federated learning enables collaborative threat intelligence
- Event streaming ensures scalable alert processing

## Architecture

```
Network Traffic → Packet Inspector → Kafka Queue → SOAR Engine → Firewall Rules
                   (Scapy+Suricata)                      ↓
                       ↓                          Security Reports
                  FL Client (Training)
```

## Components

### Packet Inspector (Enhanced ✨)

Deep packet inspection engine using **Scapy + Suricata** for comprehensive network analysis:

- **Scapy**: Real-time packet capture and deep inspection
  - Protocol detection (TCP, UDP, ICMP, ARP, DNS)
  - Payload entropy analysis
  - Feature extraction for ML models
  - Suspicious pattern detection
- **Suricata Integration**: Network flow monitoring from eve.json
  - Flow tracking and analysis
  - Alert correlation
  - HTTP/TLS/DNS protocol inspection
  - Application layer visibility

**Usage:**

```bash
# Scapy only mode
sudo python3 packet_inspector.py -i eth0

# With Suricata integration (recommended)
sudo python3 packet_inspector.py -i eth0 --suricata --eve-json logs/eve.json
```

### SOAR Engine

Security Orchestration and Automated Response system:

- Automated IP blocking via iptables/nftables
- Threat severity evaluation
- Security report generation
- Action logging and audit trails

### FL Client (Enhanced ✨)

**Federated Learning client** for distributed threat intelligence:

- **Privacy-preserving model training**: Only model weights shared, no raw data
- **Eve.json parsing**: Learns from Suricata alerts
- **Feature extraction**: Network flow and payload features
- **Random Forest classifier**: Local threat detection model
- **Collaborative learning**: Aggregates knowledge across firewall nodes

**Features:**

- Reads Suricata eve.json alerts (last 24 hours by default)
- Extracts 12+ network features per alert
- Trains Random Forest model locally
- Generates model metrics (accuracy, precision, recall)
- Saves trained model to `ml_models/fl_local_model.pkl`

**Usage:**

```bash
# Train locally and send updates to FL server
python3 fl_client.py --server-host 192.168.1.100:8080

# Dry run (train locally, don't send updates)
python3 fl_client.py --dry-run

# Custom data window
python3 fl_client.py --hours 48 --dry-run
```

### Kafka Queue

Event streaming infrastructure:

- Scalable alert distribution
- Asynchronous processing pipeline
- Decoupled architecture

### Detection Rules

Network intrusion detection signatures:

- SQL injection patterns
- Protocol-specific rules
- Custom threat signatures

### Suricata IPS Engine

Suricata inline intrusion prevention system (IPS) for real-time threat blocking:

- **Configuration**: `suricata.yaml` - IPS mode with NFQUEUE for inline packet filtering
- **Rules**: `rules/local.rules` - DROP rules for SQL injection, XSS, path traversal, and web attacks
- **Detection**: Monitors HTTP, DNS, TLS, SSH, FTP, and SMTP protocols
- **Outputs**: EVE JSON format logging with alerts, drops, flows, and anomalies
- **Response**: Automatically blocks malicious traffic inline using Suricata's DROP action
- **Classification**: `classification.config` - Alert priority and type definitions

## ML Models (New ✨)

The following pre-trained ML models are now included in `ml_models/`:

- **`domain_classifier.h5`** - Keras/TensorFlow model for domain classification
- **`gnn_fingerprint.tflite`** - TensorFlow Lite GNN model for device fingerprinting
- **`mitm.joblib`** - MITM attack detection model (scikit-learn)
- **`eta_model.pkl`** - Encrypted Traffic Analysis model
- **`deep_insider_threat_model.pkl`** - Deep learning model for insider threat detection
- **`backdoor_detection/`** - Backdoor detection models and encoders
  - `backdoor_model.pkl` - Main backdoor detection classifier
  - `label_encoders.pkl` - Feature encoding transformations
  - `scaler.pkl` - Feature normalization scaler

These models enable advanced threat detection capabilities across multiple attack vectors.

## Testing & Monitoring (New ✨)

### test.py - Full Suricata + Scapy Monitor

Comprehensive network monitoring tool combining Suricata flows and Scapy packet inspection:

**Features:**

- 📡 **Suricata Flow Monitoring**: Real-time eve.json parsing for flows, alerts, DNS
- 🔍 **Scapy Deep Packet Inspection**: Layer-by-layer packet analysis
- 🎨 **Colorful Terminal Output**: Formatted display with ANSI colors
- 🌐 **Protocol Support**: HTTP, TLS, DNS, DHCP, NTP, mDNS, ICMP, ARP
- 📊 **Payload Analysis**: Hex dumps and entropy analysis

**Usage:**

```bash
# Run with sudo for packet capture
sudo python3 test.py

# Press Ctrl+C to stop
```

**What it shows:**

- Network flows with bandwidth stats
- HTTP requests with headers and payloads
- TLS connections with SNI and JA3 fingerprints
- DNS queries and responses
- TCP/UDP packet details with flags and sequence numbers
- ICMP echo requests/replies
- ARP requests/replies

## Setup

### Prerequisites

```bash
# Install system dependencies (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv libpcap-dev

# Install Suricata (optional but recommended)
sudo apt-get install suricata
```

### Installation

```bash
# Run setup script
./setup_linux.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # If you create one
# Or install packages directly:
pip install numpy pandas scikit-learn joblib scapy
```

## Quick Start

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run full Suricata + Scapy monitor (requires sudo)
sudo python3 test.py

# 3. Run packet inspector with Suricata integration
sudo python3 packet_inspector.py -i eth0 --suricata

# 4. Train federated learning model
python3 fl_client.py --dry-run

# 5. Test SOAR engine
python3 soar_engine.py
```

## Logs

Security events and actions are logged to:

- `logs/blocked_ips.txt` - Blocked IP addresses
- `logs/soar_actions.json` - SOAR action history
- `logs/reports/` - Detailed security reports
