# First Prototype - ML-Enhanced Firewall

An intelligent network firewall system combining deep packet inspection, federated learning, and automated security orchestration for advanced threat detection and response.

## Overview

This prototype implements a distributed security architecture where:

- Network packets are inspected in real-time for threat patterns
- Security alerts trigger automated response actions
- Federated learning enables collaborative threat intelligence
- Event streaming ensures scalable alert processing

## Architecture

```
Network Traffic → Packet Inspector → Kafka Queue → SOAR Engine → Firewall Rules
                       ↓                                ↓
                  FL Client (Training)          Security Reports
```

## Components

### Packet Inspector

Deep packet inspection engine using Scapy for real-time network analysis:

- Protocol detection (TCP, UDP, ICMP)
- Payload entropy analysis
- Feature extraction for ML models
- Suspicious pattern detection

### SOAR Engine

Security Orchestration and Automated Response system:

- Automated IP blocking via iptables/nftables
- Threat severity evaluation
- Security report generation
- Action logging and audit trails

### FL Client

Federated learning client for distributed threat intelligence:

- Privacy-preserving model training
- Collaborative learning across nodes
- Model update synchronization

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

## Quick Start

```bash
# Run packet inspector
python3 packet_inspector.py -i eth0

# Test SOAR engine
python3 soar_engine.py

# Start FL client
python3 fl_client.py
```

## Logs

Security events and actions are logged to:

- `logs/blocked_ips.txt` - Blocked IP addresses
- `logs/soar_actions.json` - SOAR action history
- `logs/reports/` - Detailed security reports
