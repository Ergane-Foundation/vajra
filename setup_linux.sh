#!/bin/bash
# Setup script for first_prototype environment
# Run this before testing the first prototype

set -e  # Exit on error

echo "=================================================="
echo "L5 NGFW - First Prototype Setup"
echo "=================================================="

# Check Python version
echo ""
echo "[1/6] Checking Python version..."
python3 --version

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo ""
    echo "[2/6] Virtual environment found, activating..."
    source venv/bin/activate
else
    echo ""
    echo "[2/6] Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
fi

# Upgrade pip
echo ""
echo "[3/6] Upgrading pip..."
pip install --upgrade pip

# Install required packages for first_prototype
echo ""
echo "[4/6] Installing required Python packages..."
echo "  - Core ML packages: numpy, scikit-learn, joblib"
echo "  - Network analysis: scapy"
echo "  - Data processing: pandas"
echo ""

pip install numpy pandas scikit-learn joblib scapy

# Create logs directory
echo ""
echo "[5/6] Creating logs directory..."
mkdir -p logs
chmod 755 logs

# Create ml_models directory if not exists
if [ ! -d "ml_models" ]; then
    mkdir -p ml_models
    echo "Created ml_models directory"
fi

# Verify installations
echo ""
echo "[6/6] Verifying installations..."
python3 << 'EOF'
import sys
print("\nPython executable:", sys.executable)
print("Python version:", sys.version)

try:
    import numpy as np
    print("✅ numpy:", np.__version__)
except ImportError as e:
    print("❌ numpy: NOT INSTALLED")
    
try:
    import pandas as pd
    print("✅ pandas:", pd.__version__)
except ImportError:
    print("❌ pandas: NOT INSTALLED")
    
try:
    import sklearn
    print("✅ scikit-learn:", sklearn.__version__)
except ImportError:
    print("❌ scikit-learn: NOT INSTALLED")
    
try:
    import joblib
    print("✅ joblib:", joblib.__version__)
except ImportError:
    print("❌ joblib: NOT INSTALLED")

try:
    import scapy
    print("✅ scapy: installed")
except ImportError:
    print("❌ scapy: NOT INSTALLED")
    print("   Note: scapy may require root/sudo for packet capture")
EOF

echo ""
echo "=================================================="
echo "Setup Complete!"
echo "=================================================="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "Available components in first_prototype:"
echo "  - packet_inspector.py : Scapy + Suricata packet analysis"
echo "  - fl_client.py        : Federated learning client"
echo "  - soar_engine.py      : SOAR automated response"
echo "  - kafka_queue.py      : Event streaming (mock)"
echo "  - test.py             : Full Suricata + Scapy testing"
echo ""
echo "To run tests:"
echo "  python3 test.py                    # Suricata + Scapy monitor"
echo "  sudo python3 packet_inspector.py --suricata  # Packet inspector with Suricata"
echo "  python3 fl_client.py --dry-run    # FL training (local only)"
echo ""
echo "Note: Packet capture requires root/sudo privileges"
echo ""
