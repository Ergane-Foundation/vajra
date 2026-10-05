#!/bin/bash
# Setup script for Linux environment
# Run this on your Linux machine before testing

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

set -e  # Exit on error

echo "=================================================="
echo "Vajra - Linux Environment Setup"
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

# Install required packages
echo ""
echo "[4/6] Installing required Python packages..."
pip install numpy pandas scikit-learn joblib torch requests scapy imbalanced-learn google-generativeai

# Create logs directory
echo ""
echo "[5/6] Creating logs directory..."
mkdir -p logs
chmod 777 logs

# Verify installations
echo ""
echo "[6/6] Verifying installations..."
python3 << 'EOF'
import sys
print("\nPython executable:", sys.executable)
print("Python version:", sys.version)

try:
    import numpy as np
    print("[OK] numpy:", np.__version__)
except ImportError as e:
    print("[FAIL] numpy: NOT INSTALLED")
    
try:
    import pandas as pd
    print("[OK] pandas:", pd.__version__)
except ImportError:
    print("[FAIL] pandas: NOT INSTALLED")
    
try:
    import sklearn
    print("[OK] scikit-learn:", sklearn.__version__)
except ImportError:
    print("[FAIL] scikit-learn: NOT INSTALLED")
    
try:
    import joblib
    print("[OK] joblib:", joblib.__version__)
except ImportError:
    print("[FAIL] joblib: NOT INSTALLED")
    
try:
    import torch
    print("[OK] torch:", torch.__version__)
except ImportError:
    print("[FAIL] torch: NOT INSTALLED")

try:
    import requests
    print("[OK] requests:", requests.__version__)
except ImportError:
    print("[FAIL] requests: NOT INSTALLED")

try:
    import google.generativeai
    print("[OK] google-generativeai: installed")
except ImportError:
    print("[FAIL] google-generativeai: NOT INSTALLED")
EOF

echo ""
echo "=================================================="
echo "Setup Complete!"
echo "=================================================="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To test the models, run:"
echo "  python3 test_real_models.py"
echo "  python3 tools/attack_simulator.py --target 192.168.1.6 --eta"
echo "  python3 tools/attack_simulator.py --target 192.168.1.6 --ml"
echo "  python3 tools/attack_simulator.py --target 192.168.1.6 --uba"
echo ""
