#!/bin/bash
# Create the Python virtual environment and install Vajra.
# Optional extras can be selected with VAJRA_EXTRAS, for example:
#   VAJRA_EXTRAS=ml,dpi ./scripts/setup_venv.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

set -e

echo "Vajra - Python environment setup"
echo ""

echo "[1/4] Checking Python version..."
python3 --version

if [ -d "venv" ]; then
    echo "[2/4] Using existing virtual environment"
else
    echo "[2/4] Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate

echo "[3/4] Installing Vajra..."
pip install --upgrade pip
if [ -n "$VAJRA_EXTRAS" ]; then
    pip install -e ".[$VAJRA_EXTRAS]"
else
    pip install -e .
fi

echo "[4/4] Creating logs directory..."
mkdir -p logs

python3 - << 'PYEOF'
import importlib
for name in ["numpy", "pandas", "sklearn", "joblib", "requests", "fastapi", "vajra"]:
    try:
        module = importlib.import_module(name)
        print(f"[OK] {name} {getattr(module, '__version__', '')}")
    except ImportError:
        print(f"[FAIL] {name} is not installed")
PYEOF

echo ""
echo "Setup complete. Activate the environment with:"
echo "  source venv/bin/activate"
echo ""
echo "Try the attack simulator against a test machine:"
echo "  python3 tools/attack_simulator.py --target <target-ip>"
