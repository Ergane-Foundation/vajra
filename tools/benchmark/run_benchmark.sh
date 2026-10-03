#!/bin/bash
# Benchmark Runner Script - Tests Packet Inspector Performance

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

echo "=== Firewall Performance Benchmark ==="
echo ""

# Detect active interface
INTERFACE=$(route -n get default 2>/dev/null | grep interface | awk '{print $2}')
if [ -z "$INTERFACE" ]; then
    INTERFACE="en0"
fi

echo "Using network interface: $INTERFACE"
echo ""

# Test Mode Selection
MODE=${1:-normal}

if [ "$MODE" == "dpdk" ]; then
    echo "Starting DPDK Packet Inspector..."
    sudo env PYTHONPATH="$PYTHONPATH" python3 -m vajra.inspection.packet_inspector --dpdk > /tmp/packet_inspector.log 2>&1 &
    PI_PID=$!
    echo "Packet Inspector PID: $PI_PID"
elif [ "$MODE" == "normal" ]; then
    echo "Starting Scapy Packet Inspector on $INTERFACE..."
    sudo env PYTHONPATH="$PYTHONPATH" python3 -m vajra.inspection.packet_inspector -i "$INTERFACE" > /tmp/packet_inspector.log 2>&1 &
    PI_PID=$!
    echo "Packet Inspector PID: $PI_PID"
else
    echo "Usage: $0 [normal|dpdk]"
    exit 1
fi

# Wait for initialization
echo "Waiting for packet inspector to initialize..."
sleep 5

# Check if running
if ! ps -p $PI_PID > /dev/null 2>&1; then
    echo "[FAIL] Packet Inspector failed to start. Check /tmp/packet_inspector.log"
    cat /tmp/packet_inspector.log
    exit 1
fi

echo "[OK] Packet Inspector running"
echo ""

# Run benchmark
echo "Running benchmark tests..."
python3 tools/benchmark/benchmark.py

# Cleanup
echo ""
echo "Stopping packet inspector..."
sudo kill $PI_PID 2>/dev/null

echo ""
echo "Check /tmp/packet_inspector.log for packet inspector logs"
echo "Check logs/packet_inspector.json for captured packets"
