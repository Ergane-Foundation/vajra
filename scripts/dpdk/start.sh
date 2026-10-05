#!/bin/bash
# Start DPDK-based NGFW Pipeline
# Launches DPDK packet processor, Suricata (DPDK mode), and Python ML components

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

# Configuration
DPDK_PROCESSOR="/usr/local/bin/dpdk_packet_processor"
DPDK_FEATURES_FILE="/tmp/dpdk_features.json"
DPDK_EAL_ARGS="-l 0-3 -n 4 --proc-type=primary --file-prefix=ngfw"
DPDK_PORT=0

SURICATA_YAML="/etc/suricata/suricata.yaml"
SURICATA_DPDK_MODE=false  # Set to true if Suricata built with DPDK

PID_DIR="/var/run/ngfw"
LOG_DIR="$ROOT_DIR/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Starting DPDK-based NGFW Pipeline"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[WARN]  This script requires root privileges${NC}"
    echo "Please run with: sudo $0"
    exit 1
fi

# Create directories
mkdir -p "$PID_DIR"
mkdir -p "$LOG_DIR"

# Clear old feature file
rm -f "$DPDK_FEATURES_FILE"
touch "$DPDK_FEATURES_FILE"
chmod 666 "$DPDK_FEATURES_FILE"

echo ""
echo "Step 1: Checking DPDK packet processor..."
if [ ! -f "$DPDK_PROCESSOR" ]; then
    echo -e "${RED}[FAIL] DPDK packet processor not found: $DPDK_PROCESSOR${NC}"
    echo "Please run: sudo ./scripts/dpdk/setup.sh"
    exit 1
fi
echo -e "${GREEN}[OK] DPDK packet processor found${NC}"

echo ""
echo "Step 2: Checking hugepages..."
HUGEPAGES=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
if [ "$HUGEPAGES" -lt 512 ]; then
    echo -e "${YELLOW}[WARN]  Only $HUGEPAGES hugepages allocated (recommend 1024+)${NC}"
    echo "Allocating more hugepages..."
    echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
fi
echo -e "${GREEN}[OK] Hugepages: $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)${NC}"

echo ""
echo "Step 3: Checking NIC binding..."
# This is informational - user should have already bound NIC
if command -v dpdk-devbind.py &> /dev/null; then
    echo "Current NIC status:"
    python3 $(ls /opt/dpdk-*/usertools/dpdk-devbind.py | head -1) --status-dev net | head -20
elif command -v dpdk-bind-nic &> /dev/null; then
    dpdk-bind-nic status | head -20
fi
echo ""
echo -e "${YELLOW}[WARN]  Make sure at least one NIC is bound to DPDK (vfio-pci or igb_uio)${NC}"
echo "Use: sudo dpdk-bind-nic bind <PCI_ADDRESS>"
read -p "Press Enter to continue (or Ctrl+C to abort)..."

echo ""
echo "Step 4: Starting DPDK packet processor..."

# Kill existing instance if running
if [ -f "$PID_DIR/dpdk_processor.pid" ]; then
    OLD_PID=$(cat "$PID_DIR/dpdk_processor.pid")
    if kill -0 $OLD_PID 2>/dev/null; then
        echo "Stopping old DPDK processor (PID $OLD_PID)..."
        kill $OLD_PID || true
        sleep 2
    fi
fi

# Start DPDK processor in background
# Note: Features are written to JSON file for Python consumer
nohup $DPDK_PROCESSOR $DPDK_EAL_ARGS -- \
    > "$LOG_DIR/dpdk_processor.log" 2>&1 &

DPDK_PID=$!
echo $DPDK_PID > "$PID_DIR/dpdk_processor.pid"

# Wait a moment and check if it's running
sleep 3
if ! kill -0 $DPDK_PID 2>/dev/null; then
    echo -e "${RED}[FAIL] DPDK processor failed to start${NC}"
    echo "Check logs: cat $LOG_DIR/dpdk_processor.log"
    exit 1
fi

echo -e "${GREEN}[OK] DPDK packet processor started (PID $DPDK_PID)${NC}"
echo "   Log: $LOG_DIR/dpdk_processor.log"
echo "   Features: $DPDK_FEATURES_FILE"

echo ""
echo "Step 5: Starting Suricata..."

# Kill existing Suricata
if [ -f "$PID_DIR/suricata.pid" ]; then
    OLD_PID=$(cat "$PID_DIR/suricata.pid")
    if kill -0 $OLD_PID 2>/dev/null; then
        echo "Stopping old Suricata (PID $OLD_PID)..."
        kill $OLD_PID || true
        sleep 2
    fi
fi

if [ "$SURICATA_DPDK_MODE" = true ]; then
    # Suricata in DPDK mode
    echo "Starting Suricata in DPDK mode..."
    nohup suricata -c "$SURICATA_YAML" \
        --dpdk \
        > "$LOG_DIR/suricata.log" 2>&1 &
else
    # Suricata in AF_PACKET mode (reads from kernel)
    # Note: DPDK processor doesn't forward to kernel by default
    # This requires KNI or similar bridge (not implemented in basic version)
    echo -e "${YELLOW}[WARN]  Suricata in AF_PACKET mode${NC}"
    echo "Note: Suricata won't see DPDK-captured packets without KNI bridge"
    echo "For full integration, build Suricata with DPDK support"
    
    # Get interface to monitor (if not using DPDK)
    IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
    echo "Using interface: $IFACE"
    
    nohup suricata -c "$SURICATA_YAML" -i "$IFACE" \
        > "$LOG_DIR/suricata.log" 2>&1 &
fi

SURICATA_PID=$!
echo $SURICATA_PID > "$PID_DIR/suricata.pid"
sleep 2

if ! kill -0 $SURICATA_PID 2>/dev/null; then
    echo -e "${YELLOW}[WARN]  Suricata may have failed to start (check logs)${NC}"
else
    echo -e "${GREEN}[OK] Suricata started (PID $SURICATA_PID)${NC}"
fi
echo "   Log: $LOG_DIR/suricata.log"
echo "   Eve.json: $LOG_DIR/eve.json"

echo ""
echo "Step 6: Starting Python ML packet inspector..."

# Start packet inspector in DPDK mode
nohup python3 -m vajra.inspection.packet_inspector \
    --dpdk \
    --dpdk-json "$DPDK_FEATURES_FILE" \
    > "$LOG_DIR/packet_inspector.log" 2>&1 &

INSPECTOR_PID=$!
echo $INSPECTOR_PID > "$PID_DIR/packet_inspector.pid"
sleep 2

if ! kill -0 $INSPECTOR_PID 2>/dev/null; then
    echo -e "${YELLOW}[WARN]  Packet inspector may have failed to start${NC}"
else
    echo -e "${GREEN}[OK] Packet Inspector started (PID $INSPECTOR_PID)${NC}"
fi
echo "   Log: $LOG_DIR/packet_inspector.log"

echo ""
echo "Step 7: Starting other ML components..."

# Start SOAR engine if it exists
if [ -f "$ROOT_DIR/src/vajra/soar/engine.py" ]; then
    nohup python3 -m vajra.soar.engine \
        > "$LOG_DIR/soar_engine.log" 2>&1 &
    SOAR_PID=$!
    echo $SOAR_PID > "$PID_DIR/soar_engine.pid"
    echo -e "${GREEN}[OK] SOAR Engine started (PID $SOAR_PID)${NC}"
fi

# Start unified logger if it exists
if [ -f "$ROOT_DIR/src/vajra/pipeline/unified_logger.py" ]; then
    nohup python3 -m vajra.pipeline.unified_logger \
        > "$LOG_DIR/unified_logger.log" 2>&1 &
    LOGGER_PID=$!
    echo $LOGGER_PID > "$PID_DIR/unified_logger.pid"
    echo -e "${GREEN}[OK] Unified Logger started (PID $LOGGER_PID)${NC}"
fi

echo ""
echo "========================================="
echo -e "${GREEN}[OK] DPDK Pipeline Started Successfully!${NC}"
echo "========================================="
echo ""
echo "Pipeline Status:"
echo "  • DPDK Packet Processor: PID $DPDK_PID"
echo "  • Suricata IDS:          PID $SURICATA_PID"
echo "  • ML Packet Inspector:   PID $INSPECTOR_PID"
echo ""
echo "Monitor logs:"
echo "  tail -f $LOG_DIR/dpdk_processor.log"
echo "  tail -f $LOG_DIR/packet_inspector.log"
echo "  tail -f $LOG_DIR/eve.json"
echo ""
echo "Check status:"
echo "  python3 scripts/status.py"
echo ""
echo "Stop pipeline:"
echo "  sudo ./scripts/dpdk/stop.sh"
echo ""
