#!/bin/bash
# Stop DPDK-based NGFW Pipeline

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PID_DIR="/var/run/ngfw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "Stopping DPDK-based NGFW Pipeline"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[WARN]  This script requires root privileges${NC}"
    echo "Please run with: sudo $0"
    exit 1
fi

# Function to stop a process
stop_process() {
    local NAME=$1
    local PID_FILE=$2
    
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo "Stopping $NAME (PID $PID)..."
            kill -TERM $PID
            
            # Wait for graceful shutdown
            for i in {1..10}; do
                if ! kill -0 $PID 2>/dev/null; then
                    echo -e "${GREEN}[OK] $NAME stopped${NC}"
                    rm -f "$PID_FILE"
                    return 0
                fi
                sleep 1
            done
            
            # Force kill if still running
            if kill -0 $PID 2>/dev/null; then
                echo -e "${YELLOW}[WARN]  Force killing $NAME${NC}"
                kill -KILL $PID || true
                rm -f "$PID_FILE"
            fi
        else
            echo "$NAME not running (stale PID file)"
            rm -f "$PID_FILE"
        fi
    else
        echo "$NAME not running (no PID file)"
    fi
}

echo ""
echo "Stopping components..."

# Stop in reverse order
stop_process "Unified Logger" "$PID_DIR/unified_logger.pid"
stop_process "SOAR Engine" "$PID_DIR/soar_engine.pid"
stop_process "Packet Inspector" "$PID_DIR/packet_inspector.pid"
stop_process "Suricata" "$PID_DIR/suricata.pid"
stop_process "DPDK Processor" "$PID_DIR/dpdk_processor.pid"

echo ""
echo "Cleaning up..."

# Clean up DPDK resources
rm -f /tmp/dpdk_features.json
rm -f /var/run/dpdk/rte/config || true

# Kill any remaining DPDK processes
pkill -f "dpdk_packet_processor" || true
pkill -f "suricata.*dpdk" || true

echo ""
echo "========================================="
echo -e "${GREEN}[OK] DPDK Pipeline Stopped${NC}"
echo "========================================="
echo ""
echo "To restart:"
echo "  sudo ./scripts/dpdk/start.sh"
echo ""
