#!/bin/bash
# =============================================================================
# NGFW Complete Startup Script - macOS Version
# =============================================================================
# 
# This script starts the NGFW pipeline optimized for macOS:
#   1. System Setup (install.sh, setup_linux.sh)
#   2. Python Virtual Environment Setup
#   3. Suricata IDS (AF_PACKET mode - NFQUEUE not available on macOS)
#   4. HTTP Server (for testing)
#   5. SOAR Engine (with ML and Packet Inspection)
#   6. Unified Logger
#   7. Inference API (for Federated Learning)
#   8. Kafka Bridge (optional)
#
# Note: macOS does not support NFQUEUE, so this runs in IDS mode only
#
# Usage:
#   sudo ./start_macos.sh              # Start everything
#   sudo ./start_macos.sh --no-http    # Skip HTTP server
#   sudo ./start_macos.sh --help       # Show help
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# =============================================================================
# Initial Setup Phase
# =============================================================================

# Check if this is first run (no venv exists)
FIRST_RUN=false
if [ ! -d "venv" ] && [ ! -d "venv_test" ]; then
    FIRST_RUN=true
fi

if [ "$FIRST_RUN" = true ]; then
    echo "================================================================"
    echo "First run detected - performing initial setup..."
    echo "================================================================"
    
    # Step 1: Run install.sh
    echo ""
    echo "[Setup 1/4] Running install.sh..."
    if [ -f "install.sh" ]; then
        chmod +x install.sh
        ./install.sh
        echo "✓ install.sh completed"
    else
        echo "⚠ install.sh not found, skipping..."
    fi
    
    # Step 2: Run setup_linux.sh
    echo ""
    echo "[Setup 2/4] Running setup_linux.sh..."
    if [ -f "setup_linux.sh" ]; then
        chmod +x setup_linux.sh
        ./setup_linux.sh
        echo "✓ setup_linux.sh completed"
    else
        echo "⚠ setup_linux.sh not found, skipping..."
    fi
    
    # Step 3: Create Python virtual environment
    echo ""
    echo "[Setup 3/4] Creating Python virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
    
    # Step 4: Install requirements
    echo ""
    echo "[Setup 4/4] Installing Python requirements..."
    source venv/bin/activate
    if [ -f "requirements.txt" ]; then
        pip install --upgrade pip
        pip install -r requirements.txt
        echo "✓ Requirements installed"
    else
        echo "⚠ requirements.txt not found, skipping..."
    fi
    deactivate
    
    echo ""
    echo "================================================================"
    echo "Initial setup completed successfully!"
    echo "================================================================"
    echo ""
    sleep 2
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# =============================================================================
# Configuration - ALWAYS ENABLED
# =============================================================================
ENABLE_ML="true"
ENABLE_PACKET_INSPECTION="true"  # Always enabled as requested
ENABLE_HTTP_SERVER="true"
ENABLE_INFERENCE_API="true"
ML_MODELS_DIR="${ML_MODELS_DIR:-ml_models}"
HTTP_PORT="${HTTP_PORT:-8080}"  # Use 8080 on macOS (80 requires more permissions)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-http)
            ENABLE_HTTP_SERVER="false"
            shift
            ;;
        --no-api)
            ENABLE_INFERENCE_API="false"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo ./start_macos.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-http    Skip starting HTTP server"
            echo "  --no-api     Skip starting Inference API"
            echo "  --help       Show this help message"
            echo ""
            echo "Environment Variables (optional - all are auto-detected):"
            echo "  NGFW_INTERFACE      Network interface (auto-detected if not set)"
            echo "  HTTP_PORT           HTTP server port (default: 8080)"
            echo "  ML_MODELS_DIR       ML models directory (default: ml_models)"
            echo ""
            echo "The script automatically detects:"
            echo "  - Active network interface"
            echo "  - Local IP address"
            echo "  - Network CIDR for Suricata"
            echo ""
            echo "Note: macOS does not support NFQUEUE, running in IDS mode"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run: ./start_macos.sh --help"
            exit 1
            ;;
    esac
done

# =============================================================================
# Banner
# =============================================================================
clear
echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║     ███╗   ██╗ ██████╗ ███████╗██╗    ██╗    ██████╗ ██████╗ ███████╗ ║"
echo "║     ████╗  ██║██╔════╝ ██╔════╝██║    ██║    ██╔══██╗██╔══██╗██╔════╝ ║"
echo "║     ██╔██╗ ██║██║  ███╗█████╗  ██║ █╗ ██║    ██║  ██║██████╔╝███████╗ ║"
echo "║     ██║╚██╗██║██║   ██║██╔══╝  ██║███╗██║    ██║  ██║██╔═══╝ ╚════██║ ║"
echo "║     ██║ ╚████║╚██████╔╝██║     ╚███╔███╔╝    ██████╔╝██║     ███████║ ║"
echo "║     ╚═╝  ╚═══╝ ╚═════╝ ╚═╝      ╚══╝╚══╝     ╚═════╝ ╚═╝     ╚══════╝ ║"
echo "║                                                                       ║"
echo "║          ML-Enhanced NGFW with Federated Learning - macOS             ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Root Check
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root for network monitoring${NC}"
    echo "Run: sudo ./start_macos.sh"
    exit 1
fi

# =============================================================================
# Virtual Environment Detection
# =============================================================================
# Check if we're in a venv and preserve it for sudo
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON_CMD="$VIRTUAL_ENV/bin/python3"
    echo -e "${GREEN}Using virtual environment: $VIRTUAL_ENV${NC}"
elif [ -f "venv/bin/python3" ]; then
    PYTHON_CMD="$SCRIPT_DIR/venv/bin/python3"
    echo -e "${GREEN}Using venv: $SCRIPT_DIR/venv${NC}"
elif [ -f "venv_test/bin/python3" ]; then
    PYTHON_CMD="$SCRIPT_DIR/venv_test/bin/python3"
    echo -e "${GREEN}Using venv_test: $SCRIPT_DIR/venv_test${NC}"
else
    PYTHON_CMD="python3"
    echo -e "${YELLOW}Using system Python${NC}"
fi

# =============================================================================
# Create Directories (use absolute paths)
# =============================================================================
LOGS_DIR="$SCRIPT_DIR/logs"
RULES_DIR="$SCRIPT_DIR/rules"
ML_MODELS_DIR="$SCRIPT_DIR/${ML_MODELS_DIR:-ml_models}"
FL_MODELS_DIR="$SCRIPT_DIR/fl_models"

mkdir -p "$LOGS_DIR" "$LOGS_DIR/reports" "$ML_MODELS_DIR" "$FL_MODELS_DIR" "$RULES_DIR"
chmod 755 "$LOGS_DIR" "$ML_MODELS_DIR" "$FL_MODELS_DIR" "$RULES_DIR"

echo -e "${GREEN}  ✓ Directories ready${NC}"

# =============================================================================
# Get Network Info - AUTO DETECTION (macOS)
# =============================================================================

# Auto-detect network interface on macOS
auto_detect_interface_macos() {
    # Method 1: Get interface from default route
    local iface=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
    if [ -n "$iface" ] && [ "$iface" != "lo0" ]; then
        echo "$iface"
        return
    fi
    
    # Method 2: Check common macOS interfaces
    for check_iface in en0 en1 en2 en3 en4; do
        if ifconfig "$check_iface" &>/dev/null; then
            status=$(ifconfig "$check_iface" | grep "status:" | awk '{print $2}')
            if [ "$status" = "active" ]; then
                echo "$check_iface"
                return
            fi
        fi
    done
    
    # Fallback: first active interface
    for check_iface in $(ifconfig -l); do
        if [ "$check_iface" != "lo0" ]; then
            status=$(ifconfig "$check_iface" 2>/dev/null | grep "status:" | awk '{print $2}')
            if [ "$status" = "active" ] || [ -z "$status" ]; then
                echo "$check_iface"
                return
            fi
        fi
    done
    
    echo "en0"
}

# Auto-detect IP address on macOS
auto_detect_ip_macos() {
    local iface=$1
    
    # Method 1: Get IP from interface
    local ip=$(ifconfig "$iface" 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
    if [ -n "$ip" ]; then
        echo "$ip"
        return
    fi
    
    # Method 2: hostname
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$ip" ] && [[ ! "$ip" =~ ^127\. ]]; then
        echo "$ip"
        return
    fi
    
    # Fallback
    echo "127.0.0.1"
}

# Use environment variable if set, otherwise auto-detect
if [ -n "$NGFW_INTERFACE" ]; then
    INTERFACE="$NGFW_INTERFACE"
    echo -e "${BLUE}Using environment interface: $INTERFACE${NC}"
else
    INTERFACE=$(auto_detect_interface_macos)
    echo -e "${BLUE}Auto-detected interface: $INTERFACE${NC}"
fi

IFACE_IP=$(auto_detect_ip_macos $INTERFACE)

# Detect network CIDR for Suricata
NETWORK_CIDR=$(ifconfig "$INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2"/"$4}' | head -1)
if [ -z "$NETWORK_CIDR" ] || [[ "$NETWORK_CIDR" == *"/"* ]]; then
    # Convert netmask to CIDR if needed
    NETMASK=$(ifconfig "$INTERFACE" 2>/dev/null | grep "inet " | awk '{print $4}' | head -1)
    if [ -n "$NETMASK" ]; then
        # Simple conversion for common netmasks
        case "$NETMASK" in
            0xffffff00) CIDR_BITS=24 ;;
            0xffff0000) CIDR_BITS=16 ;;
            0xff000000) CIDR_BITS=8 ;;
            *) CIDR_BITS=24 ;;
        esac
        NETWORK_PREFIX=$(echo $IFACE_IP | cut -d. -f1-3)
        NETWORK_CIDR="${NETWORK_PREFIX}.0/${CIDR_BITS}"
    else
        # Fallback: guess /24
        NETWORK_PREFIX=$(echo $IFACE_IP | cut -d. -f1-3)
        NETWORK_CIDR="${NETWORK_PREFIX}.0/24"
    fi
fi

echo -e "${BLUE}Network Configuration (Auto-Detected):${NC}"
echo -e "  Interface: ${YELLOW}$INTERFACE${NC}"
echo -e "  IP Address: ${YELLOW}$IFACE_IP${NC}"
echo -e "  Network: ${YELLOW}$NETWORK_CIDR${NC}"
echo ""
echo -e "${YELLOW}Note: macOS does not support NFQUEUE - running in IDS mode${NC}"
echo ""

# =============================================================================
# Kill Existing Processes
# =============================================================================
echo -e "${YELLOW}[0/8] Cleaning up existing processes...${NC}"
pkill -9 suricata 2>/dev/null || true
pkill -f "soar_engine.py" 2>/dev/null || true
pkill -f "unified_logger.py" 2>/dev/null || true
pkill -f "kafka_bridge.py" 2>/dev/null || true
pkill -f "packet_inspector.py" 2>/dev/null || true
pkill -f "uvicorn inference_api" 2>/dev/null || true
pkill -f "uvicorn.*eve_watcher" 2>/dev/null || true
pkill -f "eve_watcher.py" 2>/dev/null || true
pkill -f "python3 -m http.server" 2>/dev/null || true
sleep 2
echo -e "${GREEN}  ✓ Cleanup complete${NC}"

# =============================================================================
# Step 1: Setup pfctl (macOS firewall) - NO BLOCKING, JUST MONITORING
# =============================================================================
echo ""
echo -e "${YELLOW}[1/8] Configuring macOS packet filter (pfctl)...${NC}"

# macOS doesn't have NFQUEUE, so we just enable IP forwarding if needed
# This is mainly for documentation - Suricata will use AF_PACKET mode
sysctl -w net.inet.ip.forwarding=1 2>/dev/null || true

echo -e "${GREEN}  ✓ Packet forwarding enabled (IDS mode only)${NC}"
echo -e "${YELLOW}  ⓘ macOS limitation: Cannot intercept/drop packets like Linux NFQUEUE${NC}"

# =============================================================================
# Step 1.5: Generate suricata.yaml with detected interface (macOS)
# =============================================================================
echo ""
echo -e "${YELLOW}[1.5/8] Generating suricata.yaml for macOS...${NC}"

cat > "$SCRIPT_DIR/suricata_runtime.yaml" << EOF
%YAML 1.1
---
# Suricata IDS Mode Configuration - macOS (AUTO-GENERATED)
# Interface: $INTERFACE
# Network: $NETWORK_CIDR
# Generated: $(date)

vars:
  address-groups:
    HOME_NET: "[$NETWORK_CIDR,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "any"
    HTTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    SSH_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,443"
    SSH_PORTS: 22
    FTP_PORTS: 21
    DNS_PORTS: 53

default-log-dir: $LOGS_DIR

stats:
  enabled: yes
  interval: 10

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      pcap-file: false
      types:
        - alert:
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - flow:
            enabled: yes
        - netflow:
            enabled: no
        - anomaly:
            enabled: yes
            types:
              - decode
              - stream
              - applayer
        - stats:
            totals: yes
            threads: yes
            deltas: yes

  - fast:
      enabled: yes
      filename: fast.log

  - stats:
      enabled: yes
      filename: stats.log

# PCAP mode for macOS (best compatibility)
pcap:
  - interface: $INTERFACE
    checksum-checks: no

# Rules
default-rule-path: $SCRIPT_DIR
rule-files:
  - $RULES_DIR/local.rules

classification-file: $SCRIPT_DIR/classification.config
reference-config-file: $SCRIPT_DIR/reference.config

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-inspect-window: 4kb
          response-body-inspect-window: 16kb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    ssh:
      enabled: yes
    ftp:
      enabled: yes
    smtp:
      enabled: yes

detect:
  profile: medium
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

stream:
  memcap: 128mb
  checksum-validation: no
  inline: no
  reassembly:
    memcap: 256mb
    depth: 1mb

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000

host:
  memcap: 32mb
  hash-size: 4096
  prealloc: 1000

defrag:
  memcap: 32mb
  hash-size: 65536
  prealloc: 1000

logging:
  default-log-level: info
  default-output-filter:
  outputs:
    - console:
        enabled: yes
        type: json
    - file:
        enabled: yes
        level: info
        filename: suricata.log

coredump:
  max-dump: unlimited

host-mode: auto

unix-command:
  enabled: no
EOF

echo -e "${GREEN}  ✓ Generated suricata_runtime.yaml for interface: $INTERFACE${NC}"

# =============================================================================
# Step 2: Start Suricata IDS (AF_PACKET mode for macOS)
# =============================================================================

echo ""
echo -e "${YELLOW}[2/8] Starting Suricata in IDS mode (AF_PACKET)...${NC}"

# Check if Suricata is installed
if ! command -v suricata &> /dev/null; then
    echo -e "${RED}  ✗ Suricata not found${NC}"
    echo -e "${YELLOW}  Install with: brew install suricata${NC}"
    exit 1
fi

# Clear eve.json to ensure we see fresh events
echo "[]" > "$LOGS_DIR/eve.json" 2>/dev/null || true

# Start Suricata in PCAP (IDS) mode with runtime config (absolute paths)
echo -e "${BLUE}  Starting: suricata -c suricata_runtime.yaml -i $INTERFACE${NC}"
suricata -c "$SCRIPT_DIR/suricata_runtime.yaml" -i "$INTERFACE" -l "$LOGS_DIR" -vv -D --pidfile "$LOGS_DIR/suricata.pid" 2>&1 | tee "$LOGS_DIR/suricata_startup.log"

sleep 4

if pgrep -f "suricata" > /dev/null; then
    SURI_PID=$(cat "$LOGS_DIR/suricata.pid" 2>/dev/null || pgrep -f "suricata" | head -1)
    echo -e "${GREEN}  ✓ Suricata IDS running (PID: $SURI_PID)${NC}"
    echo -e "${BLUE}    Mode: PCAP on interface $INTERFACE${NC}"
    echo -e "${YELLOW}  ⓘ IDS mode: Detects but cannot block traffic on macOS${NC}"
    
    # Verify eve.json is being written
    sleep 2
    if [ -f "$LOGS_DIR/eve.json" ] && [ -s "$LOGS_DIR/eve.json" ]; then
        echo -e "${GREEN}  ✓ eve.json is being written${NC}"
    else
        echo -e "${YELLOW}  ⚠ eve.json not yet populated (may take a few seconds)${NC}"
    fi
else
    echo -e "${RED}  ✗ Suricata failed to start${NC}"
    echo "Check $LOGS_DIR/suricata.log and $LOGS_DIR/suricata_startup.log for errors"
    echo ""
    echo "Startup log:"
    tail -20 "$LOGS_DIR/suricata_startup.log" 2>/dev/null || echo "No startup log available"
    exit 1
fi

# =============================================================================
# Step 3: Start HTTP Server (for testing)
# =============================================================================
echo ""
if [ "$ENABLE_HTTP_SERVER" = "true" ]; then
    echo -e "${YELLOW}[3/8] Starting HTTP Server on port $HTTP_PORT...${NC}"
    
    nohup $PYTHON_CMD -m http.server $HTTP_PORT > logs/http_server.out 2>&1 &
    HTTP_PID=$!
    echo $HTTP_PID > logs/http_server.pid
    sleep 1
    
    if ps -p $HTTP_PID > /dev/null 2>&1; then
        echo -e "${GREEN}  ✓ HTTP Server started (PID: $HTTP_PID)${NC}"
        echo -e "${BLUE}    URL: http://$IFACE_IP:$HTTP_PORT${NC}"
    else
        echo -e "${YELLOW}  ⚠ HTTP Server failed (may need different port)${NC}"
    fi
else
    echo -e "${YELLOW}[3/8] HTTP Server skipped (--no-http)${NC}"
fi

# =============================================================================
# Step 4: Start Unified Logger
# =============================================================================
echo ""
echo -e "${YELLOW}[4/8] Starting Unified Logger...${NC}"

nohup $PYTHON_CMD unified_logger.py > logs/unified_logger.out 2>&1 &
LOGGER_PID=$!
echo $LOGGER_PID > logs/unified_logger.pid
sleep 1

if ps -p $LOGGER_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ Unified Logger started (PID: $LOGGER_PID)${NC}"
else
    echo -e "${YELLOW}  ⚠ Unified Logger failed to start${NC}"
fi

# =============================================================================
# Step 5: Start SOAR Engine (with ML and Packet Inspection)
# =============================================================================
echo ""
echo -e "${YELLOW}[5/8] Starting SOAR Engine (ML + Packet Inspection)...${NC}"

# Build SOAR command - ALWAYS enable ML and packet inspection
SOAR_CMD="$PYTHON_CMD soar_engine.py --file-mode --ml-models-dir $ML_MODELS_DIR"
SOAR_CMD="$SOAR_CMD --packet-inspection --interface $INTERFACE"

nohup $SOAR_CMD > logs/soar.out 2>&1 &
SOAR_PID=$!
echo $SOAR_PID > logs/soar.pid
sleep 2

if ps -p $SOAR_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ SOAR Engine started (PID: $SOAR_PID)${NC}"
    echo -e "${BLUE}    ML Models: $ML_MODELS_DIR${NC}"
    echo -e "${BLUE}    Packet Inspection: ENABLED${NC}"
else
    echo -e "${YELLOW}  ⚠ SOAR Engine failed to start${NC}"
    echo "    Check logs/soar.out for errors"
fi

# =============================================================================
# Step 6: Start Inference API (Federated Learning)
# =============================================================================
echo ""
if [ "$ENABLE_INFERENCE_API" = "true" ]; then
    echo -e "${YELLOW}[6/8] Starting Inference API (Federated Learning)...${NC}"
    
    # Try to start inference API (will work if dependencies are installed)
    nohup $PYTHON_CMD inference_api.py > logs/inference_api.out 2>&1 &
    API_PID=$!
    echo $API_PID > logs/inference_api.pid
    sleep 3
    
    if ps -p $API_PID > /dev/null 2>&1; then
        echo -e "${GREEN}  ✓ Inference API started (PID: $API_PID)${NC}"
        echo -e "${BLUE}    URL: http://localhost:8001${NC}"
        echo -e "${BLUE}    Health: http://localhost:8001/health${NC}"
        echo -e "${BLUE}    Docs: http://localhost:8001/docs${NC}"
    else
        echo -e "${YELLOW}  ⚠ Inference API failed to start${NC}"
        echo -e "${YELLOW}    Check logs/inference_api.out for errors${NC}"
        echo -e "${YELLOW}    Install with: pip install uvicorn fastapi${NC}"
    fi
else
    echo -e "${YELLOW}[6/8] Inference API skipped (--no-api)${NC}"
fi

# =============================================================================
# Step 7: Start Eve Watcher (WebSocket stream for eve.json)
# =============================================================================
echo ""
echo -e "${YELLOW}[7/8] Starting Eve Watcher (WebSocket stream)...${NC}"

nohup $PYTHON_CMD eve_watcher.py > logs/eve_watcher.out 2>&1 &
EVE_WATCHER_PID=$!
echo $EVE_WATCHER_PID > logs/eve_watcher.pid
sleep 2

if ps -p $EVE_WATCHER_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ Eve Watcher started (PID: $EVE_WATCHER_PID)${NC}"
    echo -e "${BLUE}    WebSocket: ws://localhost:8000/ws/logs${NC}"
    echo -e "${BLUE}    Health: http://localhost:8000/health${NC}"
    echo -e "${BLUE}    Stats: http://localhost:8000/stats${NC}"
else
    echo -e "${YELLOW}  ⚠ Eve Watcher failed to start${NC}"
    echo -e "${YELLOW}    Check logs/eve_watcher.out for errors${NC}"
fi

# =============================================================================
# Step 8: Start Kafka Bridge (optional)
# =============================================================================
echo ""
echo -e "${YELLOW}[8/8] Starting Kafka Bridge...${NC}"

nohup $PYTHON_CMD kafka_bridge.py > logs/bridge.out 2>&1 &
BRIDGE_PID=$!
echo $BRIDGE_PID > logs/bridge.pid
sleep 1

if ps -p $BRIDGE_PID > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ Kafka Bridge started (PID: $BRIDGE_PID)${NC}"
else
    echo -e "${YELLOW}  ⚠ Kafka Bridge not running (Kafka may not be available)${NC}"
fi

# =============================================================================
# Step 8: Check ML Models
# =============================================================================
echo ""
echo -e "${YELLOW}[8/8] Checking ML Models...${NC}"

# Count different model types
PKL_MODEL_COUNT=$(find "$ML_MODELS_DIR" -maxdepth 1 -name "*.pkl" -o -name "*.joblib" 2>/dev/null | wc -l | tr -d ' ')
H5_MODEL_COUNT=$(find "$ML_MODELS_DIR" -maxdepth 1 -name "*.h5" 2>/dev/null | wc -l | tr -d ' ')
TFLITE_MODEL_COUNT=$(find "$ML_MODELS_DIR" -maxdepth 1 -name "*.tflite" 2>/dev/null | wc -l | tr -d ' ')

# Count models in subdirectories (like backdoor_detection)
SUBDIR_MODEL_COUNT=$(find "$ML_MODELS_DIR" -mindepth 2 -name "*.pkl" -o -name "*.joblib" -o -name "*.h5" -o -name "*.tflite" 2>/dev/null | wc -l | tr -d ' ')

ML_MODEL_COUNT=$((PKL_MODEL_COUNT + H5_MODEL_COUNT + TFLITE_MODEL_COUNT + SUBDIR_MODEL_COUNT))

FL_MODEL_COUNT=$(find "fl_models" -name "*.pkl" -o -name "*.joblib" 2>/dev/null | wc -l | tr -d ' ')

if [ "$ML_MODEL_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Found $ML_MODEL_COUNT ML model(s) in $ML_MODELS_DIR${NC}"
    echo -e "${BLUE}    PKL/Joblib: $PKL_MODEL_COUNT, H5: $H5_MODEL_COUNT, TFLite: $TFLITE_MODEL_COUNT, Subdirs: $SUBDIR_MODEL_COUNT${NC}"
    
    # List all models
    for model in "$ML_MODELS_DIR"/*.pkl "$ML_MODELS_DIR"/*.joblib "$ML_MODELS_DIR"/*.h5 "$ML_MODELS_DIR"/*.tflite; do
        [ -f "$model" ] && echo -e "${BLUE}    - $(basename $model)${NC}"
    done 2>/dev/null
    
    # List subdirectory models
    for subdir in "$ML_MODELS_DIR"/*/; do
        if [ -d "$subdir" ]; then
            subdir_name=$(basename "$subdir")
            subdir_count=$(find "$subdir" -name "*.pkl" -o -name "*.joblib" -o -name "*.h5" -o -name "*.tflite" 2>/dev/null | wc -l | tr -d ' ')
            if [ "$subdir_count" -gt 0 ]; then
                echo -e "${BLUE}    - $subdir_name/ ($subdir_count files)${NC}"
            fi
        fi
    done 2>/dev/null
else
    echo -e "${YELLOW}  ⚠ No ML models in $ML_MODELS_DIR${NC}"
fi

if [ "$FL_MODEL_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Found $FL_MODEL_COUNT FL model(s) in fl_models/${NC}"
else
    echo -e "${YELLOW}  ⚠ No FL models in fl_models/ (run FL client to train)${NC}"
fi

# =============================================================================
# Final Summary
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                     NGFW IDS MODE ACTIVE (macOS)                      ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}✓${NC} Suricata IDS monitoring traffic on $INTERFACE"
echo -e "${YELLOW}⚠${NC} IDS mode only: ${YELLOW}Cannot block packets on macOS${NC}"
echo -e "${GREEN}✓${NC} ML threat detection is ${GREEN}ENABLED${NC}"
echo -e "${GREEN}✓${NC} Packet inspection is ${GREEN}ENABLED${NC}"
echo -e "${GREEN}✓${NC} SOAR orchestration is ${GREEN}ACTIVE${NC}"
if [ "$ENABLE_HTTP_SERVER" = "true" ]; then
    echo -e "${GREEN}✓${NC} HTTP server on port ${YELLOW}$HTTP_PORT${NC}"
fi
if [ "$ENABLE_INFERENCE_API" = "true" ]; then
    echo -e "${GREEN}✓${NC} Inference API on port ${YELLOW}8001${NC}"
fi

echo ""
echo -e "${BOLD}Logs:${NC}"
echo "  Suricata:       logs/eve.json"
echo "  ML Predictions: logs/ml_predictions.json"
echo "  Unified Events: logs/unified_events.json"
echo "  SOAR Actions:   logs/soar_actions.log"
echo "  SOAR Engine:    logs/soar_engine.log"

echo ""
echo -e "${BOLD}Test Attack:${NC}"
echo -e "  ${CYAN}python3 attack_test.py --target $IFACE_IP --full${NC}"

echo ""
echo -e "${BOLD}Monitor:${NC}"
echo -e "  ${CYAN}python3 status.py${NC}"
echo -e "  ${CYAN}tail -f logs/unified_events.json${NC}"
echo -e "  ${CYAN}tail -f logs/eve.json${NC}"

echo ""
echo -e "${BOLD}To stop all services: ${CYAN}sudo ./stop_macos.sh${NC}"
echo ""
