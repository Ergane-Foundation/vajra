#!/bin/bash
# =============================================================================
# Quick Verification Script - Test Network Flow Fix
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}VAJRA Network Flow Fix Verification${NC}"
echo "======================================"
echo ""

# Detect OS
OS_TYPE="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="macos"
    STARTUP_SCRIPT="./start_macos.sh"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS_TYPE="linux"
    STARTUP_SCRIPT="./start.sh"
fi

echo -e "${BLUE}Detected OS:${NC} $OS_TYPE"
echo -e "${BLUE}Will use:${NC} $STARTUP_SCRIPT"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root${NC}"
    echo "Run: sudo $0"
    exit 1
fi

# Auto-detect interface
echo -e "${YELLOW}Step 1: Auto-detecting network interface...${NC}"
if [ "$OS_TYPE" = "macos" ]; then
    INTERFACE=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
    if [ -z "$INTERFACE" ]; then
        INTERFACE="en0"
    fi
    IP=$(ifconfig "$INTERFACE" 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
else
    INTERFACE=$(ip route show default 2>/dev/null | grep -oP 'dev\s+\K\S+' | head -1)
    if [ -z "$INTERFACE" ]; then
        INTERFACE="eth0"
    fi
    IP=$(ip -4 addr show $INTERFACE 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
fi

echo -e "  ${GREEN}✓${NC} Interface: ${CYAN}$INTERFACE${NC}"
echo -e "  ${GREEN}✓${NC} IP Address: ${CYAN}$IP${NC}"
echo ""

# Test packet capture capability
echo -e "${YELLOW}Step 2: Testing packet capture capability...${NC}"
if command -v tcpdump &> /dev/null; then
    echo -e "  Testing 2-second packet capture on $INTERFACE..."
    CAPTURE_OUT=$(timeout 2 tcpdump -i "$INTERFACE" -c 10 2>&1 | grep "packets captured" || echo "0 packets captured")
    PACKET_COUNT=$(echo "$CAPTURE_OUT" | grep -o '[0-9]* packets captured' | awk '{print $1}')
    
    if [ -n "$PACKET_COUNT" ] && [ "$PACKET_COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} Captured $PACKET_COUNT packets - interface is working!"
    else
        echo -e "  ${RED}✗${NC} No packets captured - there may be an issue"
        echo -e "  ${YELLOW}Note: This could be normal if there's no traffic right now${NC}"
    fi
else
    echo -e "  ${YELLOW}⚠${NC} tcpdump not available - skipping test"
fi
echo ""

# Check Suricata installation
echo -e "${YELLOW}Step 3: Checking Suricata installation...${NC}"
if command -v suricata &> /dev/null; then
    SURI_VERSION=$(suricata --version 2>&1 | head -1)
    echo -e "  ${GREEN}✓${NC} Suricata installed: ${CYAN}$SURI_VERSION${NC}"
else
    echo -e "  ${RED}✗${NC} Suricata not found"
    if [ "$OS_TYPE" = "macos" ]; then
        echo -e "  ${YELLOW}Install with: brew install suricata${NC}"
    else
        echo -e "  ${YELLOW}Install with: sudo apt install suricata${NC}"
    fi
    exit 1
fi
echo ""

# Check Python environment
echo -e "${YELLOW}Step 4: Checking Python environment...${NC}"
if [ -d "venv" ] || [ -d "venv_test" ]; then
    echo -e "  ${GREEN}✓${NC} Virtual environment found"
else
    echo -e "  ${YELLOW}⚠${NC} No virtual environment - will be created on first run"
fi
echo ""

# Summary
echo -e "${BOLD}${GREEN}Pre-flight checks complete!${NC}"
echo ""
echo -e "${BOLD}Next Steps:${NC}"
echo -e "1. Start the firewall:"
echo -e "   ${CYAN}sudo $STARTUP_SCRIPT${NC}"
echo ""
echo -e "2. In another terminal, monitor eve.json:"
echo -e "   ${CYAN}tail -f logs/eve.json${NC}"
echo ""
echo -e "3. Generate test traffic:"
echo -e "   ${CYAN}curl http://www.google.com${NC}"
echo -e "   ${CYAN}curl https://www.github.com${NC}"
echo ""
echo -e "4. Run diagnostics:"
echo -e "   ${CYAN}./diagnose_network.sh${NC}"
echo ""
echo -e "5. Check system status:"
echo -e "   ${CYAN}python3 status.py${NC}"
echo ""
echo -e "${BOLD}${YELLOW}Key Fix Applied:${NC}"
if [ "$OS_TYPE" = "macos" ]; then
    echo -e "  • Auto-detects interface (currently: ${CYAN}$INTERFACE${NC})"
    echo -e "  • Uses PCAP mode (macOS compatible)"
    echo -e "  • Enables all eve.json event types"
    echo -e "  • Proper flow logging configured"
else
    echo -e "  • Auto-detects interface (currently: ${CYAN}$INTERFACE${NC})"
    echo -e "  • Uses NFQUEUE mode (Linux IPS)"
    echo -e "  • Enables all eve.json event types"
    echo -e "  • Proper flow logging configured"
fi
echo ""
