#!/bin/bash
# =============================================================================
# VAJRA Network Flow Diagnostics
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

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║        VAJRA Network Flow Diagnostics                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS
OS_TYPE="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_TYPE="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS_TYPE="linux"
fi

echo -e "${BLUE}Operating System:${NC} $OS_TYPE"
echo ""

# =============================================================================
# 1. Check Suricata Process
# =============================================================================
echo -e "${YELLOW}1️⃣  Suricata Process Status:${NC}"
if pgrep -f suricata > /dev/null; then
    SURI_PID=$(pgrep -f suricata | head -1)
    SURI_CMD=$(ps -p $SURI_PID -o command= 2>/dev/null)
    echo -e "  ${GREEN}✓${NC} Suricata is running"
    echo -e "    PID: ${CYAN}$SURI_PID${NC}"
    echo -e "    Command: ${CYAN}$SURI_CMD${NC}"
else
    echo -e "  ${RED}✗${NC} Suricata is NOT running"
fi
echo ""

# =============================================================================
# 2. Network Interfaces
# =============================================================================
echo -e "${YELLOW}2️⃣  Network Interfaces:${NC}"
if [ "$OS_TYPE" = "macos" ]; then
    # macOS
    for iface in $(ifconfig -l); do
        if [ "$iface" != "lo0" ]; then
            status=$(ifconfig "$iface" 2>/dev/null | grep "status:" | awk '{print $2}')
            inet=$(ifconfig "$iface" 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
            if [ "$status" = "active" ] || [ -n "$inet" ]; then
                echo -e "  ${GREEN}✓${NC} $iface - Status: ${GREEN}$status${NC}, IP: ${CYAN}${inet:-none}${NC}"
            fi
        fi
    done
    
    # Default route interface
    DEFAULT_IFACE=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
    if [ -n "$DEFAULT_IFACE" ]; then
        echo -e "  ${BLUE}ℹ${NC}  Default route interface: ${CYAN}$DEFAULT_IFACE${NC}"
    fi
else
    # Linux
    for iface in $(ls /sys/class/net 2>/dev/null); do
        if [ "$iface" != "lo" ]; then
            state=$(cat /sys/class/net/$iface/operstate 2>/dev/null)
            inet=$(ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
            if [ "$state" = "up" ]; then
                echo -e "  ${GREEN}✓${NC} $iface - State: ${GREEN}$state${NC}, IP: ${CYAN}${inet:-none}${NC}"
            fi
        fi
    done
    
    # Default route interface
    DEFAULT_IFACE=$(ip route show default 2>/dev/null | grep -oP 'dev\s+\K\S+' | head -1)
    if [ -n "$DEFAULT_IFACE" ]; then
        echo -e "  ${BLUE}ℹ${NC}  Default route interface: ${CYAN}$DEFAULT_IFACE${NC}"
    fi
fi
echo ""

# =============================================================================
# 3. Check eve.json
# =============================================================================
echo -e "${YELLOW}3️⃣  Suricata eve.json Status:${NC}"
EVE_FILE="logs/eve.json"

if [ -f "$EVE_FILE" ]; then
    LINE_COUNT=$(wc -l < "$EVE_FILE" 2>/dev/null | tr -d ' ')
    FILE_SIZE=$(ls -lh "$EVE_FILE" 2>/dev/null | awk '{print $5}')
    FILE_AGE=$(stat -f "%Sm" "$EVE_FILE" 2>/dev/null || stat -c "%y" "$EVE_FILE" 2>/dev/null)
    
    echo -e "  ${GREEN}✓${NC} eve.json exists"
    echo -e "    Lines: ${CYAN}$LINE_COUNT${NC}"
    echo -e "    Size: ${CYAN}$FILE_SIZE${NC}"
    echo -e "    Last modified: ${CYAN}$FILE_AGE${NC}"
    
    if [ "$LINE_COUNT" -gt 0 ]; then
        echo ""
        echo -e "  ${BLUE}Last 3 events:${NC}"
        tail -n 3 "$EVE_FILE" | while read line; do
            event_type=$(echo "$line" | grep -o '"event_type":"[^"]*"' | cut -d'"' -f4)
            timestamp=$(echo "$line" | grep -o '"timestamp":"[^"]*"' | cut -d'"' -f4)
            echo -e "    • Type: ${CYAN}$event_type${NC}, Time: ${YELLOW}$timestamp${NC}"
        done
    else
        echo -e "  ${RED}⚠${NC}  File is empty - no events captured yet"
    fi
else
    echo -e "  ${RED}✗${NC} eve.json not found"
    echo -e "    Expected location: ${CYAN}$SCRIPT_DIR/$EVE_FILE${NC}"
fi
echo ""

# =============================================================================
# 4. Check WebSocket Server
# =============================================================================
echo -e "${YELLOW}4️⃣  WebSocket Server (Unified Logger):${NC}"
if pgrep -f "vajra.pipeline.unified_logger" > /dev/null; then
    LOGGER_PID=$(pgrep -f "vajra.pipeline.unified_logger" | head -1)
    echo -e "  ${GREEN}✓${NC} Unified Logger is running (PID: $LOGGER_PID)"
    
    # Check if port 8765 is listening
    if [ "$OS_TYPE" = "macos" ]; then
        if lsof -i :8765 2>/dev/null | grep -q LISTEN; then
            echo -e "  ${GREEN}✓${NC} WebSocket listening on port 8765"
        else
            echo -e "  ${RED}⚠${NC}  Port 8765 not listening"
        fi
    else
        if netstat -tuln 2>/dev/null | grep -q ":8765 " || ss -tuln 2>/dev/null | grep -q ":8765 "; then
            echo -e "  ${GREEN}✓${NC} WebSocket listening on port 8765"
        else
            echo -e "  ${RED}⚠${NC}  Port 8765 not listening"
        fi
    fi
else
    echo -e "  ${RED}✗${NC} Unified Logger is NOT running"
fi
echo ""

# =============================================================================
# 5. Check Suricata Rules
# =============================================================================
echo -e "${YELLOW}5️⃣  Suricata Rules:${NC}"
RULES_FILE="rules/local.rules"

if [ -f "$RULES_FILE" ]; then
    RULE_COUNT=$(grep -c '^alert' "$RULES_FILE" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${NC} Rules file exists: $RULES_FILE"
    echo -e "    Alert rules: ${CYAN}$RULE_COUNT${NC}"
else
    echo -e "  ${RED}✗${NC} Rules file not found: $RULES_FILE"
fi
echo ""

# =============================================================================
# 6. Test Packet Capture Permission
# =============================================================================
echo -e "${YELLOW}6️⃣  Packet Capture Test:${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "  ${YELLOW}⚠${NC}  Not running as root - cannot test packet capture"
else
    # Get interface
    if [ "$OS_TYPE" = "macos" ]; then
        TEST_IFACE=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
        [ -z "$TEST_IFACE" ] && TEST_IFACE="en0"
    else
        TEST_IFACE=$(ip route show default 2>/dev/null | grep -oP 'dev\s+\K\S+' | head -1)
        [ -z "$TEST_IFACE" ] && TEST_IFACE="eth0"
    fi
    
    echo -e "  Testing on interface: ${CYAN}$TEST_IFACE${NC}"
    
    if command -v tcpdump &> /dev/null; then
        TCPDUMP_OUT=$(timeout 2 tcpdump -i "$TEST_IFACE" -c 5 2>&1 || true)
        PACKET_COUNT=$(echo "$TCPDUMP_OUT" | grep -o '[0-9]* packets captured' | awk '{print $1}')
        
        if [ -n "$PACKET_COUNT" ] && [ "$PACKET_COUNT" -gt 0 ]; then
            echo -e "  ${GREEN}✓${NC} Packet capture working - captured $PACKET_COUNT packets"
        else
            echo -e "  ${RED}⚠${NC}  No packets captured - possible permission or interface issue"
        fi
    else
        echo -e "  ${YELLOW}⚠${NC}  tcpdump not available - skipping test"
    fi
fi
echo ""

# =============================================================================
# 7. Check Suricata Configuration
# =============================================================================
echo -e "${YELLOW}7️⃣  Suricata Configuration:${NC}"
SURI_CONFIG="suricata_runtime.yaml"

if [ -f "$SURI_CONFIG" ]; then
    echo -e "  ${GREEN}✓${NC} Configuration file exists: $SURI_CONFIG"
    
    # Extract interface from config
    CONFIG_IFACE=$(grep -E '^\s+interface:' "$SURI_CONFIG" | head -1 | awk '{print $2}' | tr -d '"')
    if [ -n "$CONFIG_IFACE" ]; then
        echo -e "    Configured interface: ${CYAN}$CONFIG_IFACE${NC}"
    fi
    
    # Check if eve-log is enabled
    EVE_ENABLED=$(grep -A 1 'eve-log:' "$SURI_CONFIG" | grep 'enabled:' | awk '{print $2}')
    if [ "$EVE_ENABLED" = "yes" ]; then
        echo -e "    Eve logging: ${GREEN}enabled${NC}"
    else
        echo -e "    Eve logging: ${RED}disabled${NC}"
    fi
    
    # Check capture mode
    if grep -q 'nfqueue:' "$SURI_CONFIG"; then
        echo -e "    Mode: ${CYAN}NFQUEUE (IPS)${NC}"
    elif grep -q 'af-packet:' "$SURI_CONFIG"; then
        echo -e "    Mode: ${CYAN}AF_PACKET (IDS)${NC}"
    elif grep -q 'pcap:' "$SURI_CONFIG"; then
        echo -e "    Mode: ${CYAN}PCAP (IDS)${NC}"
    fi
else
    echo -e "  ${RED}✗${NC} Configuration file not found: $SURI_CONFIG"
fi
echo ""

# =============================================================================
# 8. Traffic Generation Test
# =============================================================================
echo -e "${YELLOW}8️⃣  Quick Traffic Test:${NC}"
echo -e "  Generating test traffic..."

# Generate some traffic
curl -s --max-time 2 http://www.google.com > /dev/null 2>&1 &
curl -s --max-time 2 https://www.github.com > /dev/null 2>&1 &
ping -c 3 8.8.8.8 > /dev/null 2>&1 &

wait
sleep 1

# Check if new events appeared
if [ -f "$EVE_FILE" ]; then
    NEW_LINE_COUNT=$(wc -l < "$EVE_FILE" 2>/dev/null | tr -d ' ')
    if [ "$NEW_LINE_COUNT" -gt "$LINE_COUNT" ]; then
        DIFF=$((NEW_LINE_COUNT - LINE_COUNT))
        echo -e "  ${GREEN}✓${NC} New events detected! (+$DIFF events)"
    else
        echo -e "  ${RED}⚠${NC}  No new events - Suricata may not be capturing traffic"
    fi
else
    echo -e "  ${RED}⚠${NC}  Cannot verify - eve.json not found"
fi
echo ""

# =============================================================================
# Summary & Recommendations
# =============================================================================
echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Diagnostic Summary                         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

ISSUES=0

if ! pgrep -f suricata > /dev/null; then
    echo -e "${RED}✗${NC} Suricata is not running"
    echo -e "  → Start with: ${CYAN}sudo ./start.sh${NC} (Linux) or ${CYAN}sudo ./start_macos.sh${NC} (macOS)"
    ISSUES=$((ISSUES + 1))
fi

if [ ! -f "$EVE_FILE" ] || [ "$(wc -l < "$EVE_FILE" 2>/dev/null)" -eq 0 ]; then
    echo -e "${RED}✗${NC} No events in eve.json"
    echo -e "  → Check Suricata config and restart"
    ISSUES=$((ISSUES + 1))
fi

if ! pgrep -f "vajra.pipeline.unified_logger" > /dev/null; then
    echo -e "${RED}✗${NC} Unified Logger not running"
    echo -e "  → WebSocket events will not be available"
    ISSUES=$((ISSUES + 1))
fi

if [ "$ISSUES" -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All checks passed! System appears to be working correctly."
else
    echo -e "${YELLOW}⚠${NC}  Found $ISSUES issue(s) - see recommendations above"
fi

echo ""
