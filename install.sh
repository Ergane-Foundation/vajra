#!/bin/bash
# =============================================================================
# NGFW Complete Installation Script
# =============================================================================
#
# Installs all dependencies for the ML-Enhanced NGFW with Federated Learning
#
# Usage:
#   sudo ./install.sh           # Full installation
#   sudo ./install.sh --minimal # Skip Kafka, just basic deps
#   sudo ./install.sh --help    # Show help
#
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

MINIMAL_INSTALL="false"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            MINIMAL_INSTALL="true"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --minimal  Skip Kafka installation (basic setup only)"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║           NGFW INSTALLATION - ML Enhanced with Federated Learning     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Root Check
# =============================================================================
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root${NC}"
    echo "Run: sudo ./install.sh"
    exit 1
fi

# =============================================================================
# Detect Package Manager
# =============================================================================
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
    UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    UPDATE_CMD="dnf check-update || true"
    INSTALL_CMD="dnf install -y"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    UPDATE_CMD="yum check-update || true"
    INSTALL_CMD="yum install -y"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    UPDATE_CMD="pacman -Sy"
    INSTALL_CMD="pacman -S --noconfirm"
else
    echo -e "${RED}Error: No supported package manager found (apt/dnf/yum/pacman)${NC}"
    exit 1
fi

echo -e "${BLUE}Package Manager: $PKG_MANAGER${NC}"
echo ""

# =============================================================================
# Step 1: Update Package Lists
# =============================================================================
echo -e "${YELLOW}[1/7] Updating package lists...${NC}"
$UPDATE_CMD
echo -e "${GREEN}  ✓ Package lists updated${NC}"

# =============================================================================
# Step 2: Install System Dependencies
# =============================================================================
echo ""
echo -e "${YELLOW}[2/7] Installing system dependencies...${NC}"

if [ "$PKG_MANAGER" = "apt-get" ]; then
    apt-get install -y \
        python3 python3-pip python3-venv python3-dev \
        build-essential libffi-dev libssl-dev \
        curl wget git jq \
        net-tools iptables iproute2 \
        libpcap-dev tcpdump
elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
    $INSTALL_CMD \
        python3 python3-pip python3-devel \
        gcc gcc-c++ libffi-devel openssl-devel \
        curl wget git jq \
        net-tools iptables iproute \
        libpcap-devel tcpdump
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S --noconfirm \
        python python-pip \
        base-devel libffi openssl \
        curl wget git jq \
        net-tools iptables iproute2 \
        libpcap tcpdump
fi

echo -e "${GREEN}  ✓ System dependencies installed${NC}"

# =============================================================================
# Step 3: Install Suricata
# =============================================================================
echo ""
echo -e "${YELLOW}[3/7] Installing Suricata IDS/IPS...${NC}"

if [ "$PKG_MANAGER" = "apt-get" ]; then
    # Add Suricata PPA for latest version
    add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
    apt-get update
    apt-get install -y suricata suricata-update
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install -y suricata
elif [ "$PKG_MANAGER" = "yum" ]; then
    yum install -y epel-release
    yum install -y suricata
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S --noconfirm suricata
fi

# Verify Suricata
if command -v suricata &> /dev/null; then
    SURICATA_VERSION=$(suricata -V 2>&1 | grep -oP 'Suricata version \K[0-9.]+' || echo "unknown")
    echo -e "${GREEN}  ✓ Suricata installed (version: $SURICATA_VERSION)${NC}"
else
    echo -e "${RED}  ✗ Suricata installation failed${NC}"
fi

# Update Suricata rules
suricata-update 2>/dev/null || echo -e "${YELLOW}  ⚠ suricata-update not available, using local rules only${NC}"

# =============================================================================
# Step 4: Install Kafka (Optional)
# =============================================================================
echo ""
if [ "$MINIMAL_INSTALL" = "false" ]; then
    echo -e "${YELLOW}[4/7] Installing Kafka (optional, for distributed mode)...${NC}"
    
    # Install Java first
    if [ "$PKG_MANAGER" = "apt-get" ]; then
        apt-get install -y default-jdk
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        $INSTALL_CMD java-11-openjdk java-11-openjdk-devel
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        pacman -S --noconfirm jdk-openjdk
    fi
    
    # Download and install Kafka
    KAFKA_VERSION="3.6.1"
    SCALA_VERSION="2.13"
    KAFKA_DIR="/opt/kafka"
    
    if [ ! -d "$KAFKA_DIR" ]; then
        cd /tmp
        wget -q "https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz" -O kafka.tgz 2>/dev/null || \
        wget -q "https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/kafka_${SCALA_VERSION}-${KAFKA_VERSION}.tgz" -O kafka.tgz 2>/dev/null || \
        echo -e "${YELLOW}  ⚠ Kafka download failed (optional, system will work without it)${NC}"
        
        if [ -f kafka.tgz ]; then
            tar -xzf kafka.tgz
            mv "kafka_${SCALA_VERSION}-${KAFKA_VERSION}" "$KAFKA_DIR"
            rm kafka.tgz
            echo -e "${GREEN}  ✓ Kafka installed to $KAFKA_DIR${NC}"
        fi
    else
        echo -e "${GREEN}  ✓ Kafka already installed at $KAFKA_DIR${NC}"
    fi
else
    echo -e "${YELLOW}[4/7] Skipping Kafka (--minimal mode)${NC}"
fi

# =============================================================================
# Step 5: Setup Python Virtual Environment
# =============================================================================
echo ""
echo -e "${YELLOW}[5/7] Setting up Python virtual environment...${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}  ✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}  ✓ Virtual environment already exists${NC}"
fi

# Activate and install packages
source venv/bin/activate
pip install --upgrade pip

echo -e "${BLUE}  Installing Python packages...${NC}"
pip install -r requirements.txt

echo -e "${GREEN}  ✓ Python packages installed${NC}"

# =============================================================================
# Step 6: Setup Directories and Files
# =============================================================================
echo ""
echo -e "${YELLOW}[6/7] Setting up directories and configuration...${NC}"

# Create directories
mkdir -p logs logs/reports rules ml_models fl_models

# Set permissions
chmod 755 logs rules ml_models fl_models
chmod +x start.sh stop.sh 2>/dev/null || true
chmod +x start_inference_api.sh 2>/dev/null || true

# Create .env if not exists
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        chmod 600 .env
        echo -e "${GREEN}  ✓ Created .env from template (configure API keys!)${NC}"
    fi
fi

echo -e "${GREEN}  ✓ Directories created${NC}"

# =============================================================================
# Step 7: Verify Installation
# =============================================================================
echo ""
echo -e "${YELLOW}[7/7] Verifying installation...${NC}"

ERRORS=0

# Check Suricata
if command -v suricata &> /dev/null; then
    echo -e "${GREEN}  ✓ Suricata: OK${NC}"
else
    echo -e "${RED}  ✗ Suricata: NOT FOUND${NC}"
    ERRORS=$((ERRORS+1))
fi

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}  ✓ Python: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}  ✗ Python: NOT FOUND${NC}"
    ERRORS=$((ERRORS+1))
fi

# Check key Python packages
source venv/bin/activate

if python3 -c "import numpy" 2>/dev/null; then
    echo -e "${GREEN}  ✓ NumPy: OK${NC}"
else
    echo -e "${RED}  ✗ NumPy: Not installed (REQUIRED for ML)${NC}"
    ERRORS=$((ERRORS+1))
fi

if python3 -c "import scapy" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Scapy: OK${NC}"
else
    echo -e "${YELLOW}  ⚠ Scapy: Not installed (packet inspection disabled)${NC}"
fi

if python3 -c "import sklearn" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Scikit-learn: OK${NC}"
else
    echo -e "${YELLOW}  ⚠ Scikit-learn: Not installed${NC}"
fi

if python3 -c "import uvicorn" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Uvicorn: OK${NC}"
else
    echo -e "${YELLOW}  ⚠ Uvicorn: Not installed (inference API disabled)${NC}"
fi

if python3 -c "import fastapi" 2>/dev/null; then
    echo -e "${GREEN}  ✓ FastAPI: OK${NC}"
else
    echo -e "${YELLOW}  ⚠ FastAPI: Not installed (needed for FL)${NC}"
fi

if python3 -c "import flwr" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Flower (FL): OK${NC}"
else
    echo -e "${YELLOW}  ⚠ Flower: Not installed (needed for FL)${NC}"
fi

# Check iptables
if command -v iptables &> /dev/null; then
    echo -e "${GREEN}  ✓ iptables: OK${NC}"
else
    echo -e "${RED}  ✗ iptables: NOT FOUND${NC}"
    ERRORS=$((ERRORS+1))
fi

# =============================================================================
# Final Summary
# =============================================================================
echo ""
if [ $ERRORS -eq 0 ]; then
    echo -e "${BOLD}${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                    INSTALLATION COMPLETE!                             ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
else
    echo -e "${BOLD}${RED}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║             INSTALLATION COMPLETE WITH $ERRORS ERROR(S)                  ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
fi

echo ""
echo -e "${BOLD}Configuration (Optional):${NC}"
echo -e "  ${YELLOW}Network interface is AUTO-DETECTED! No manual setup needed.${NC}"
echo -e "  1. Configure ${CYAN}.env${NC} with your Google API key (for AI rules)"
echo -e "  2. Add ML models to ${CYAN}ml_models/${NC} directory (optional)"
echo ""

echo -e "${BOLD}Quick Start:${NC}"
echo -e "  ${CYAN}sudo ./start.sh${NC}           # Start everything (auto-detects network)"
echo -e "  ${CYAN}python3 attack_test.py${NC}    # Run attack test (auto-detects target)"
echo -e "  ${CYAN}sudo ./stop.sh${NC}            # Stop everything"
echo ""

echo -e "${BOLD}Federated Learning (Optional):${NC}"
echo -e "  ${CYAN}python3 fl_client_manager.py --all --dry-run${NC}  # Local training test"
echo -e "  ${CYAN}python3 fl_server_manager.py --all${NC}            # Start FL server"
echo ""

echo -e "${BOLD}Documentation:${NC}"
echo -e "  README.md                  - Main documentation"
echo -e "  FL_QUICK_START.md          - Federated Learning guide"
echo -e "  FL_INTEGRATION_GUIDE.md    - Detailed FL integration"
echo ""
