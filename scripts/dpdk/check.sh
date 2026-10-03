#!/bin/bash
# DPDK Pre-flight Check
# Verifies DPDK is ready before running benchmarks

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}     DPDK Environment Check${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

ERRORS=0

# Check 1: Root privileges
echo -n "Checking root privileges... "
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}FAIL${NC}"
    echo "  ⚠️  This script must be run as root: sudo $0"
    exit 1
fi
echo -e "${GREEN}OK${NC}"

# Check 2: DPDK installation
echo -n "Checking DPDK installation... "
if command -v dpdk-devbind.py &> /dev/null || [ -d /opt/dpdk-* ]; then
    echo -e "${GREEN}OK${NC}"
    DPDK_DIR=$(ls -d /opt/dpdk-* 2>/dev/null | head -1)
    if [ -n "$DPDK_DIR" ]; then
        echo "  ℹ️  Found: $DPDK_DIR"
    fi
else
    echo -e "${YELLOW}NOT FOUND${NC}"
    echo "  ⚠️  DPDK not installed. Run: sudo ./scripts/dpdk/setup.sh"
    ERRORS=$((ERRORS + 1))
fi

# Check 3: DPDK packet processor binary
echo -n "Checking dpdk_packet_processor... "
if [ -f /usr/local/bin/dpdk_packet_processor ]; then
    echo -e "${GREEN}OK${NC}"
    echo "  ℹ️  Located at: /usr/local/bin/dpdk_packet_processor"
elif [ -f native/dpdk/build/dpdk_packet_processor ]; then
    echo -e "${YELLOW}BUILT but NOT INSTALLED${NC}"
    echo "  ⚠️  Run: cd native/dpdk/build && sudo ninja install"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${RED}NOT FOUND${NC}"
    echo "  ⚠️  Build the processor:"
    echo "     cd dpdk && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig meson setup build"
    echo "     cd build && ninja && sudo ninja install"
    ERRORS=$((ERRORS + 1))
fi

# Check 4: Hugepages
echo -n "Checking hugepages... "
if [ -f /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages ]; then
    HUGEPAGES=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
    if [ "$HUGEPAGES" -ge 512 ]; then
        echo -e "${GREEN}OK${NC}"
        echo "  ℹ️  Allocated: $HUGEPAGES pages ($(($HUGEPAGES * 2)) MB)"
    else
        echo -e "${YELLOW}INSUFFICIENT${NC}"
        echo "  ⚠️  Only $HUGEPAGES allocated. Allocating 1024..."
        echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
        HUGEPAGES=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
        echo "  ✓  Now: $HUGEPAGES pages"
    fi
else
    echo -e "${RED}NOT AVAILABLE${NC}"
    echo "  ⚠️  Hugepages not supported on this kernel"
    ERRORS=$((ERRORS + 1))
fi

# Check 5: DPDK-compatible drivers
echo -n "Checking DPDK drivers... "
VFIO_LOADED=0
UIO_LOADED=0

if lsmod | grep -q vfio_pci; then
    VFIO_LOADED=1
fi

if lsmod | grep -q igb_uio; then
    UIO_LOADED=1
fi

if [ $VFIO_LOADED -eq 1 ] || [ $UIO_LOADED -eq 1 ]; then
    echo -e "${GREEN}OK${NC}"
    [ $VFIO_LOADED -eq 1 ] && echo "  ℹ️  vfio-pci loaded (recommended)"
    [ $UIO_LOADED -eq 1 ] && echo "  ℹ️  igb_uio loaded"
else
    echo -e "${YELLOW}NOT LOADED${NC}"
    echo "  ⚠️  Loading vfio-pci..."
    modprobe vfio-pci 2>/dev/null || echo "     Could not load vfio-pci (may need kernel support)"
fi

# Check 6: Network interfaces
echo ""
echo "Network Interfaces:"
echo "-------------------"

DPDK_BOUND=0
KERNEL_IFACES=0

# Find dpdk-devbind.py
DEVBIND=""
if command -v dpdk-devbind.py &> /dev/null; then
    DEVBIND="dpdk-devbind.py"
elif [ -n "$DPDK_DIR" ] && [ -f "$DPDK_DIR/usertools/dpdk-devbind.py" ]; then
    DEVBIND="python3 $DPDK_DIR/usertools/dpdk-devbind.py"
fi

if [ -n "$DEVBIND" ]; then
    echo "  DPDK-bound NICs:"
    DPDK_NICS=$($DEVBIND --status 2>/dev/null | grep -A 20 "Network devices using DPDK-compatible driver" | grep -E "^\s*[0-9]" || echo "")
    if [ -n "$DPDK_NICS" ]; then
        echo "$DPDK_NICS" | while read -r line; do
            echo -e "    ${GREEN}✓${NC} $line"
        done
        DPDK_BOUND=1
    else
        echo -e "    ${YELLOW}(none)${NC}"
    fi
    
    echo ""
    echo "  Kernel NICs (available for DPDK binding):"
    KERNEL_NICS=$($DEVBIND --status 2>/dev/null | grep -A 50 "Network devices using kernel driver" | grep -E "^\s*[0-9]" | head -5 || echo "")
    if [ -n "$KERNEL_NICS" ]; then
        echo "$KERNEL_NICS" | while read -r line; do
            PCI=$(echo "$line" | awk '{print $1}')
            echo -e "    ${BLUE}○${NC} $line"
            echo "       To bind: sudo dpdk-devbind.py -b vfio-pci $PCI"
        done
        KERNEL_IFACES=1
    fi
else
    echo -e "  ${YELLOW}dpdk-devbind.py not found - cannot check NIC bindings${NC}"
fi

echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}     Summary${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}❌ $ERRORS critical issue(s) found${NC}"
    echo ""
    echo "Please fix the issues above before running DPDK mode."
    echo ""
    echo "Quick setup:"
    echo "  1. sudo ./scripts/dpdk/setup.sh          # Install DPDK"
    echo "  2. cd dpdk && ./build.sh         # Build packet processor"
    echo "  3. sudo dpdk-devbind.py -b vfio-pci <PCI_ADDR>  # Bind NIC"
    echo ""
    exit 1
fi

if [ $DPDK_BOUND -eq 0 ]; then
    echo -e "${YELLOW}⚠️  DPDK is installed but no NICs are bound${NC}"
    echo ""
    echo "To run DPDK packet capture, bind a network interface:"
    echo ""
    if [ $KERNEL_IFACES -eq 1 ]; then
        echo "Available interfaces listed above. Example:"
        FIRST_NIC=$($DEVBIND --status 2>/dev/null | grep -A 50 "Network devices using kernel driver" | grep -E "^\s*[0-9]" | head -1 | awk '{print $1}')
        if [ -n "$FIRST_NIC" ]; then
            echo "  sudo dpdk-devbind.py -b vfio-pci $FIRST_NIC"
        fi
    else
        echo "  sudo dpdk-devbind.py -b vfio-pci 00:08.0  # Replace with your PCI address"
    fi
    echo ""
    echo "⚠️  WARNING: Binding removes the interface from Linux kernel"
    echo "   Make sure you have another interface for SSH/management!"
    echo ""
    echo "For now, you can run in Scapy mode:"
    echo "  ./run_benchmark.sh normal"
    echo ""
    exit 2
fi

echo -e "${GREEN}✅ DPDK environment is ready!${NC}"
echo ""
echo "You can now run:"
echo "  1. sudo ./scripts/dpdk/start.sh           # Start DPDK packet processor"
echo "  2. ./run_benchmark.sh dpdk        # Run benchmark in DPDK mode"
echo ""
