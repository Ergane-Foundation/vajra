#!/bin/bash
# DPDK Setup Script for NGFW Linux Pipeline
# Installs DPDK, configures hugepages, and builds packet processor

set -e

echo "====================================="
echo "DPDK Setup for NGFW"
echo "====================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[WARN]  This script requires root privileges"
    echo "Please run with: sudo $0"
    exit 1
fi

# Configuration
DPDK_VERSION="23.11"
DPDK_DIR="/opt/dpdk-${DPDK_VERSION}"
HUGEPAGE_SIZE="2048"  # MB per hugepage
NUM_HUGEPAGES="1024"  # Number of hugepages (2GB total)

echo ""
echo "Step 1: Installing build dependencies..."
apt-get update
apt-get install -y \
    build-essential \
    meson \
    ninja-build \
    pkg-config \
    python3-pyelftools \
    libnuma-dev \
    libpcap-dev \
    linux-headers-$(uname -r) \
    git \
    wget

echo ""
echo "Step 2: Downloading DPDK ${DPDK_VERSION}..."
if [ ! -d "$DPDK_DIR" ]; then
    cd /opt
    wget https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz
    tar xf dpdk-${DPDK_VERSION}.tar.xz
    rm dpdk-${DPDK_VERSION}.tar.xz
    echo "[OK] DPDK downloaded"
else
    echo "[OK] DPDK already exists at $DPDK_DIR"
fi

echo ""
echo "Step 3: Building DPDK..."
cd $DPDK_DIR

if [ ! -d "build" ]; then
    meson setup build
    cd build
    ninja
    ninja install
    ldconfig
    echo "[OK] DPDK built and installed"
else
    echo "[OK] DPDK already built"
fi

echo ""
echo "Step 4: Configuring hugepages..."

# Setup hugepages directory
mkdir -p /mnt/huge
if ! grep -q "hugetlbfs" /etc/fstab; then
    echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
fi

# Mount hugepages
if ! mount | grep -q "/mnt/huge"; then
    mount -t hugetlbfs nodev /mnt/huge
    echo "[OK] Hugepages mounted"
else
    echo "[OK] Hugepages already mounted"
fi

# Allocate hugepages
echo $NUM_HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Verify
ALLOCATED=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
echo "[OK] Allocated $ALLOCATED hugepages (${ALLOCATED}x2MB = $((ALLOCATED*2))MB)"

# Make hugepages persistent
if ! grep -q "vm.nr_hugepages" /etc/sysctl.conf; then
    echo "vm.nr_hugepages=$NUM_HUGEPAGES" >> /etc/sysctl.conf
    sysctl -p
fi

echo ""
echo "Step 5: Loading kernel modules..."

# Load VFIO module (preferred)
modprobe vfio-pci || true

# Alternative: Load UIO module
if ! lsmod | grep -q "uio"; then
    modprobe uio
    echo "[OK] UIO module loaded"
fi

# Install igb_uio if needed (alternative to vfio-pci)
if [ ! -f "/lib/modules/$(uname -r)/extra/dpdk/igb_uio.ko" ]; then
    echo "Building igb_uio module..."
    cd $DPDK_DIR/kernel/linux/igb_uio
    make
    insmod igb_uio.ko || true
    echo "[OK] igb_uio module built"
fi

echo ""
echo "Step 6: Building DPDK packet processor..."
cd "$(dirname "$0")/../../native/dpdk"

# Use meson if available, otherwise fall back to make
if [ -f "meson.build" ]; then
    echo "Using meson build system..."
    if [ ! -d "build" ]; then
        PKG_CONFIG_PATH=/usr/local/lib/pkgconfig meson setup build
    fi
    cd build
    ninja
    ninja install || cp dpdk_packet_processor /usr/local/bin/
    echo "[OK] DPDK packet processor built (meson)"
else
    echo "Using Makefile..."
    export RTE_SDK=$DPDK_DIR
    export RTE_TARGET=x86_64-native-linux-gcc
    make clean || true
    make
    cp build/dpdk_packet_processor /usr/local/bin/ || true
    echo "[OK] DPDK packet processor built (make)"
fi

echo ""
echo "Step 7: Creating helper scripts..."

# Create NIC binding helper
cat > /usr/local/bin/dpdk-bind-nic << 'EOF'
#!/bin/bash
# Bind/unbind NICs to DPDK drivers

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Use dpdk-devbind.py from DPDK installation
DEVBIND="/opt/dpdk-*/usertools/dpdk-devbind.py"

case "$1" in
    bind)
        if [ -z "$2" ]; then
            echo "Usage: dpdk-bind-nic bind <PCI_ADDRESS>"
            echo "Example: dpdk-bind-nic bind 0000:00:08.0"
            exit 1
        fi
        python3 $DEVBIND --bind=vfio-pci $2
        echo "[OK] NIC $2 bound to DPDK (vfio-pci)"
        ;;
    unbind)
        if [ -z "$2" ]; then
            echo "Usage: dpdk-bind-nic unbind <PCI_ADDRESS>"
            exit 1
        fi
        python3 $DEVBIND --bind=ixgbe $2  # Or appropriate kernel driver
        echo "[OK] NIC $2 unbound from DPDK"
        ;;
    status)
        python3 $DEVBIND --status
        ;;
    *)
        echo "Usage: dpdk-bind-nic {bind|unbind|status} [PCI_ADDRESS]"
        echo ""
        echo "Commands:"
        echo "  status              - Show NIC binding status"
        echo "  bind <PCI_ADDR>     - Bind NIC to DPDK"
        echo "  unbind <PCI_ADDR>   - Unbind NIC from DPDK"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/dpdk-bind-nic

echo "[OK] Created dpdk-bind-nic helper"

echo ""
echo "========================================="
echo "[OK] DPDK Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Check available NICs:"
echo "   sudo dpdk-bind-nic status"
echo ""
echo "2. Bind a NIC to DPDK (example):"
echo "   sudo dpdk-bind-nic bind 0000:00:08.0"
echo ""
echo "3. Build Suricata with DPDK support (see scripts/dpdk/build_suricata.sh)"
echo ""
echo "4. Start the DPDK pipeline:"
echo "   sudo ./scripts/dpdk/start.sh"
echo ""
echo "To unbind NIC later:"
echo "   sudo dpdk-bind-nic unbind 0000:00:08.0"
echo ""
