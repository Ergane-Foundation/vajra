#!/bin/bash
# Build Suricata with DPDK Support

set -e

echo "====================================="
echo "Building Suricata with DPDK Support"
echo "====================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[WARN]  This script requires root privileges"
    echo "Please run with: sudo $0"
    exit 1
fi

SURICATA_VERSION="7.0.2"
DPDK_DIR="/opt/dpdk-23.11"

echo ""
echo "Step 1: Installing Suricata build dependencies..."
apt-get update
apt-get install -y \
    libpcre2-dev \
    libyaml-dev \
    libjansson-dev \
    libcap-ng-dev \
    libmagic-dev \
    libnet1-dev \
    libnetfilter-queue-dev \
    zlib1g-dev \
    libhtp-dev \
    libpcap-dev \
    rustc \
    cargo \
    autoconf \
    automake \
    libtool \
    make \
    pkg-config

echo ""
echo "Step 2: Downloading Suricata ${SURICATA_VERSION}..."
cd /tmp
if [ ! -d "suricata-${SURICATA_VERSION}" ]; then
    wget https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz
    tar xzf suricata-${SURICATA_VERSION}.tar.gz
    rm suricata-${SURICATA_VERSION}.tar.gz
fi

cd suricata-${SURICATA_VERSION}

echo ""
echo "Step 3: Configuring Suricata with DPDK..."

# Export DPDK paths
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export RTE_SDK=$DPDK_DIR

./configure \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    --enable-dpdk \
    --with-libdpdk-includes=/usr/local/include \
    --with-libdpdk-libraries=/usr/local/lib \
    --enable-nfqueue \
    --enable-rust

echo ""
echo "Step 4: Building Suricata..."
make -j$(nproc)

echo ""
echo "Step 5: Installing Suricata..."
make install
ldconfig

echo ""
echo "Step 6: Setting up Suricata directories..."
mkdir -p /etc/suricata/rules
mkdir -p /var/log/suricata
mkdir -p /var/run/suricata

# Copy default rules if they don't exist
if [ -d "rules" ]; then
    cp rules/*.rules /etc/suricata/rules/ || true
fi

echo ""
echo "========================================="
echo "[OK] Suricata with DPDK built successfully!"
echo "========================================="
echo ""
echo "Verify DPDK support:"
echo "  suricata --build-info | grep DPDK"
echo ""
echo "Configure DPDK in suricata.yaml:"
echo "  dpdk:"
echo "    eal-params:"
echo "      proc-type: primary"
echo "      pci-whitelist:"
echo "        - 0000:00:08.0"
echo "    ports:"
echo "      - port: 0"
echo ""
