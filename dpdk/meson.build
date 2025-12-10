# DPDK Packet Processor Build Configuration

project('dpdk-packet-processor', 'C', 'CPP',
    version: '1.0.0',
    default_options: ['warning_level=3', 'c_std=c11', 'cpp_std=c++14']
)

# Find DPDK dependency
dpdk = dependency('libdpdk', required: true)

# Source files
sources = files('dpdk_packet_processor.cpp')

# Executable
executable('dpdk_packet_processor',
    sources,
    dependencies: dpdk,
    install: true,
    install_dir: get_option('bindir')
)
