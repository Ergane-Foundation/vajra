# DPDK Packet Processor Makefile
# Alternative to Meson for simpler builds

# Binary name
APP = dpdk_packet_processor

# Sources
SRCS = dpdk_packet_processor.cpp

# DPDK configuration
ifeq ($(RTE_SDK),)
$(error "RTE_SDK is not set. Please set it to your DPDK installation directory")
endif

ifeq ($(RTE_TARGET),)
RTE_TARGET = x86_64-native-linux-gcc
endif

include $(RTE_SDK)/mk/rte.vars.mk

# Compiler flags
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(SRCDIR)

# C++ support
CXXFLAGS += -std=c++14

# Linker flags
LDLIBS += -lm

# Build using DPDK makefile system
include $(RTE_SDK)/mk/rte.extapp.mk

# Phony targets
.PHONY: clean help

help:
	@echo "DPDK Packet Processor Build"
	@echo ""
	@echo "Usage:"
	@echo "  make                 - Build the application"
	@echo "  make clean           - Clean build artifacts"
	@echo ""
	@echo "Requirements:"
	@echo "  RTE_SDK must be set to DPDK installation directory"
	@echo ""
	@echo "Example:"
	@echo "  export RTE_SDK=/usr/local/share/dpdk"
	@echo "  make"
