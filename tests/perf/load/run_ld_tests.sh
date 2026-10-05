#!/bin/bash
# Vajra Load Testing (LD) Script
#
# Performs comprehensive load testing to identify bottlenecks:
# - Baseline, Normal, Peak, Stress scenarios
# - HTTP, TCP, UDP, Mixed traffic
# - Throughput, latency, success rate analysis
# - Bottleneck identification
#
# Usage:
#   sudo ./run_ld_tests.sh
#
# Output:
#   - tests/perf/load/output/ld_report_TIMESTAMP.json
#   - tests/perf/load/output/ld_dashboard_TIMESTAMP.png
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
LOGS_DIR="$SCRIPT_DIR/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log() {
    local level=$1
    shift
    local msg="$@"
    local timestamp=$(date +"%H:%M:%S")
    
    case $level in
        INFO)    color=$BLUE ;;
        SUCCESS) color=$GREEN ;;
        WARNING) color=$YELLOW ;;
        ERROR)   color=$RED ;;
        HEADER)  color=$CYAN ;;
        *)       color=$NC ;;
    esac
    
    echo -e "${BOLD}[$timestamp]${NC} ${color}[$level]${NC} $msg"
}

# Banner

clear
echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║                 Vajra Load Testing (LD) Suite                         ║"
echo "║                                                                       ║"
echo "║          Bottleneck Detection & Performance Analysis                 ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Prerequisites

log INFO "Checking prerequisites..."

# Check for root
if [ "$EUID" -ne 0 ]; then
    log ERROR "This script must be run as root"
    log ERROR "Run with: sudo ./run_ld_tests.sh"
    exit 1
fi

# Check Python
PYTHON_CMD="python3"
if [ -f "$ROOT_DIR/venv/bin/python3" ]; then
    PYTHON_CMD="$ROOT_DIR/venv/bin/python3"
elif [ -f "$ROOT_DIR/venv_test/bin/python3" ]; then
    PYTHON_CMD="$ROOT_DIR/venv_test/bin/python3"
fi

if ! command -v python3 &> /dev/null; then
    log ERROR "python3 not found"
    exit 1
fi

log SUCCESS "Prerequisites OK"

# Create directories
mkdir -p "$OUTPUT_DIR" "$LOGS_DIR"

# Run Load Tests

log HEADER ""
log HEADER "Starting Load Testing..."
log HEADER ""

cd "$SCRIPT_DIR"

# Run the load test suite
$PYTHON_CMD ld_test_runner.py

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    log SUCCESS ""
    log SUCCESS "Load Testing completed successfully!"
    log SUCCESS ""
    log SUCCESS "Results:"
    log SUCCESS "  - JSON Report:     $OUTPUT_DIR/ld_report_*.json"
    log SUCCESS "  - Dashboard PNG:   $OUTPUT_DIR/ld_dashboard_*.png"
    log SUCCESS ""
else
    log ERROR ""
    log ERROR "Load Testing failed with exit code: $EXIT_CODE"
    log ERROR ""
fi

log HEADER "═══════════════════════════════════════════════════════════════════════"

exit $EXIT_CODE
