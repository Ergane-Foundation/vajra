#!/bin/bash
# Vajra Resource Consumption (RC) Testing Script
# 
# This script automates the entire RC testing process:
# 1. Starts the Vajra pipeline (eve_watcher + start_macos.sh)
# 2. Monitors resource consumption
# 3. Generates reports and visualizations
#
# Usage:
#   sudo ./run_rc_tests.sh
#
# Output:
#   - tests/perf/resource/output/rc_report_TIMESTAMP.json
#   - tests/perf/resource/output/rc_dashboard_TIMESTAMP.png
#   - tests/perf/resource/output/resource_snapshots.json
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

# Functions

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
echo "║              VAJRA Resource Consumption (RC) Testing                 ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Prerequisites

log INFO "Checking prerequisites..."

# Check for root
if [ "$EUID" -ne 0 ]; then
    log ERROR "This script must be run as root (for Suricata)"
    log ERROR "Please run: sudo ./run_rc_tests.sh"
    exit 1
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    log ERROR "python3 not found"
    exit 1
fi

# Check for required Python packages
PYTHON_CMD="python3"
if [ -f "$ROOT_DIR/venv/bin/python3" ]; then
    PYTHON_CMD="$ROOT_DIR/venv/bin/python3"
    log INFO "Using venv: $ROOT_DIR/venv"
elif [ -f "$ROOT_DIR/venv_test/bin/python3" ]; then
    PYTHON_CMD="$ROOT_DIR/venv_test/bin/python3"
    log INFO "Using venv_test: $ROOT_DIR/venv_test"
fi

# Check psutil
if ! $PYTHON_CMD -c "import psutil" 2>/dev/null; then
    log ERROR "psutil not installed"
    log INFO "Install with: pip install psutil"
    exit 1
fi

log SUCCESS "Prerequisites OK"

# Create directories
mkdir -p "$OUTPUT_DIR" "$LOGS_DIR"
log INFO "Output directory: $OUTPUT_DIR"

# Run RC Test

log HEADER ""
log HEADER "Starting RC Test..."
log HEADER ""

cd "$SCRIPT_DIR"

# Run the Python RC test runner
log INFO "Executing rc_test_runner.py..."
$PYTHON_CMD rc_test_runner.py

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    log SUCCESS ""
    log SUCCESS "RC Testing completed successfully!"
    log SUCCESS ""
    log SUCCESS "Results:"
    log SUCCESS "  - JSON Report:     $OUTPUT_DIR/rc_report_*.json"
    log SUCCESS "  - Dashboard PNG:   $OUTPUT_DIR/rc_dashboard_*.png"
    log SUCCESS "  - Snapshots:       $OUTPUT_DIR/resource_snapshots.json"
    log SUCCESS ""
else
    log ERROR ""
    log ERROR "RC Testing failed with exit code: $EXIT_CODE"
    log ERROR "Check logs in: $LOGS_DIR"
    log ERROR ""
fi

# Summary

log HEADER "═══════════════════════════════════════════════════════════════════════"
log HEADER "Test ID: $(ls -t $OUTPUT_DIR/rc_report_*.json 2>/dev/null | head -1 | xargs basename | sed 's/rc_report_//' | sed 's/.json//')"
log HEADER "═══════════════════════════════════════════════════════════════════════"

exit $EXIT_CODE
