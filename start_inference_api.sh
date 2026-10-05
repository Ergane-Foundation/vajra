#!/bin/bash
# Start FL Inference API
# This server provides ML predictions via REST API

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
export PYTHONPATH="$SCRIPT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo -e "${GREEN}Starting FL Inference API${NC}"
echo "=========================================="

# Create directories
mkdir -p logs
mkdir -p fl_models

# Check if uvicorn is installed
if ! command -v uvicorn &> /dev/null; then
    echo -e "${YELLOW}uvicorn not found, installing...${NC}"
    pip install uvicorn fastapi pydantic
fi

# Kill existing API server
pkill -f "uvicorn vajra.api.inference:app" 2>/dev/null || true
sleep 1

# Start API server
echo -e "${YELLOW}Starting Inference API on port 8001...${NC}"

nohup uvicorn vajra.api.inference:app \
    --host 0.0.0.0 \
    --port 8001 \
    --log-level info \
    > logs/inference_api.out 2>&1 &

API_PID=$!
echo $API_PID > logs/inference_api.pid

sleep 2

# Check if running
if ps -p $API_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Inference API started (PID: $API_PID)${NC}"
    echo -e "${GREEN}✓ API available at: http://localhost:8001${NC}"
    echo ""
    echo "Test endpoints:"
    echo "  curl http://localhost:8001/health"
    echo "  curl http://localhost:8001/models"
    echo ""
else
    echo -e "\033[0;31m✗ Failed to start Inference API${NC}"
    echo "Check logs/inference_api.out for errors"
    exit 1
fi

echo "=========================================="
echo -e "${GREEN}Inference API Running${NC}"
echo "=========================================="
