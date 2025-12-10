#!/bin/bash
# Quick start script for Advanced Threat Detection System

echo "=================================="
echo "Advanced Threat Detection System"
echo "=================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "threat_orchestrator.py" ]; then
    echo -e "${RED}Error: Please run this script from the linux/ directory${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Installing Python dependencies...${NC}"
pip install -r requirements.txt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Dependencies installed${NC}"
else
    echo -e "${RED}✗ Failed to install dependencies${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Step 2: Creating logs directory...${NC}"
mkdir -p logs
echo -e "${GREEN}✓ Logs directory created${NC}"

echo ""
echo -e "${YELLOW}Step 3: Testing individual engines...${NC}"
echo ""

# Test FlowPrint
echo -e "${YELLOW}Testing FlowPrint Engine...${NC}"
python3 -c "from flowprint_engine import get_flowprint_engine; engine = get_flowprint_engine(); print('FlowPrint: OK')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ FlowPrint Engine: OK${NC}"
else
    echo -e "${RED}✗ FlowPrint Engine: FAILED${NC}"
fi

# Test Kitsune
echo -e "${YELLOW}Testing Kitsune Engine...${NC}"
python3 -c "from kitsune_engine import get_kitsune_engine; engine = get_kitsune_engine(); print('Kitsune: OK')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Kitsune Engine: OK${NC}"
else
    echo -e "${RED}✗ Kitsune Engine: FAILED (NumPy may be required)${NC}"
fi

# Test ET-BERT
echo -e "${YELLOW}Testing ET-BERT Engine...${NC}"
python3 -c "from etbert_engine import get_etbert_engine; engine = get_etbert_engine(); print('ET-BERT: OK')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ ET-BERT Engine: OK${NC}"
else
    echo -e "${RED}✗ ET-BERT Engine: FAILED${NC}"
fi

# Test Stratosphere
echo -e "${YELLOW}Testing Stratosphere Engine...${NC}"
python3 -c "from stratosphere_engine import get_stratosphere_engine; engine = get_stratosphere_engine(); print('Stratosphere: OK')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Stratosphere Engine: OK${NC}"
else
    echo -e "${RED}✗ Stratosphere Engine: FAILED${NC}"
fi

# Test Exploit Detection
echo -e "${YELLOW}Testing Exploit Detection Engine...${NC}"
python3 -c "from exploit_detection import get_exploit_detector; engine = get_exploit_detector(); print('Exploit Detection: OK')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Exploit Detection Engine: OK${NC}"
else
    echo -e "${RED}✗ Exploit Detection Engine: FAILED${NC}"
fi

# Test Orchestrator
echo ""
echo -e "${YELLOW}Testing Threat Orchestrator...${NC}"
python3 -c "from threat_orchestrator import get_threat_orchestrator; orch = get_threat_orchestrator(); print('Orchestrator: OK with', len(orch.get_enabled_engines()), 'engines')" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Threat Orchestrator: OK${NC}"
else
    echo -e "${RED}✗ Threat Orchestrator: FAILED${NC}"
fi

echo ""
echo "=================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "=================================="
echo ""
echo "Available engines:"
echo "  1. FlowPrint - Device/App fingerprinting"
echo "  2. Kitsune - Online anomaly detection"
echo "  3. ET-BERT - Encrypted traffic classification"
echo "  4. Stratosphere - Behavioral IPS"
echo "  5. Exploit Detection - Vulnerability detection"
echo ""
echo "To run tests:"
echo "  python3 flowprint_engine.py"
echo "  python3 kitsune_engine.py"
echo "  python3 etbert_engine.py"
echo "  python3 stratosphere_engine.py"
echo "  python3 exploit_detection.py"
echo "  python3 threat_orchestrator.py"
echo ""
echo "To integrate with existing pipeline:"
echo "  1. Edit packet_inspector.py"
echo "  2. Import: from threat_orchestrator import get_threat_orchestrator"
echo "  3. Use orchestrator.analyze_packet() in your packet processing"
echo ""
echo "Configuration:"
echo "  Edit advanced_detection.config to customize settings"
echo ""
echo "Logs location:"
echo "  logs/threat_assessments.json - All threat detections"
echo "  logs/*_engine.log - Individual engine logs"
echo ""
echo "For more information, see ADVANCED_DETECTION_GUIDE.md"
echo ""
