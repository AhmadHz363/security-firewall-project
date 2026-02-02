#!/bin/bash
################################################################################
# Zeek Diagnostic and Fix Script
# Diagnoses why Zeek isn't capturing traffic and fixes it
################################################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "  Zeek Diagnostics"
echo "=========================================="
echo ""

# 1. Check if Zeek container is running
echo -e "${BLUE}[1] Checking Zeek container status...${NC}"
if docker ps | grep -q zeek; then
    echo -e "${GREEN}✓${NC} Zeek container is running"
else
    echo -e "${RED}✗${NC} Zeek container is NOT running"
    exit 1
fi
echo ""

# 2. Check Zeek process
echo -e "${BLUE}[2] Checking Zeek process...${NC}"
docker exec zeek ps aux | grep zeek
echo ""

# 3. Check Zeek logs
echo -e "${BLUE}[3] Checking Zeek console log...${NC}"
echo "--- Zeek Console Output ---"
cat logs/zeek/zeek-console.log
echo "----------------------------"
echo ""

# 4. Check network interfaces in Zeek container
echo -e "${BLUE}[4] Network interfaces in Zeek container...${NC}"
docker exec zeek ip addr show
echo ""

# 5. Check if interface is in promiscuous mode
echo -e "${BLUE}[5] Checking promiscuous mode...${NC}"
docker exec zeek ip link show eth0 | grep PROMISC
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} eth0 is in promiscuous mode"
else
    echo -e "${RED}✗${NC} eth0 is NOT in promiscuous mode"
fi
echo ""

# 6. Check if Zeek is actually monitoring
echo -e "${BLUE}[6] Checking if Zeek is capturing packets...${NC}"
docker exec zeek zeekctl status 2>/dev/null || echo "zeekctl not available (using standalone mode)"
echo ""

# 7. Check current connections
echo -e "${BLUE}[7] Checking Zeek conn.log...${NC}"
if [ -f "logs/zeek/conn.log" ]; then
    CONN_LINES=$(wc -l < logs/zeek/conn.log)
    echo "conn.log has $CONN_LINES lines"
    
    if [ "$CONN_LINES" -gt 10 ]; then
        echo -e "${GREEN}✓${NC} Zeek is capturing connections"
        echo ""
        echo "Last 3 connections:"
        tail -3 logs/zeek/conn.log
    else
        echo -e "${YELLOW}⚠${NC} Very few connections captured"
    fi
else
    echo -e "${RED}✗${NC} conn.log does not exist"
fi
echo ""

# 8. Generate test traffic and check
echo -e "${BLUE}[8] Generating test traffic...${NC}"
echo "Sending HTTP request..."
docker exec attacker curl -s http://172.25.0.3/ > /dev/null 2>&1

echo "Waiting 5 seconds for Zeek to process..."
sleep 5

# Check if new entries appeared
if [ -f "logs/zeek/conn.log" ]; then
    NEW_LINES=$(wc -l < logs/zeek/conn.log)
    echo "conn.log now has $NEW_LINES lines"
    echo ""
    echo "Latest connection:"
    tail -1 logs/zeek/conn.log
else
    echo -e "${RED}✗${NC} Still no conn.log"
fi
echo ""

# 9. Check notice.log for alerts
echo -e "${BLUE}[9] Checking notice.log for alerts...${NC}"
if [ -f "logs/zeek/notice.log" ]; then
    NOTICE_LINES=$(wc -l < logs/zeek/notice.log)
    echo "notice.log has $NOTICE_LINES lines"
    
    if [ "$NOTICE_LINES" -gt 5 ]; then
        echo ""
        echo "Recent notices:"
        tail -5 logs/zeek/notice.log
    fi
else
    echo -e "${YELLOW}⚠${NC} notice.log does not exist or is empty"
fi
echo ""

echo "=========================================="
echo "  Diagnosis Complete"
echo "=========================================="
echo ""

# Summary
echo -e "${BLUE}Summary:${NC}"
if [ -f "logs/zeek/conn.log" ]; then
    CONN_COUNT=$(wc -l < logs/zeek/conn.log)
    if [ "$CONN_COUNT" -gt 20 ]; then
        echo -e "${GREEN}✓ Zeek appears to be working${NC} ($CONN_COUNT connections logged)"
    else
        echo -e "${YELLOW}⚠ Zeek is running but capturing very little traffic${NC}"
        echo ""
        echo "Possible issues:"
        echo "  1. Interface not in promiscuous mode"
        echo "  2. Zeek not monitoring the right interface"
        echo "  3. Network traffic not reaching Zeek container"
    fi
else
    echo -e "${RED}✗ Zeek is NOT capturing traffic${NC}"
    echo ""
    echo "Recommended actions:"
    echo "  1. Restart Zeek container: docker compose restart zeek"
    echo "  2. Check Zeek logs: docker logs zeek"
    echo "  3. Verify network configuration"
fi