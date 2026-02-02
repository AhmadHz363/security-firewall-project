#!/bin/bash
################################################################################
# Quick System Status Check
# Verifies all components are working correctly
################################################################################

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "  System Status Check"
echo "=========================================="
echo ""

# Check if containers are running
echo -e "${BLUE}[1] Container Status:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "NAME|elasticsearch|kibana|target_web|attacker|zeek|filebeat"
echo ""

# Check ulogd2
echo -e "${BLUE}[2] ulogd2 Process:${NC}"
if docker exec target_web ps aux | grep -v grep | grep ulogd > /dev/null; then
    echo -e "${GREEN}✓${NC} ulogd2 is running"
    docker exec target_web ps aux | grep -v grep | grep ulogd
else
    echo -e "${RED}✗${NC} ulogd2 is NOT running"
fi
echo ""

# Check firewall rules
echo -e "${BLUE}[3] Firewall Rules:${NC}"
RULE_COUNT=$(docker exec target_web iptables -L INPUT -n | wc -l)
if [ "$RULE_COUNT" -gt 10 ]; then
    echo -e "${GREEN}✓${NC} Firewall rules loaded ($RULE_COUNT lines)"
else
    echo -e "${RED}✗${NC} Firewall rules may not be loaded"
fi
echo ""

# Check firewall log
echo -e "${BLUE}[4] Firewall Log:${NC}"
if [ -f "logs/firewall.log" ]; then
    LOG_LINES=$(wc -l < logs/firewall.log)
    echo -e "${GREEN}✓${NC} logs/firewall.log exists ($LOG_LINES lines)"
    
    # Check if logs have proper JSON structure
    if grep -q '"action"' logs/firewall.log 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Logs contain proper JSON with 'action' field"
    else
        echo -e "${YELLOW}⚠${NC} Logs may not have proper JSON structure"
    fi
    
    # Show sample
    echo ""
    echo "Last log entry:"
    tail -1 logs/firewall.log | jq . 2>/dev/null || tail -1 logs/firewall.log
else
    echo -e "${RED}✗${NC} logs/firewall.log does not exist"
fi
echo ""

# Check ulogd JSON
echo -e "${BLUE}[5] ulogd2 JSON Output:${NC}"
if docker exec target_web test -f /var/log/ulogd/ulogd.json 2>/dev/null; then
    JSON_LINES=$(docker exec target_web wc -l < /var/log/ulogd/ulogd.json 2>/dev/null)
    echo -e "${GREEN}✓${NC} /var/log/ulogd/ulogd.json exists ($JSON_LINES lines)"
else
    echo -e "${RED}✗${NC} /var/log/ulogd/ulogd.json does not exist"
fi
echo ""

# Check packet counters
echo -e "${BLUE}[6] Packet Counters:${NC}"
HTTP_PKTS=$(docker exec target_web iptables -L INPUT -n -v | grep "HTTP_ALLOW" | awk '{print $1}')
SSH_PKTS=$(docker exec target_web iptables -L INPUT -n -v | grep "SSH_BLOCK" | awk '{print $1}')
echo "HTTP packets processed: $HTTP_PKTS"
echo "SSH packets blocked: $SSH_PKTS"
echo ""

# Check Elasticsearch
echo -e "${BLUE}[7] Elasticsearch:${NC}"
if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q "yellow\|green"; then
    echo -e "${GREEN}✓${NC} Elasticsearch is healthy"
else
    echo -e "${RED}✗${NC} Elasticsearch is not responding"
fi
echo ""

# Check Kibana
echo -e "${BLUE}[8] Kibana:${NC}"
if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q "available"; then
    echo -e "${GREEN}✓${NC} Kibana is available"
else
    echo -e "${YELLOW}⚠${NC} Kibana is not fully ready yet"
fi
echo ""

# Check Zeek
echo -e "${BLUE}[9] Zeek Logs:${NC}"
if [ -d "logs/zeek" ] && [ "$(ls -A logs/zeek)" ]; then
    echo -e "${GREEN}✓${NC} Zeek logs directory contains files:"
    ls -lh logs/zeek/ | tail -10
    echo ""
    
    # Check conn.log
    if [ -f "logs/zeek/conn.log" ]; then
        CONN_COUNT=$(wc -l < logs/zeek/conn.log)
        echo -e "${GREEN}✓${NC} Zeek conn.log exists ($CONN_COUNT connections)"
    fi
    
    # Check notice.log for alerts
    if [ -f "logs/zeek/notice.log" ]; then
        ALERT_COUNT=$(grep -v 'Zeek_Started' logs/zeek/notice.log | wc -l)
        echo -e "${GREEN}✓${NC} Zeek notice.log exists ($ALERT_COUNT alerts)"
        
        if [ "$ALERT_COUNT" -gt 0 ]; then
            echo ""
            echo "Recent Zeek alerts:"
            grep -v 'Zeek_Started' logs/zeek/notice.log | tail -3
        fi
    fi
else
    echo -e "${YELLOW}⚠${NC} Zeek logs directory is empty"
fi
echo ""

echo "=========================================="
echo "  Status Check Complete"
echo "=========================================="