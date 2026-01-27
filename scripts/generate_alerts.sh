#!/bin/bash
# Generate High-Volume Traffic for Zeek Detection
# This will create LOTS of alerts for your report

echo "=========================================="
echo "  Zeek Alert Generation Script"
echo "=========================================="
echo ""

TARGET="172.25.0.3"  # target_web container

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}This will generate traffic to trigger Zeek alerts${NC}"
echo "Monitor alerts: tail -f logs/zeek/notice.log"
echo ""
read -p "Press ENTER to start..."

#---------------------------------------------------------
# Test 1: Port Scanning (Triggers Port_Scan_Detected)
#---------------------------------------------------------
echo -e "\n${RED}[1/6] Port Scanning Attack${NC}"
docker exec attacker bash -c "
    apt-get update -qq 2>/dev/null && apt-get install -y -qq nmap 2>/dev/null
    echo 'Scanning ports 1-100...'
    nmap -sS -p 1-100 --max-retries 0 -T5 $TARGET 2>/dev/null
    echo 'Scanning ports 100-200...'
    nmap -sS -p 100-200 --max-retries 0 -T5 $TARGET 2>/dev/null
" 2>/dev/null
echo -e "${GREEN}✓ Port scan completed (should trigger alert)${NC}"
sleep 5

#---------------------------------------------------------
# Test 2: HTTP Flood (Triggers HTTP_Flood_Detected)
#---------------------------------------------------------
echo -e "\n${RED}[2/6] HTTP Flood Attack${NC}"
docker exec attacker bash -c "
    apt-get install -y -qq curl 2>/dev/null
    echo 'Sending 150 rapid HTTP requests...'
    for i in {1..150}; do
        curl -s http://$TARGET/ > /dev/null &
    done
    wait
" 2>/dev/null
echo -e "${GREEN}✓ HTTP flood completed (should trigger alert)${NC}"
sleep 5

#---------------------------------------------------------
# Test 3: SQL Injection (Triggers SQL_Injection_Attempt)
#---------------------------------------------------------
echo -e "\n${RED}[3/6] SQL Injection Attacks${NC}"
docker exec attacker bash -c "
    for i in {1..20}; do
        curl -s 'http://$TARGET/login?user=admin&pass=1%27%20OR%20%271%27=%271' > /dev/null
        curl -s 'http://$TARGET/search?q=1%27%20UNION%20SELECT%20NULL--' > /dev/null
        curl -s 'http://$TARGET/page?id=1%27%20DROP%20TABLE%20users--' > /dev/null
    done
" 2>/dev/null
echo -e "${GREEN}✓ SQL injection attempts completed (should trigger alerts)${NC}"
sleep 5

#---------------------------------------------------------
# Test 4: XSS Attacks (Triggers XSS_Attempt)
#---------------------------------------------------------
echo -e "\n${RED}[4/6] XSS Attacks${NC}"
docker exec attacker bash -c "
    for i in {1..20}; do
        curl -s 'http://$TARGET/search?q=<script>alert(1)</script>' > /dev/null
        curl -s 'http://$TARGET/comment?text=<img%20src=x%20onerror=alert(1)>' > /dev/null
        curl -s 'http://$TARGET/profile?name=<script>document.cookie</script>' > /dev/null
    done
" 2>/dev/null
echo -e "${GREEN}✓ XSS attempts completed (should trigger alerts)${NC}"
sleep 5

#---------------------------------------------------------
# Test 5: Directory Traversal (Triggers Directory_Traversal_Attempt)
#---------------------------------------------------------
echo -e "\n${RED}[5/6] Directory Traversal Attacks${NC}"
docker exec attacker bash -c "
    for i in {1..20}; do
        curl -s 'http://$TARGET/file?path=../../../etc/passwd' > /dev/null
        curl -s 'http://$TARGET/download?file=../../../../etc/shadow' > /dev/null
        curl -s 'http://$TARGET/view?doc=../../.ssh/id_rsa' > /dev/null
    done
" 2>/dev/null
echo -e "${GREEN}✓ Directory traversal attempts completed (should trigger alerts)${NC}"
sleep 5

#---------------------------------------------------------
# Test 6: DNS Queries (Triggers Excessive_DNS_Queries)
#---------------------------------------------------------
echo -e "\n${RED}[6/6] Excessive DNS Queries${NC}"
docker exec attacker bash -c "
    apt-get install -y -qq dnsutils 2>/dev/null
    echo 'Sending 150 DNS queries...'
    for i in {1..150}; do
        nslookup google.com 8.8.8.8 > /dev/null 2>&1 &
    done
    wait
" 2>/dev/null
echo -e "${GREEN}✓ DNS queries completed (should trigger alert)${NC}"

echo ""
echo "=========================================="
echo -e "${GREEN}✓ All attack scenarios completed!${NC}"
echo "=========================================="
echo ""
echo "Check results:"
echo "  1. Zeek alerts: cat logs/zeek/notice.log | wc -l"
echo "  2. View alerts: tail -20 logs/zeek/notice.log"
echo "  3. Check Elasticsearch: curl http://localhost:9200/zeek-notice-*/_count"
echo ""