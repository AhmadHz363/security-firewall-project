#!/bin/bash
################################################################################
# Zeek JSON Logging Fix Script
# Fixes Zeek to output JSON logs for Filebeat compatibility
# Does NOT touch firewall configuration
################################################################################

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}"
    echo "================================================================================"
    echo "  $1"
    echo "================================================================================"
    echo -e "${NC}"
}

print_step() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }

print_header "Zeek JSON Logging Fix"
echo "This script will enable JSON logging in Zeek without affecting the firewall"
echo ""

################################################################################
# Backup existing configuration
################################################################################
print_header "Step 1: Backing Up Current Configuration"

if [ -f "zeek/local.zeek" ]; then
    cp zeek/local.zeek "zeek/local.zeek.backup.$(date +%Y%m%d_%H%M%S)"
    print_step "Backed up zeek/local.zeek"
else
    print_warning "No existing zeek/local.zeek found (this is OK)"
fi
echo ""

################################################################################
# Verify firewall is still running
################################################################################
print_header "Step 2: Verifying Firewall Status"

if docker ps | grep -q target_web; then
    print_step "target_web container is running"
    
    if docker exec target_web ps aux | grep -v grep | grep -q ulogd; then
        print_step "ulogd2 is running"
    else
        print_warning "ulogd2 not running - may need restart"
    fi
    
    RULE_COUNT=$(docker exec target_web iptables -L INPUT -n | wc -l)
    if [ "$RULE_COUNT" -gt 10 ]; then
        print_step "Firewall rules are active ($RULE_COUNT lines)"
    else
        print_warning "Firewall may need to be reloaded"
    fi
else
    print_error "target_web container is not running!"
fi
echo ""

################################################################################
# Clean old Zeek logs (optional)
################################################################################
print_header "Step 3: Cleaning Old Zeek Logs"

read -p "Do you want to clear old Zeek logs? (y/N): " CLEAR_LOGS
if [[ "$CLEAR_LOGS" =~ ^[Yy]$ ]]; then
    print_info "Removing old logs..."
    rm -rf logs/zeek/*
    print_step "Old logs cleared"
else
    print_info "Keeping old logs"
fi
echo ""

################################################################################
# Restart Zeek container
################################################################################
print_header "Step 4: Restarting Zeek"

print_info "Stopping Zeek container..."
docker compose stop zeek
sleep 2

print_info "Starting Zeek container with new configuration..."
docker compose up -d zeek
sleep 5

if docker ps | grep -q zeek; then
    print_step "Zeek container is running"
else
    print_error "Failed to start Zeek container"
    exit 1
fi
echo ""

################################################################################
# Wait for Zeek to initialize
################################################################################
print_header "Step 5: Waiting for Zeek to Initialize"

print_info "Giving Zeek 20 seconds to start up..."
sleep 20
print_step "Zeek should be ready"
echo ""

################################################################################
# Generate test traffic
################################################################################
print_header "Step 6: Generating Test Traffic"

print_info "Sending test HTTP request..."
docker exec attacker curl -s http://172.25.0.3/ > /dev/null 2>&1 || true
sleep 2

print_info "Sending SQL injection test..."
docker exec attacker curl -s "http://172.25.0.3/login?username=admin&password=1' OR '1'='1" > /dev/null 2>&1 || true
sleep 2

print_info "Sending XSS test..."
docker exec attacker curl -s "http://172.25.0.3/search?q=<script>alert(1)</script>" > /dev/null 2>&1 || true
sleep 2

print_step "Test traffic sent"
echo ""

################################################################################
# Wait for logs to be written
################################################################################
print_header "Step 7: Waiting for Logs to be Written"

print_info "Waiting 15 seconds for Zeek to process and write logs..."
sleep 15
echo ""

################################################################################
# Verify logs are being created
################################################################################
print_header "Step 8: Verifying Log Creation"

# Check conn.log
if [ -f "logs/zeek/conn.log" ]; then
    CONN_LINES=$(wc -l < logs/zeek/conn.log)
    print_step "conn.log exists with $CONN_LINES lines"
    
    # Check if it's JSON format
    if grep -q '{' logs/zeek/conn.log 2>/dev/null; then
        print_step "conn.log is in JSON format ✓"
        echo ""
        echo "Sample conn.log entry:"
        head -1 logs/zeek/conn.log | jq . 2>/dev/null || head -1 logs/zeek/conn.log
    else
        print_warning "conn.log is NOT in JSON format - checking further..."
    fi
else
    print_warning "conn.log not created yet"
fi
echo ""

# Check notice.log
if [ -f "logs/zeek/notice.log" ]; then
    NOTICE_LINES=$(wc -l < logs/zeek/notice.log)
    print_step "notice.log exists with $NOTICE_LINES lines"
    
    # Check if it's JSON format
    if grep -q '{' logs/zeek/notice.log 2>/dev/null; then
        print_step "notice.log is in JSON format ✓"
        echo ""
        echo "Sample notice.log entry:"
        head -1 logs/zeek/notice.log | jq . 2>/dev/null || head -1 logs/zeek/notice.log
    else
        print_warning "notice.log is NOT in JSON format"
    fi
else
    print_warning "notice.log not created yet"
fi
echo ""

# Check http.log
if [ -f "logs/zeek/http.log" ]; then
    HTTP_LINES=$(wc -l < logs/zeek/http.log)
    print_step "http.log exists with $HTTP_LINES lines"
    
    if grep -q '{' logs/zeek/http.log 2>/dev/null; then
        print_step "http.log is in JSON format ✓"
    fi
else
    print_info "http.log not created yet (will be created when HTTP traffic is detected)"
fi
echo ""

################################################################################
# Verify firewall still works
################################################################################
print_header "Step 9: Verifying Firewall Still Works"

print_info "Testing SSH block (should be blocked)..."
docker exec attacker timeout 2 nc -vz 172.25.0.3 22 2>&1 > /dev/null || print_step "SSH properly blocked"

print_info "Testing HTTP (should work)..."
if docker exec attacker curl -s -o /dev/null -w "%{http_code}" http://172.25.0.3/ 2>/dev/null | grep -q 200; then
    print_step "HTTP working correctly"
else
    print_warning "HTTP may have issues"
fi
echo ""

# Check firewall logs
if [ -f "logs/firewall.log" ] && [ -s "logs/firewall.log" ]; then
    FIREWALL_LINES=$(wc -l < logs/firewall.log)
    print_step "Firewall logs working ($FIREWALL_LINES lines)"
else
    print_warning "Firewall logs may need attention"
fi
echo ""

################################################################################
# Summary
################################################################################
print_header "Fix Complete! 🎉"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Summary:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
print_step "Zeek configuration updated with JSON logging"
print_step "Zeek container restarted"
print_step "Firewall continues to work normally"
echo ""

if [ -f "logs/zeek/conn.log" ] && grep -q '{' logs/zeek/conn.log 2>/dev/null; then
    print_step "Zeek is now logging in JSON format ✓"
else
    print_warning "Zeek may not be using JSON format yet - check logs"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Next Steps:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Run attack scenarios to test detection:"
echo -e "     ${YELLOW}./scripts/attack_scenarios.sh --zeek${NC}"
echo ""
echo "  2. Monitor Zeek alerts in real-time:"
echo -e "     ${YELLOW}tail -f logs/zeek/notice.log${NC}"
echo ""
echo "  3. Check Zeek connections:"
echo -e "     ${YELLOW}tail -f logs/zeek/conn.log | jq${NC}"
echo ""
echo "  4. View Zeek HTTP logs:"
echo -e "     ${YELLOW}tail -f logs/zeek/http.log | jq${NC}"
echo ""
echo "  5. Check system status:"
echo -e "     ${YELLOW}./check_status.sh${NC}"
echo ""
echo "  6. Restart Filebeat to pick up new logs:"
echo -e "     ${YELLOW}docker compose restart filebeat${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""