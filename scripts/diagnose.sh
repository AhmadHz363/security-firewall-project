#!/bin/bash
################################################################################
# Diagnostic and Troubleshooting Script
# Checks system health and helps identify issues
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

print_pass() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_fail() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo ""
print_header "Network Security System Diagnostics"
echo ""

################################################################################
# 1. Container Status
################################################################################
print_header "1. Container Status"
echo ""

REQUIRED_CONTAINERS=("elasticsearch" "kibana" "filebeat" "zeek" "target_web" "attacker")

for container in "${REQUIRED_CONTAINERS[@]}"; do
    if docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        STATUS=$(docker ps --format "{{.Status}}" --filter "name=^${container}$")
        print_pass "$container is running ($STATUS)"
    else
        print_fail "$container is NOT running"
    fi
done

echo ""

################################################################################
# 2. Service Health Checks
################################################################################
print_header "2. Service Health Checks"
echo ""

# Elasticsearch
if curl -s http://localhost:9200 | grep -q "cluster_name"; then
    CLUSTER_HEALTH=$(curl -s http://localhost:9200/_cluster/health | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    print_pass "Elasticsearch responding (status: $CLUSTER_HEALTH)"
else
    print_fail "Elasticsearch not responding"
fi

# Kibana
if curl -s http://localhost:5601/api/status | grep -q "available"; then
    print_pass "Kibana responding and available"
else
    print_fail "Kibana not responding"
fi

# Target Web
if curl -s http://localhost:8080 | grep -q "Security Testing Target"; then
    print_pass "Target web server responding"
else
    print_fail "Target web server not responding"
fi

echo ""

################################################################################
# 3. Log Files
################################################################################
print_header "3. Log Files Status"
echo ""

# Firewall log
if [ -f "logs/firewall.log" ]; then
    SIZE=$(stat -f%z logs/firewall.log 2>/dev/null || stat -c%s logs/firewall.log 2>/dev/null)
    LINES=$(wc -l < logs/firewall.log)
    if [ "$LINES" -gt 0 ]; then
        print_pass "Firewall log exists ($LINES lines, $SIZE bytes)"
    else
        print_warn "Firewall log exists but is empty"
    fi
else
    print_fail "Firewall log does not exist"
fi

# Zeek logs
ZEEK_LOGS=("conn.log" "http.log" "dns.log" "notice.log")
for log in "${ZEEK_LOGS[@]}"; do
    if [ -f "logs/zeek/$log" ]; then
        LINES=$(wc -l < "logs/zeek/$log")
        print_pass "Zeek $log exists ($LINES lines)"
    else
        print_warn "Zeek $log not found"
    fi
done

echo ""

################################################################################
# 4. Firewall Configuration
################################################################################
print_header "4. Firewall Configuration"
echo ""

if docker ps --format "{{.Names}}" | grep -q "^target_web$"; then
    # Check if iptables is accessible
    if docker exec target_web iptables -L -n > /dev/null 2>&1; then
        RULES_COUNT=$(docker exec target_web iptables -L INPUT -n | grep -c .)
        print_pass "Firewall rules accessible ($RULES_COUNT lines)"
        
        # Check for specific rules
        if docker exec target_web iptables -L -n | grep -q "LOG_DROP"; then
            print_pass "Custom LOG_DROP chain found"
        else
            print_fail "Custom LOG_DROP chain NOT found"
        fi
        
        if docker exec target_web iptables -L -n | grep -q "LOG_RATELIMIT"; then
            print_pass "Custom LOG_RATELIMIT chain found"
        else
            print_fail "Custom LOG_RATELIMIT chain NOT found"
        fi
    else
        print_fail "Cannot access iptables in target_web container"
    fi
    
    # Check if firewall monitor is running
    if docker exec target_web ps aux | grep -q "[f]irewall_monitor"; then
        print_pass "Firewall monitor process is running"
    else
        print_fail "Firewall monitor process NOT running"
    fi
else
    print_fail "target_web container not running"
fi

echo ""

################################################################################
# 5. Elasticsearch Indices
################################################################################
print_header "5. Elasticsearch Indices"
echo ""

if curl -s http://localhost:9200/_cat/indices?v 2>/dev/null | grep -q "firewall\|zeek"; then
    print_pass "Security indices exist:"
    curl -s http://localhost:9200/_cat/indices?v 2>/dev/null | grep -E "firewall|zeek" | while read line; do
        echo "    $line"
    done
else
    print_warn "No security indices found yet"
    print_info "Indices are created when first logs arrive"
fi

echo ""

################################################################################
# 6. Filebeat Status
################################################################################
print_header "6. Filebeat Status"
echo ""

if docker ps --format "{{.Names}}" | grep -q "^filebeat$"; then
    # Check if filebeat is shipping logs
    LAST_LOG=$(docker logs filebeat 2>&1 | tail -5)
    if echo "$LAST_LOG" | grep -q "Non-zero metrics"; then
        print_pass "Filebeat is actively shipping logs"
    else
        print_warn "Filebeat may not be shipping logs yet"
    fi
else
    print_fail "Filebeat container not running"
fi

echo ""

################################################################################
# 7. Network Configuration
################################################################################
print_header "7. Network Configuration"
echo ""

# Check if security_net exists
if docker network ls | grep -q "security_net"; then
    print_pass "security_net network exists"
    
    # Get network details
    SUBNET=$(docker network inspect security_net -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
    print_info "Subnet: $SUBNET"
    
    # List connected containers
    print_info "Connected containers:"
    docker network inspect security_net -f '{{range $k, $v := .Containers}}{{printf "    %s: %s\n" $v.Name $v.IPv4Address}}{{end}}'
else
    print_fail "security_net network does not exist"
fi

echo ""

################################################################################
# 8. Resource Usage
################################################################################
print_header "8. Resource Usage"
echo ""

if docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | grep -E "elasticsearch|kibana|target_web"; then
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep -E "NAME|elasticsearch|kibana|target_web"
else
    print_warn "Could not get resource usage"
fi

echo ""

################################################################################
# 9. Recent Errors
################################################################################
print_header "9. Recent Container Errors"
echo ""

for container in "${REQUIRED_CONTAINERS[@]}"; do
    if docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        ERRORS=$(docker logs $container 2>&1 | grep -i "error\|fail\|exception" | tail -3)
        if [ -n "$ERRORS" ]; then
            print_warn "$container has recent errors:"
            echo "$ERRORS" | while read line; do
                echo "    $line"
            done
        fi
    fi
done

echo ""

################################################################################
# 10. Quick Test
################################################################################
print_header "10. Quick Connectivity Test"
echo ""

print_info "Testing connectivity from attacker to target..."
if docker exec attacker ping -c 2 172.25.0.3 > /dev/null 2>&1; then
    print_pass "Attacker can reach target (ICMP)"
else
    print_fail "Attacker cannot reach target"
fi

print_info "Testing HTTP connectivity..."
if docker exec attacker curl -s http://172.25.0.3/ > /dev/null 2>&1; then
    print_pass "HTTP connection successful"
else
    print_fail "HTTP connection failed"
fi

echo ""

################################################################################
# Summary and Recommendations
################################################################################
print_header "Summary and Recommendations"
echo ""

# Count issues
ISSUES=0

# Check critical services
for container in "elasticsearch" "kibana" "target_web"; do
    if ! docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        ((ISSUES++))
    fi
done

# Check logs
if [ ! -f "logs/firewall.log" ] || [ ! -s "logs/firewall.log" ]; then
    ((ISSUES++))
fi

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ System appears healthy!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run attack scenarios: ./scripts/attack_scenarios.sh"
    echo "  2. Monitor logs: tail -f logs/firewall.log"
    echo "  3. View in Kibana: http://localhost:5601"
else
    echo -e "${YELLOW}⚠ Found $ISSUES potential issue(s)${NC}"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Check container logs: docker logs <container_name>"
    echo "  2. Restart problematic services: docker compose restart <service>"
    echo "  3. Full restart: docker compose down && ./setup.sh"
    echo "  4. Check system resources: free -h && df -h"
fi

echo ""

################################################################################
# Useful Commands
################################################################################
print_header "Useful Commands"
echo ""

echo "View all logs:"
echo "  docker compose logs -f"
echo ""
echo "Restart a service:"
echo "  docker compose restart <service_name>"
echo ""
echo "Check firewall rules:"
echo "  docker exec target_web iptables -L -n -v"
echo ""
echo "Test Elasticsearch:"
echo "  curl http://localhost:9200/_cat/indices?v"
echo ""
echo "Generate test traffic:"
echo "  ./scripts/attack_scenarios.sh"
echo ""

print_header "Diagnostics Complete"
echo ""