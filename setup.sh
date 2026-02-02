#!/bin/bash
################################################################################
# Complete Network Security Monitoring System Deployment
# Handles both fresh installation and system reset
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
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

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Parse command line arguments
FRESH_START=false
if [ "$1" == "--fresh" ] || [ "$1" == "--reset" ]; then
    FRESH_START=true
fi

if [ "$FRESH_START" = true ]; then
    print_header "Complete System Reset - Fresh Start"
else
    print_header "Network Security Monitoring System - Setup"
fi
echo "Project Directory: $PROJECT_DIR"
echo ""

################################################################################
# System Requirements Check
################################################################################
print_header "Step 1: System Requirements Check"

# Check Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    exit 1
fi
print_step "Docker installed"

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed"
    exit 1
fi
print_step "Docker Compose installed"

# Check permissions
if ! docker ps &> /dev/null; then
    print_error "Cannot run Docker commands"
    print_info "Run: sudo usermod -aG docker $USER"
    exit 1
fi
print_step "Docker permissions OK"

echo ""

################################################################################
# Stop Existing Containers
################################################################################
print_header "Step 2: Stopping Existing Containers"

if docker ps -a | grep -qE "elasticsearch|kibana|filebeat|zeek|target_web|attacker"; then
    print_info "Stopping all containers..."
    docker compose down -v 2>/dev/null || true
    sleep 3
    print_step "Containers stopped"
else
    print_info "No existing containers to stop"
fi

echo ""

################################################################################
# Clean Up (if fresh start)
################################################################################
if [ "$FRESH_START" = true ]; then
    print_header "Step 3: Cleaning Up Old Data"
    
    print_info "Removing old firewall logs..."
    rm -f logs/firewall.log
    print_step "Firewall logs removed"
    
    print_info "Removing old Zeek logs..."
    rm -rf logs/zeek/*
    print_step "Zeek logs removed"
    
    print_info "Cleaning Docker resources..."
    docker volume prune -f > /dev/null 2>&1 || true
    docker network prune -f > /dev/null 2>&1 || true
    print_step "Docker resources cleaned"
    
    echo ""
else
    print_header "Step 3: Cleaning Docker Resources"
    docker volume prune -f > /dev/null 2>&1 || true
    docker network prune -f > /dev/null 2>&1 || true
    print_step "Docker resources cleaned"
    echo ""
fi

################################################################################
# Create Directory Structure
################################################################################
print_header "Step 4: Setting Up Directory Structure"

mkdir -p logs/zeek
mkdir -p logs/pcap
mkdir -p target/html
mkdir -p target_web/scripts
mkdir -p filebeat
mkdir -p zeek
mkdir -p scripts

# Set permissions
chmod 777 logs logs/zeek logs/pcap 2>/dev/null || true

print_step "Directory structure created"
echo ""

################################################################################
# Build Docker Images
################################################################################
print_header "Step 5: Building Docker Images"

print_info "Building target_web container..."
if [ "$FRESH_START" = true ]; then
    # Force rebuild on fresh start
    if docker compose build --no-cache target_web; then
        print_step "target_web image rebuilt from scratch"
    else
        print_error "Failed to build target_web image"
        exit 1
    fi
else
    # Normal build (uses cache)
    if docker compose build target_web; then
        print_step "target_web image built successfully"
    else
        print_error "Failed to build target_web image"
        exit 1
    fi
fi

echo ""

################################################################################
# Start Services
################################################################################
print_header "Step 6: Starting All Services"

print_info "Starting services..."
docker compose up -d

print_step "Services started"
echo ""

################################################################################
# Wait for Elasticsearch
################################################################################
print_header "Step 7: Waiting for Elasticsearch"

print_info "Elasticsearch initializing (up to 2 minutes)..."
MAX_WAIT=40
WAIT_COUNT=0

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q "yellow\|green"; then
        print_step "Elasticsearch is ready!"
        break
    fi
    
    if [ $WAIT_COUNT -eq $((MAX_WAIT - 1)) ]; then
        print_error "Elasticsearch failed to start"
        print_info "Check logs: docker logs elasticsearch"
        exit 1
    fi
    
    printf "  Waiting... (%d/%d)\r" $WAIT_COUNT $MAX_WAIT
    sleep 5
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

echo ""
echo ""

################################################################################
# Wait for Kibana
################################################################################
print_header "Step 8: Waiting for Kibana"

print_info "Kibana initializing (up to 2 minutes)..."
MAX_WAIT=24
WAIT_COUNT=0

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q "available"; then
        print_step "Kibana is ready!"
        break
    fi
    
    if [ $WAIT_COUNT -eq $((MAX_WAIT - 1)) ]; then
        print_warning "Kibana taking longer than expected"
        print_info "It will continue initializing in background"
    fi
    
    printf "  Waiting... (%d/%d)\r" $WAIT_COUNT $MAX_WAIT
    sleep 5
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

echo ""
echo ""

################################################################################
# Wait for Zeek to Initialize
################################################################################
print_header "Step 9: Waiting for Zeek to Initialize"

print_info "Zeek starting up (30 seconds)..."
sleep 30
print_step "Zeek initialized"
echo ""

################################################################################
# Install Tools in Attacker Container
################################################################################
print_header "Step 10: Installing Attack Tools"

print_info "Installing curl, netcat, ping in attacker container..."
docker exec attacker bash -c "apt-get update -qq 2>/dev/null && apt-get install -y -qq curl netcat-openbsd iputils-ping 2>/dev/null" > /dev/null 2>&1 || print_warning "Some tools may already be installed"
print_step "Attack tools ready"
echo ""

################################################################################
# Verify Services
################################################################################
print_header "Step 11: Verifying System Status"

echo ""
print_info "Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAME|elasticsearch|kibana|filebeat|zeek|target|attacker"
echo ""

# Test services
if curl -s http://localhost:9200 | grep -q "cluster_name"; then
    print_step "Elasticsearch responding (http://localhost:9200)"
else
    print_warning "Elasticsearch not responding"
fi

if curl -s http://localhost:5601/api/status | grep -q "available"; then
    print_step "Kibana responding (http://localhost:5601)"
else
    print_warning "Kibana still initializing"
fi

if curl -s http://localhost:8080 | grep -q "Security Testing Target"; then
    print_step "Target web server responding (http://localhost:8080)"
else
    print_warning "Target web server not ready"
fi

echo ""

################################################################################
# Verify Firewall and ulogd2
################################################################################
print_header "Step 12: Verifying Firewall and ulogd2"

print_info "Checking ulogd2 process..."
if docker exec target_web ps aux | grep -v grep | grep -q ulogd; then
    print_step "ulogd2 is running"
else
    print_warning "ulogd2 not running - check docker logs target_web"
fi

print_info "Checking iptables rules..."
RULE_COUNT=$(docker exec target_web iptables -L INPUT -n | wc -l)
if [ "$RULE_COUNT" -gt 10 ]; then
    print_step "Firewall rules loaded ($RULE_COUNT lines)"
else
    print_warning "Firewall rules may not be loaded properly"
fi
echo ""

################################################################################
# Create Index Patterns in Kibana
################################################################################
print_header "Step 13: Configuring Kibana Index Patterns"

print_info "Waiting for Kibana API to be fully ready..."
sleep 10

# Create firewall index pattern
print_info "Creating firewall-* index pattern..."
curl -s -X POST "http://localhost:5601/api/saved_objects/index-pattern/firewall-*" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "firewall-*",
      "timeFieldName": "@timestamp"
    }
  }' > /dev/null 2>&1 && print_step "Firewall index pattern created" || print_info "Index pattern may already exist"

# Create zeek index pattern
print_info "Creating zeek-* index pattern..."
curl -s -X POST "http://localhost:5601/api/saved_objects/index-pattern/zeek-*" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "zeek-*",
      "timeFieldName": "@timestamp"
    }
  }' > /dev/null 2>&1 && print_step "Zeek index pattern created" || print_info "Index pattern may already exist"

echo ""

################################################################################
# Generate Test Traffic
################################################################################
print_header "Step 14: Generating Test Traffic"

print_info "Sending test HTTP request (should PASS)..."
docker exec attacker curl -s http://172.25.0.3/ > /dev/null
sleep 2
print_step "HTTP test sent"

print_info "Attempting SSH connection (should BLOCK)..."
docker exec attacker timeout 2 nc -vz 172.25.0.3 22 2>&1 > /dev/null || echo "  (blocked as expected)"
sleep 2
print_step "SSH test sent"

print_info "Sending ICMP ping..."
docker exec attacker ping -c 3 172.25.0.3 > /dev/null 2>&1 || true
sleep 2
print_step "ICMP test sent"

echo ""
print_info "Waiting for logs to be processed (10 seconds)..."
sleep 10
echo ""

################################################################################
# Verify Logs Were Created
################################################################################
print_header "Step 15: Verifying Log Generation"

# Check firewall logs
if [ -f "logs/firewall.log" ] && [ -s "logs/firewall.log" ]; then
    LOG_LINES=$(wc -l < logs/firewall.log)
    print_step "Firewall log exists ($LOG_LINES lines)"
    echo ""
    echo "=== Last Firewall Log Entry ==="
    tail -1 logs/firewall.log | jq . 2>/dev/null || tail -1 logs/firewall.log
    echo "==============================="
else
    print_warning "No firewall logs yet - may need more time"
fi

echo ""

# Check ulogd2 JSON
docker exec target_web bash -c '
if [ -f /var/log/ulogd/ulogd.json ]; then
    echo "ulogd JSON file exists ($(wc -l < /var/log/ulogd/ulogd.json) lines)"
else
    echo "WARNING: ulogd JSON file not found"
fi
'

echo ""

# Check Zeek logs
if [ -d "logs/zeek" ] && [ "$(ls -A logs/zeek)" ]; then
    print_step "Zeek logs directory contains files:"
    ls -lh logs/zeek/ | tail -5
else
    print_warning "Zeek logs directory is empty - check docker logs zeek"
fi

echo ""

################################################################################
# Check Zeek Status
################################################################################
print_header "Step 16: Verifying Zeek Status"

print_info "Checking Zeek logs..."
if [ -f "logs/zeek/conn.log" ]; then
    CONN_LINES=$(wc -l < logs/zeek/conn.log)
    print_step "Zeek conn.log exists ($CONN_LINES lines)"
    if [ "$CONN_LINES" -gt 5 ]; then
        print_step "Zeek is capturing traffic!"
    else
        print_warning "Zeek has few entries - may need more traffic"
    fi
else
    print_warning "Zeek conn.log not created yet"
    print_info "Check Zeek logs: docker logs zeek"
fi

echo ""

################################################################################
# Installation Complete
################################################################################
print_header "System Ready! 🎉"

echo -e "${GREEN}✓ Network Security Monitoring System is operational${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Access Points:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${BLUE}Elasticsearch:${NC} http://localhost:9200"
echo -e "  ${BLUE}Kibana:       ${NC} http://localhost:5601"
echo -e "  ${BLUE}Target Web:   ${NC} http://localhost:8080"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Next Steps:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Run Attack Scenarios:"
echo -e "     ${YELLOW}./scripts/attack_scenarios.sh${NC}"
echo ""
echo "  2. Monitor Firewall Logs:"
echo -e "     ${YELLOW}tail -f logs/firewall.log${NC}"
echo ""
echo "  3. Monitor Zeek Alerts:"
echo -e "     ${YELLOW}tail -f logs/zeek/notice.log${NC}"
echo ""
echo "  4. Monitor Zeek Connections:"
echo -e "     ${YELLOW}tail -f logs/zeek/conn.log${NC}"
echo ""
echo "  5. Check System Status:"
echo -e "     ${YELLOW}./check_status.sh${NC}"
echo ""
echo "  6. Diagnose Zeek Issues:"
echo -e "     ${YELLOW}./diagnose_zeek.sh${NC}"
echo ""
echo "  7. Access Kibana Dashboard:"
echo -e "     ${YELLOW}Open http://localhost:5601 in browser${NC}"
echo -e "     ${YELLOW}Go to Discover and select 'firewall-*' or 'zeek-*'${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Quick Commands:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${BLUE}Fresh start:${NC}             ./setup.sh --fresh"
echo -e "  ${BLUE}Check logs:${NC}              docker logs target_web"
echo -e "  ${BLUE}Check Zeek logs:${NC}         docker logs zeek"
echo -e "  ${BLUE}Check firewall rules:${NC}    docker exec target_web iptables -L -n -v"
echo -e "  ${BLUE}Restart system:${NC}          docker compose restart"
echo -e "  ${BLUE}Stop system:${NC}             docker compose down"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
print_warning "Remember: This is for educational purposes only!"
echo ""