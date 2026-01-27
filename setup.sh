#!/bin/bash
################################################################################
# Professional Network Security Monitoring System
# Complete Setup and Deployment Script
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

print_header "Network Security Monitoring System - Setup"
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
print_header "Step 2: Cleaning Up Existing Deployment"

if docker ps -a | grep -qE "elasticsearch|kibana|filebeat|zeek|target_web|attacker"; then
    print_info "Stopping existing containers..."
    docker compose down -v 2>/dev/null || true
    sleep 3
    print_step "Containers stopped"
fi

# Clean up
docker volume prune -f > /dev/null 2>&1 || true
docker network prune -f > /dev/null 2>&1 || true
print_step "Docker resources cleaned"

echo ""

################################################################################
# Create Directory Structure
################################################################################
print_header "Step 3: Setting Up Directory Structure"

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
print_header "Step 4: Building Docker Images"

print_info "Building target_web container..."
if docker compose build target_web; then
    print_step "target_web image built successfully"
else
    print_error "Failed to build target_web image"
    exit 1
fi

echo ""

################################################################################
# Start Services
################################################################################
print_header "Step 5: Starting Services"

print_info "Starting all services..."
docker compose up -d

print_step "Services started"
echo ""

################################################################################
# Wait for Elasticsearch
################################################################################
print_header "Step 6: Waiting for Elasticsearch"

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
print_header "Step 7: Waiting for Kibana"

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
# Verify Services
################################################################################
print_header "Step 8: Verifying Services"

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

# Check firewall logs
sleep 5
if [ -f "logs/firewall.log" ]; then
    print_step "Firewall logging active"
else
    print_warning "Waiting for firewall logs to be created..."
fi

echo ""

################################################################################
# Create Index Patterns in Kibana
################################################################################
print_header "Step 9: Configuring Kibana Index Patterns"

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
# Test Firewall
################################################################################
print_header "Step 10: Testing Firewall"

print_info "Sending test traffic to generate firewall logs..."

# Test ICMP
docker exec attacker ping -c 5 172.25.0.3 > /dev/null 2>&1 &

# Test HTTP
docker exec attacker curl -s http://172.25.0.3/ > /dev/null 2>&1 &

wait

sleep 3

if [ -f "logs/firewall.log" ] && [ -s "logs/firewall.log" ]; then
    LOG_LINES=$(wc -l < logs/firewall.log)
    print_step "Firewall logs generated ($LOG_LINES lines)"
else
    print_warning "No firewall logs yet - may need a few seconds"
fi

echo ""

################################################################################
# Installation Complete
################################################################################
print_header "Installation Complete! 🎉"

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
echo "  4. Access Kibana Dashboard:"
echo -e "     ${YELLOW}Open http://localhost:5601 in browser${NC}"
echo -e "     ${YELLOW}Go to Discover and select 'firewall-*' or 'zeek-*'${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${CYAN}Troubleshooting:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${BLUE}Check container logs:${NC}     docker logs target_web"
echo -e "  ${BLUE}Check firewall rules:${NC}     docker exec target_web iptables -L -n -v"
echo -e "  ${BLUE}Restart system:${NC}           docker compose restart"
echo -e "  ${BLUE}Stop system:${NC}              docker compose down"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
print_warning "Remember: This is for educational purposes only!"
echo ""