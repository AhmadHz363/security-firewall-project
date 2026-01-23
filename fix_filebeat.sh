#!/bin/bash

echo "======================================"
echo "Fixing Filebeat Configuration Issue"
echo "======================================"
echo ""

# Navigate to docker directory
cd docker 2>/dev/null || {
    echo "Error: Run this from the project root"
    exit 1
}

# Step 1: Stop containers
echo "[1] Stopping containers..."
docker-compose down -v
echo "✓ Done"
echo ""

# Step 2: Remove the filebeat directory and recreate properly
echo "[2] Fixing filebeat directory structure..."
rm -rf filebeat
mkdir -p filebeat
echo "✓ Directory created"
echo ""

# Step 3: Create the filebeat.yml file (not directory!)
echo "[3] Creating filebeat.yml file..."
cat > filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /usr/share/filebeat/logs/pf.log
    json.keys_under_root: true
    json.add_error_key: true
    json.overwrite_keys: true
    scan_frequency: 1s

output.elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  index: "firewall-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "firewall"
setup.template.pattern: "firewall-*"

logging.level: info
EOF

if [ -f "filebeat/filebeat.yml" ]; then
    echo "✓ filebeat.yml created successfully"
    ls -lh filebeat/filebeat.yml
else
    echo "✗ Failed to create filebeat.yml"
    exit 1
fi
echo ""

# Step 4: Create logs directory
echo "[4] Creating logs directory..."
mkdir -p logs
touch logs/pf.log
chmod 666 logs/pf.log
echo "✓ logs/pf.log created"
echo ""

# Step 5: Verify docker-compose.yaml
echo "[5] Verifying docker-compose.yaml..."
if [ -f "docker-compose.yaml" ]; then
    echo "✓ docker-compose.yaml exists"
    echo ""
    echo "Volume mounts:"
    grep -A2 "filebeat:" docker-compose.yaml | grep "volumes:" -A5 | head -6
else
    echo "✗ docker-compose.yaml not found"
    exit 1
fi
echo ""

# Step 6: Start containers
echo "[6] Starting Docker containers..."
docker-compose up -d
echo ""

# Step 7: Wait and verify
echo "[7] Waiting 30 seconds for containers to start..."
sleep 30
echo ""

echo "[8] Checking container status..."
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "filebeat|kibana|es"
echo ""

# Step 9: Check filebeat specifically
echo "[9] Checking Filebeat container..."
if docker ps | grep -q "filebeat.*Up"; then
    echo "✓ Filebeat is running"
    echo ""
    echo "Filebeat logs (last 10 lines):"
    docker logs filebeat --tail 10
else
    echo "✗ Filebeat is NOT running"
    echo ""
    echo "Checking for errors:"
    docker logs filebeat 2>&1 | tail -20
fi
echo ""

echo "======================================"
echo "Fix Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Run verification: cd .. && ./verify_setup.sh"
echo "2. If all passes, start logger: sudo ./firewall/pf_logger.sh"