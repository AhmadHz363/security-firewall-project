#!/bin/bash

echo "======================================"
echo "Complete Firewall System Fix"
echo "======================================"
echo ""

# Step 1: Clean up all tcpdump processes
echo "[1] Cleaning up old tcpdump processes..."
sudo pkill -9 -f tcpdump
sleep 2
echo "✓ Done"
echo ""

# Step 2: Clean up Docker
echo "[2] Stopping and removing Docker containers..."
cd docker 2>/dev/null || cd "$(dirname "$0")/docker" 2>/dev/null || {
    echo "Error: Cannot find docker directory"
    exit 1
}
docker-compose down -v
echo "✓ Done"
echo ""

# Step 3: Fix filebeat.yml file issue
echo "[3] Fixing filebeat.yml configuration..."
mkdir -p filebeat
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
echo "✓ filebeat.yml created"
echo ""

# Step 4: Verify docker-compose.yaml is correct
echo "[4] Verifying docker-compose.yaml..."
if grep -q "filebeat.yml:/usr/share/filebeat/filebeat.yml:ro" docker-compose.yaml; then
    echo "✓ docker-compose.yaml looks correct"
else
    echo "⚠ Warning: filebeat volume mount may need adjustment"
fi
echo ""

# Step 5: Clean and recreate logs
echo "[5] Setting up logs directory..."
rm -rf logs
mkdir -p logs
touch logs/pf.log
chmod 666 logs/pf.log
echo "✓ logs/pf.log created with proper permissions"
echo ""

# Step 6: Start Docker services
echo "[6] Starting Docker services..."
docker-compose up -d
echo "⏳ Waiting 30 seconds for services to start..."
sleep 30
echo "✓ Services should be ready"
echo ""

# Step 7: Check service status
echo "[7] Checking service status..."
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "es|kibana|filebeat"
echo ""

# Step 8: Verify Elasticsearch is healthy
echo "[8] Checking Elasticsearch health..."
for i in {1..10}; do
    if curl -s http://localhost:9200/_cluster/health | grep -q "yellow\|green"; then
        echo "✓ Elasticsearch is healthy"
        break
    else
        echo "⏳ Waiting for Elasticsearch... ($i/10)"
        sleep 3
    fi
done
echo ""

# Step 9: Create index template
echo "[9] Creating Elasticsearch index template..."
curl -X PUT "http://localhost:9200/_index_template/firewall-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["firewall-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "action": { "type": "keyword" },
        "protocol": { "type": "keyword" },
        "src_ip": { "type": "ip" },
        "dst_ip": { "type": "ip" },
        "log_type": { "type": "keyword" },
        "message": { "type": "text" }
      }
    }
  }
}
'
echo ""
echo "✓ Template created"
echo ""

echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. In a new terminal, run: sudo ./firewall/pf_logger.sh"
echo "2. Generate traffic: ping -c 10 8.8.8.8"
echo "3. Check logs: tail -f logs/pf.log"
echo "4. Open Kibana: http://localhost:5601"
echo ""