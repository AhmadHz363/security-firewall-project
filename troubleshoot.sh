#!/bin/bash

echo "======================================"
echo "Firewall Logging Troubleshooting"
echo "======================================"
echo ""

# 1. Check if Docker containers are running
echo "[1] Checking Docker containers..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

# 2. Check if pf.log exists and has data
echo "[2] Checking pf.log file..."
if [ -f "logs/pf.log" ]; then
    echo "✓ pf.log exists"
    echo "File size: $(ls -lh logs/pf.log | awk '{print $5}')"
    echo "Line count: $(wc -l < logs/pf.log)"
    echo ""
    echo "Last 3 lines of pf.log:"
    tail -n 3 logs/pf.log
else
    echo "✗ pf.log does NOT exist at logs/pf.log"
fi
echo ""

# 3. Check if tcpdump is running
echo "[3] Checking if tcpdump is running..."
if pgrep -f "tcpdump.*pflog0" > /dev/null; then
    echo "✓ tcpdump is running"
    ps aux | grep "[t]cpdump.*pflog0"
else
    echo "✗ tcpdump is NOT running"
    echo "  Run: sudo ./firewall/pf_logger.sh"
fi
echo ""

# 4. Check if pf is enabled
echo "[4] Checking if pf (packet filter) is enabled..."
sudo pfctl -s info | grep -E "Status:|Debug:"
echo ""

# 5. Check Elasticsearch health
echo "[5] Checking Elasticsearch health..."
curl -s http://localhost:9200/_cluster/health?pretty | grep -E "status|number_of_nodes"
echo ""

# 6. Check if ingest pipeline exists
echo "[6] Checking if ingest pipeline exists..."
curl -s http://localhost:9200/_ingest/pipeline/firewall-json-parser | jq '.["firewall-json-parser"]' 2>/dev/null || echo "Pipeline not found or jq not installed"
echo ""

# 7. Check Filebeat logs
echo "[7] Checking Filebeat logs (last 20 lines)..."
docker logs filebeat --tail 20
echo ""

# 8. Check if index exists in Elasticsearch
echo "[8] Checking if firewall index exists..."
curl -s http://localhost:9200/_cat/indices/firewall-*?v
echo ""

# 9. Check document count
echo "[9] Checking document count in Elasticsearch..."
curl -s http://localhost:9200/firewall-*/_count | jq .
echo ""

# 10. Test JSON format of pf.log
echo "[10] Testing if pf.log contains valid JSON..."
if [ -f "logs/pf.log" ]; then
    head -n 1 logs/pf.log | jq . 2>/dev/null && echo "✓ JSON format is valid" || echo "✗ JSON format is INVALID"
else
    echo "✗ pf.log does not exist"
fi
echo ""

echo "======================================"
echo "Troubleshooting complete!"
echo "======================================"