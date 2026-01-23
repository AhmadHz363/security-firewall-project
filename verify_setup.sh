#!/bin/bash

echo "======================================"
echo "  Firewall System Verification"
echo "======================================"
echo ""

passed=0
failed=0

# Test 1: Docker containers running
echo -n "[1] Docker containers running... "
if docker ps | grep -q "es.*Up" && docker ps | grep -q "kibana.*Up" && docker ps | grep -q "filebeat.*Up"; then
    echo "✓ PASS"
    ((passed++))
else
    echo "✗ FAIL"
    ((failed++))
fi

# Test 2: Elasticsearch responding
echo -n "[2] Elasticsearch responding... "
if curl -s http://localhost:9200 | grep -q "cluster_name"; then
    echo "✓ PASS"
    ((passed++))
else
    echo "✗ FAIL"
    ((failed++))
fi

# Test 3: Kibana responding
echo -n "[3] Kibana responding... "
if curl -s http://localhost:5601/api/status | grep -q "available"; then
    echo "✓ PASS"
    ((passed++))
else
    echo "✗ FAIL (may need more time to start)"
    ((failed++))
fi

# Test 4: pf.log exists
echo -n "[4] pf.log file exists... "
if [ -f "logs/pf.log" ]; then
    echo "✓ PASS"
    ((passed++))
else
    echo "✗ FAIL"
    ((failed++))
fi

# Test 5: pf.log has valid JSON
echo -n "[5] pf.log contains valid JSON... "
if [ -f "logs/pf.log" ] && [ -s "logs/pf.log" ]; then
    if head -1 logs/pf.log | python3 -m json.tool > /dev/null 2>&1; then
        echo "✓ PASS"
        ((passed++))
    else
        echo "✗ FAIL - Invalid JSON format"
        echo "    First line: $(head -1 logs/pf.log)"
        ((failed++))
    fi
else
    echo "⊘ SKIP - No data yet"
fi

# Test 6: Firebeat harvesting logs
echo -n "[6] Filebeat harvesting logs... "
if docker logs filebeat 2>&1 | grep -q "harvester.*started"; then
    echo "✓ PASS"
    ((passed++))
else
    echo "⚠ WARNING - Not harvesting yet"
    ((failed++))
fi

# Test 7: Data in Elasticsearch
echo -n "[7] Data in Elasticsearch... "
count=$(curl -s "http://localhost:9200/firewall-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2)
if [ -n "$count" ] && [ "$count" -gt 0 ]; then
    echo "✓ PASS ($count documents)"
    ((passed++))
else
    echo "⊘ SKIP - No documents yet (count: ${count:-0})"
fi

echo ""
echo "======================================"
echo "Results: $passed passed, $failed failed"
echo "======================================"
echo ""

if [ "$failed" -eq 0 ] && [ "$passed" -ge 5 ]; then
    echo "✓ System is ready!"
    echo ""
    echo "Next steps:"
    echo "1. Start logger: sudo ./firewall/pf_logger.sh"
    echo "2. Generate traffic: ping -c 10 8.8.8.8"
    echo "3. View in Kibana: http://localhost:5601"
else
    echo "⚠ System needs attention"
    echo ""
    echo "Common fixes:"
    echo "- Wait longer (run this script again in 30 seconds)"
    echo "- Check Docker logs: docker logs <container>"
    echo "- Restart: cd docker && docker-compose restart"
fi

echo ""