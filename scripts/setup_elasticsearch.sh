#!/bin/bash
# Elasticsearch Setup Script - No Authentication Version

set -e

echo "=========================================="
echo "Elasticsearch Setup (No Auth)"
echo "=========================================="

# Wait for Elasticsearch
echo "Waiting for Elasticsearch..."
until curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; do
  echo "  Waiting..."
  sleep 5
done

echo "✓ Elasticsearch is ready"

# Create firewall index template
echo "Creating firewall index template..."
curl -s -X PUT "http://localhost:9200/_index_template/firewall-template" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["firewall-*"],
    "priority": 100,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "@timestamp": {"type": "date"},
          "action": {"type": "keyword"},
          "protocol": {"type": "keyword"},
          "src_ip": {"type": "ip"},
          "dst_ip": {"type": "ip"},
          "src_port": {"type": "integer"},
          "dst_port": {"type": "integer"},
          "log_source": {"type": "keyword"}
        }
      }
    }
  }' > /dev/null

echo "✓ Firewall template created"

# Create Zeek index template
echo "Creating Zeek index template..."
curl -s -X PUT "http://localhost:9200/_index_template/zeek-template" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["zeek-*"],
    "priority": 100,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "@timestamp": {"type": "date"},
          "ts": {"type": "date"},
          "note": {"type": "keyword"},
          "msg": {"type": "text"},
          "src": {"type": "ip"},
          "log_source": {"type": "keyword"}
        }
      }
    }
  }' > /dev/null

echo "✓ Zeek template created"
echo ""
echo "Setup complete!"