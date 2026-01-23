#!/bin/bash
# Creates index template and ingest pipeline for JSON logs

# Index template
curl -X PUT "http://localhost:9200/_index_template/firewall-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["firewall-*"],
  "template": {
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

# Ingest pipeline (optional, can process JSON)
curl -X PUT "http://localhost:9200/_ingest/pipeline/firewall-json-parser" -H 'Content-Type: application/json' -d'
{
  "description": "Parse JSON firewall logs",
  "processors": [
    {
      "json": {
        "field": "message",
        "target_field": "json_parsed",
        "add_to_root": true,
        "ignore_failure": true
      }
    }
  ]
}
'

echo "[*] Elasticsearch pipeline and template created!"
