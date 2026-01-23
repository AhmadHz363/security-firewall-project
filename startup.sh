#!/bin/bash
# startup.sh - Starts Docker containers and prepares the firewall monitoring system

echo "[*] Starting Firewall Monitoring System..."

# Navigate to docker folder
cd docker || exit

# Start Docker containers
echo "[*] Starting Elasticsearch, Kibana, Filebeat..."
docker-compose up -d

# Wait for Elasticsearch to be ready
echo "[*] Waiting for Elasticsearch to be ready (HTTPS)..."
until curl -sk https://localhost:9200/_cluster/health?wait_for_status=yellow >/dev/null; do
  echo "Waiting for Elasticsearch..."
  sleep 5
done
echo "[*] Elasticsearch is ready!"


# Run setup script for pipelines and templates
echo "[*] Setting up Elasticsearch ingest pipelines..."
chmod +x setup-elasticsearch.sh
./setup-elasticsearch.sh

echo "[*] Firewall Monitoring System setup completed!"
echo "[*] Run 'sudo ./firewall/pf_logger.sh' to start logging firewall events."
