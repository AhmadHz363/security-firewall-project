#!/bin/bash
# Simple Firewall Log Generator
# This will create realistic logs and show them in real-time

LOG_FILE="./logs/firewall.log"
PROJECT_DIR="$(pwd)"

cd "$PROJECT_DIR"

# Create logs directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Clear existing log
> "$LOG_FILE"

echo "=========================================="
echo "Simple Firewall Logger"
echo "=========================================="
echo "Writing to: $LOG_FILE"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping logger..."
    exit 0
}
trap cleanup SIGINT SIGTERM

# Generate initial logs
echo "Generating initial firewall logs..."

# Initial log entries
cat > "$LOG_FILE" << EOF
{"@timestamp":"2026-01-27T11:00:00Z","action":"block","protocol":"icmp","src_ip":"172.25.0.4","dst_ip":"1.1.1.1","src_port":0,"dst_port":0,"interface":"eth0","reason":"blocked_destination","log_type":"firewall","log_source":"iptables"}
{"@timestamp":"2026-01-27T11:00:01Z","action":"rate_limit","protocol":"tcp","src_ip":"172.25.0.4","dst_ip":"172.25.0.3","src_port":54321,"dst_port":80,"interface":"eth0","reason":"http_dos_protection","log_type":"firewall","log_source":"iptables"}
{"@timestamp":"2026-01-27T11:00:02Z","action":"block","protocol":"tcp","src_ip":"172.25.0.4","dst_ip":"172.25.0.3","src_port":54322,"dst_port":22,"interface":"eth0","reason":"ssh_blocked","log_type":"firewall","log_source":"iptables"}
EOF

echo "Initial logs created. Now watching for changes..."
echo ""

# Continuously add new logs
while true; do
    # Wait a bit and add new log
    sleep $((RANDOM % 5 + 3))
    
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    ACTIONS=("block" "pass" "rate_limit")
    PROTOCOLS=("TCP" "UDP" "ICMP")
    ACTION=${ACTIONS[$RANDOM % 3]}
    PROTOCOL=${PROTOCOLS[$RANDOM % 3]}
    SRC_PORT=$((RANDOM % 65535))
    DST_PORT=$((RANDOM % 65535))
    
    # Create JSON log entry
    cat <<EOF >> "$LOG_FILE"
{"@timestamp":"$TIMESTAMP","action":"$ACTION","protocol":"$PROTOCOL","src_ip":"172.25.0.4","dst_ip":"172.25.0.3","src_port":$SRC_PORT,"dst_port":$DST_PORT,"interface":"eth0","reason":"test_event","log_type":"firewall","log_source":"iptables"}
EOF
    
    echo "[$(date +%H:%M:%S)] Added new firewall log entry"
done