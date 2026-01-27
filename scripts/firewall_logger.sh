#!/bin/bash
# This runs on your HOST (moham@salim)
# Updated for Alpine/BusyBox compatibility

LOG_FILE="./logs/firewall.log"
CONTAINER_NAME="target_web"

echo "=========================================="
echo "   Container Firewall Log Collector (Alpine)"
echo "=========================================="
echo "[*] Target: $CONTAINER_NAME"
echo "[*] Saving to: $LOG_FILE"
echo ""

mkdir -p ./logs
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

log_to_json() {
    local line="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local action="unknown"
    if echo "$line" | grep -q "FIREWALL_BLOCK"; then action="block"; fi
    if echo "$line" | grep -q "FIREWALL_RATELIMIT"; then action="rate_limit"; fi

    local src_ip=$(echo "$line" | grep -oP 'SRC=\K[0-9.]+')
    local dst_ip=$(echo "$line" | grep -oP 'DST=\K[0-9.]+')
    local proto=$(echo "$line" | grep -oP 'PROTO=\K[^ ]+')
    local dport=$(echo "$line" | grep -oP 'DPT=\K[0-9]+')

    cat <<EOF
{"@timestamp":"$timestamp","action":"$action","protocol":"$proto","src_ip":"$src_ip","dst_ip":"$dst_ip","dst_port":"$dport","log_type":"firewall","message":"$line"}
EOF
}

echo "[*] Starting log polling loop..."
echo "[*] Monitoring for [FIREWALL_BLOCK] and [FIREWALL_RATELIMIT]"
echo "[*] (Press Ctrl+C to stop)"

# Since Alpine dmesg can't "follow", we store what we've already seen
LAST_LOGS=""

while true; do
    # 1. Get current firewall logs from container
    # 2. Compare with what we saw last time to find ONLY new lines
    CURRENT_LOGS=$(docker exec $CONTAINER_NAME dmesg | grep "\[FIREWALL")
    
    # Simple logic to process only new lines
    NEW_LINES=$(comm -13 <(echo "$LAST_LOGS" | sort) <(echo "$CURRENT_LOGS" | sort))

    if [ ! -z "$NEW_LINES" ]; then
        while read -r line; do
            if [ ! -z "$line" ]; then
                json_line=$(log_to_json "$line")
                echo "$json_line" >> "$LOG_FILE"
                echo "[$(date +%H:%M:%S)] NEW EVENT: $line"
            fi
        done <<< "$NEW_LINES"
    fi

    LAST_LOGS="$CURRENT_LOGS"
    sleep 1 # Check for new logs every second
done