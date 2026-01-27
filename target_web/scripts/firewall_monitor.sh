#!/bin/bash
################################################################################
# Professional Firewall Monitor
# Reads kernel logs from dmesg and converts to structured JSON for Filebeat
################################################################################

set -e

LOG_FILE="/logs/firewall.log"
TEMP_STATE="/tmp/firewall_state.txt"

echo "[Monitor] Starting firewall log monitor..."
echo "[Monitor] Writing to: $LOG_FILE"

# Initialize log file
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

# Initialize state tracking
touch "$TEMP_STATE"

# Function to convert kernel log to JSON
log_to_json() {
    local log_line="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Extract fields from kernel log
    local action="unknown"
    local src_ip=""
    local dst_ip=""
    local src_port=""
    local dst_port=""
    local protocol=""
    local interface=""
    local reason=""
    
    # Determine action type
    if echo "$log_line" | grep -q "\[FIREWALL_BLOCK\]"; then
        action="block"
        reason="firewall_blocked"
    elif echo "$log_line" | grep -q "\[FIREWALL_RATELIMIT\]"; then
        action="rate_limit"
        reason="rate_limit_exceeded"
    elif echo "$log_line" | grep -q "\[FIREWALL_PASS\]"; then
        action="pass"
        reason="firewall_allowed"
    fi
    
    # Extract specific reasons from comments
    if echo "$log_line" | grep -q "FIREWALL_TCP_NULL"; then
        reason="tcp_null_scan_detected"
    elif echo "$log_line" | grep -q "FIREWALL_TCP_XMAS"; then
        reason="tcp_xmas_scan_detected"
    elif echo "$log_line" | grep -q "FIREWALL_TCP_FIN"; then
        reason="tcp_fin_scan_detected"
    elif echo "$log_line" | grep -q "FIREWALL_SSH_BLOCK"; then
        reason="ssh_blocked"
    elif echo "$log_line" | grep -q "FIREWALL_HTTP_FLOOD"; then
        reason="http_flood_detected"
    elif echo "$log_line" | grep -q "FIREWALL_ICMP_FLOOD"; then
        reason="icmp_flood_detected"
    elif echo "$log_line" | grep -q "FIREWALL_BLOCK_ATTACKER"; then
        reason="attacker_ip_blocked"
    elif echo "$log_line" | grep -q "FIREWALL_DEFAULT_DROP"; then
        reason="default_deny"
    fi
    
    # Extract network parameters using grep
    src_ip=$(echo "$log_line" | grep -oP 'SRC=\K[0-9.]+' || echo "unknown")
    dst_ip=$(echo "$log_line" | grep -oP 'DST=\K[0-9.]+' || echo "unknown")
    protocol=$(echo "$log_line" | grep -oP 'PROTO=\K[^ ]+' || echo "unknown")
    
    # Extract ports if TCP/UDP
    if [ "$protocol" = "TCP" ] || [ "$protocol" = "UDP" ]; then
        src_port=$(echo "$log_line" | grep -oP 'SPT=\K[0-9]+' || echo "0")
        dst_port=$(echo "$log_line" | grep -oP 'DPT=\K[0-9]+' || echo "0")
    else
        src_port="0"
        dst_port="0"
    fi
    
    # Extract interface
    interface=$(echo "$log_line" | grep -oP 'IN=\K[^ ]+' || echo "eth0")
    
    # Extract TCP flags if present
    local tcp_flags=""
    if echo "$log_line" | grep -q "SPT="; then
        tcp_flags=$(echo "$log_line" | grep -oP 'FLAGS=\K[^ ]+' || echo "")
    fi
    
    # Build JSON
    cat <<EOF
{"@timestamp":"$timestamp","action":"$action","protocol":"$(echo $protocol | tr '[:upper:]' '[:lower:]')","src_ip":"$src_ip","dst_ip":"$dst_ip","src_port":$src_port,"dst_port":$dst_port,"interface":"$interface","reason":"$reason","tcp_flags":"$tcp_flags","log_type":"firewall","log_source":"iptables","component":"firewall","security_layer":"network_filter"}
EOF
}

# Track seen log entries to avoid duplicates
declare -A seen_logs

# Main monitoring loop
echo "[Monitor] Entering monitoring loop (Ctrl+C to stop)"

# Initial scan of existing dmesg
dmesg | grep "\[FIREWALL" | while IFS= read -r line; do
    line_hash=$(echo "$line" | md5sum | cut -d' ' -f1)
    seen_logs[$line_hash]=1
done

# Continuous monitoring
LAST_DMESG_SIZE=0

while true; do
    # Read new kernel messages
    CURRENT_DMESG=$(dmesg | grep "\[FIREWALL" || true)
    CURRENT_SIZE=$(echo "$CURRENT_DMESG" | wc -l)
    
    # Check if there are new messages
    if [ "$CURRENT_SIZE" -gt "$LAST_DMESG_SIZE" ]; then
        # Process only new lines
        echo "$CURRENT_DMESG" | tail -n +$((LAST_DMESG_SIZE + 1)) | while IFS= read -r line; do
            if [ -n "$line" ]; then
                # Generate hash to avoid duplicates
                line_hash=$(echo "$line" | md5sum | cut -d' ' -f1)
                
                if [ -z "${seen_logs[$line_hash]}" ]; then
                    seen_logs[$line_hash]=1
                    
                    # Convert to JSON and append to log file
                    json_line=$(log_to_json "$line")
                    echo "$json_line" >> "$LOG_FILE"
                    
                    # Print to console for debugging
                    echo "[$(date +%H:%M:%S)] NEW EVENT: $line"
                fi
            fi
        done
        
        LAST_DMESG_SIZE=$CURRENT_SIZE
    fi
    
    # Sleep briefly before next check
    sleep 1
done