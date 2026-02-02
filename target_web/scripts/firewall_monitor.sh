#!/bin/bash
################################################################################
# Professional Firewall Monitor - FIXED VERSION
# Captures iptables logs via NFLOG and converts to JSON
################################################################################

set -e

LOG_FILE="/logs/firewall.log"
ULOGD_JSON="/var/log/ulogd/ulogd.json"
ULOGD_CONF="/etc/ulogd.conf"

echo "=========================================="
echo "   Firewall Monitor - NFLOG Edition"
echo "=========================================="
echo "[Monitor] Target log file: $LOG_FILE"
echo "[Monitor] NFLOG group: 1"
echo ""

# Initialize log file
mkdir -p /logs /var/log/ulogd
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

# Configure ulogd2 for JSON output
echo "[Monitor] Configuring ulogd2..."
cat > "$ULOGD_CONF" <<'EOF'
[global]
logfile="/var/log/ulogd/ulogd.log"
loglevel=5

plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_inppkt_NFLOG.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_raw2packet_BASE.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_IFINDEX.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_IP2STR.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_output_JSON.so"

stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,json1:JSON

[log1]
group=1

[json1]
file="/var/log/ulogd/ulogd.json"
sync=1
timestamp=1
EOF

echo "[Monitor] ✓ ulogd2 configured"

# Start ulogd2 daemon
echo "[Monitor] Starting ulogd2..."
ulogd 2>&1 | tee /var/log/ulogd/ulogd-startup.log &
ULOGD_PID=$!

# Wait for ulogd to initialize
sleep 5

# Check if ulogd started successfully
if ! kill -0 $ULOGD_PID 2>/dev/null; then
    echo "[Monitor] ✗ ERROR: ulogd2 failed to start"
    echo "[Monitor] Startup log:"
    cat /var/log/ulogd/ulogd-startup.log 2>/dev/null || echo "No startup log available"
    cat /var/log/ulogd/ulogd.log 2>/dev/null || echo "No ulogd log available"
    exit 1
fi

echo "[Monitor] ✓ ulogd2 running (PID: $ULOGD_PID)"
echo ""

# Function to convert ulogd JSON to Filebeat-compatible format
convert_to_firewall_log() {
    local ulogd_line="$1"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Extract fields using grep (since jq might fail if JSON is malformed)
    local src_ip=$(echo "$ulogd_line" | grep -oP '"src_ip":\s*"\K[^"]+' 2>/dev/null || echo "unknown")
    local dst_ip=$(echo "$ulogd_line" | grep -oP '"dest_ip":\s*"\K[^"]+' 2>/dev/null || echo "unknown")
    local proto_num=$(echo "$ulogd_line" | grep -oP '"ip\.protocol":\s*\K[0-9]+' 2>/dev/null || echo "0")
    local src_port=$(echo "$ulogd_line" | grep -oP '"src_port":\s*\K[0-9]+' 2>/dev/null || echo "0")
    local dst_port=$(echo "$ulogd_line" | grep -oP '"dest_port":\s*\K[0-9]+' 2>/dev/null || echo "0")
    local prefix=$(echo "$ulogd_line" | grep -oP '"oob\.prefix":\s*"\K[^"]+' 2>/dev/null || echo "")
    
    # Convert protocol number to name
    local protocol="unknown"
    case "$proto_num" in
        1) protocol="icmp" ;;
        6) protocol="tcp" ;;
        17) protocol="udp" ;;
        *) protocol="protocol_$proto_num" ;;
    esac
    
    # Determine action and reason from prefix
    local action="unknown"
    local reason="unknown"
    
    if [[ "$prefix" == *"FIREWALL_BLOCK"* ]]; then
        action="block"
        
        # Check the original ulogd_line for more context
        if echo "$ulogd_line" | grep -q '"tcp\.syn": 1'; then
            if echo "$ulogd_line" | grep -q '"dest_port": 22'; then
                reason="ssh_blocked"
            else
                reason="firewall_blocked"
            fi
        elif echo "$ulogd_line" | grep -q '"icmp\.type": 8'; then
            reason="icmp_blocked"
        else
            reason="firewall_blocked"
        fi
        
    elif [[ "$prefix" == *"FIREWALL_RATELIMIT"* ]]; then
        action="rate_limit"
        
        if [[ "$dst_port" == "80" ]]; then
            reason="http_flood_detected"
        elif [[ "$proto_num" == "1" ]]; then
            reason="icmp_flood_detected"
        else
            reason="rate_limit_exceeded"
        fi
        
    elif [[ "$prefix" == *"FIREWALL_PASS"* ]]; then
        action="pass"
        
        if [[ "$dst_port" == "80" ]]; then
            reason="http_allowed"
        else
            reason="firewall_allowed"
        fi
    fi
    
    # Build JSON output for Filebeat
    cat <<EOF
{"@timestamp":"$timestamp","action":"$action","protocol":"$protocol","src_ip":"$src_ip","dst_ip":"$dst_ip","src_port":$src_port,"dst_port":$dst_port,"reason":"$reason","log_type":"firewall","log_source":"iptables","component":"firewall","security_layer":"network_filter","raw_prefix":"$prefix"}
EOF
}

# Initialize tracking for last read position
LAST_POS=0
EVENTS_COUNT=0

echo "=========================================="
echo "   Monitoring Started"
echo "=========================================="
echo "[Monitor] Watching: $ULOGD_JSON"
echo "[Monitor] Output: $LOG_FILE"
echo "[Monitor] Press Ctrl+C to stop"
echo ""

# Main monitoring loop
while true; do
    # Check if ulogd is still running
    if ! kill -0 $ULOGD_PID 2>/dev/null; then
        echo "[Monitor] ✗ WARNING: ulogd2 died, restarting..."
        ulogd 2>&1 &
        ULOGD_PID=$!
        sleep 5
    fi
    
    # Check if ulogd JSON file exists
    if [ -f "$ULOGD_JSON" ]; then
        # Get current file size
        CURRENT_SIZE=$(stat -c%s "$ULOGD_JSON" 2>/dev/null || echo "0")
        
        # If file grew, read new lines
        if [ "$CURRENT_SIZE" -gt "$LAST_POS" ]; then
            # Read only new bytes from last position
            tail -c +$((LAST_POS + 1)) "$ULOGD_JSON" 2>/dev/null | while IFS= read -r line; do
                # Skip empty lines
                if [ -z "$line" ]; then
                    continue
                fi
                
                # Check if line is valid JSON (starts with {)
                if [[ "$line" == "{"* ]]; then
                    # Convert to firewall log format
                    converted=$(convert_to_firewall_log "$line")
                    
                    # Write to log file
                    echo "$converted" >> "$LOG_FILE"
                    
                    # Display to console
                    EVENTS_COUNT=$((EVENTS_COUNT + 1))
                    echo "[$(date +%H:%M:%S)] Event #$EVENTS_COUNT: $converted"
                fi
            done
            
            # Update last position
            LAST_POS=$CURRENT_SIZE
        fi
    else
        # Wait for ulogd to create the file
        if [ $((EVENTS_COUNT % 10)) -eq 0 ]; then
            echo "[Monitor] Waiting for ulogd to create $ULOGD_JSON..."
        fi
    fi
    
    # Sleep briefly before next check
    sleep 1
done