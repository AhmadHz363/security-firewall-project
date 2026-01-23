#!/bin/bash

# Working macOS Firewall Logger with proper JSON output
# This version ensures valid JSON format

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_DIR/docker/logs/pf.log"
RULES_FILE="$SCRIPT_DIR/firewall_rules.conf"

echo "=========================================="
echo "  macOS Firewall Logger"
echo "=========================================="
echo "Log file: $LOG_FILE"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run with sudo"
    exit 1
fi

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
> "$LOG_FILE"

# Create pflog0 if needed
if ! ifconfig pflog0 &>/dev/null; then
    echo "[*] Creating pflog0 interface..."
    ifconfig pflog0 create
fi

# Enable pf
echo "[*] Enabling packet filter..."
pfctl -e 2>/dev/null || true

# Load rules if available
if [ -f "$RULES_FILE" ]; then
    echo "[*] Loading firewall rules..."
    pfctl -f "$RULES_FILE"
else
    echo "[*] No rules file, using default pass-all"
    echo "pass log all" | pfctl -f -
fi

echo "[*] Starting packet capture..."
echo "[*] Press CTRL+C to stop"
echo ""
echo "Firewall Events:"
echo "----------------------------------------"

# Cleanup function
cleanup() {
    echo ""
    echo "[*] Stopping..."
    pkill -P $$
    exit 0
}
trap cleanup SIGINT SIGTERM

# Start tcpdump and process output
sudo tcpdump -i pflog0 -l -n -e 2>/dev/null | while IFS= read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue
    
    # Get current timestamp in ISO 8601 format
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Determine action
    action="pass"
    if echo "$line" | grep -q "block"; then
        action="block"
    fi
    
    # Determine protocol
    protocol="unknown"
    if echo "$line" | grep -qi "icmp"; then
        protocol="icmp"
    elif echo "$line" | grep -qi " tcp "; then
        protocol="tcp"
    elif echo "$line" | grep -qi " udp "; then
        protocol="udp"
    fi
    
    # Extract IPs - look for patterns like "10.0.0.1 > 8.8.8.8"
    src_ip=$(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -1)
    dst_ip=$(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | tail -1)
    
    # Use defaults if extraction failed
    src_ip=${src_ip:-"0.0.0.0"}
    dst_ip=${dst_ip:-"0.0.0.0"}
    
    # Escape the message for JSON (replace quotes and backslashes)
    message=$(echo "$line" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
    
    # Create valid JSON - one line, properly formatted
    json='{"@timestamp":"'$timestamp'","action":"'$action'","protocol":"'$protocol'","src_ip":"'$src_ip'","dst_ip":"'$dst_ip'","log_type":"pf","message":"'$message'"}'
    
    # Write to log file
    echo "$json" >> "$LOG_FILE"
    
    # Display to console
    printf "[%s] %s | %s | %s -> %s\n" "$(date +%H:%M:%S)" "$action" "$protocol" "$src_ip" "$dst_ip"
done

wait