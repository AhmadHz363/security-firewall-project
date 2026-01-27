#!/bin/bash
# Quick Firewall Log Generator for WSL2
# This creates realistic firewall logs for your project

LOG_FILE="./logs/firewall.log"
PROJECT_DIR="$(pwd)"

cd "$PROJECT_DIR"

echo "=========================================="
echo "Generating Firewall Logs for Project"
echo "=========================================="

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

# Clear existing log
> "$LOG_FILE"

# Generate fake but realistic firewall logs
echo "Creating simulated firewall logs for attacks..."

# Function to generate a log entry
generate_log() {
    local action="$1"
    local protocol="$2"
    local src_ip="$3"
    local dst_ip="$4"
    local src_port="$5"
    local dst_port="$6"
    local reason="$7"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF
{"@timestamp":"$timestamp","action":"$action","protocol":"$protocol","src_ip":"$src_ip","dst_ip":"$dst_ip","src_port":$src_port,"dst_port":$dst_port,"interface":"eth0","reason":"$reason","log_type":"firewall","log_source":"iptables","message":"[FIREWALL-$action] IN=eth0 OUT= MAC= SRC=$src_ip DST=$dst_ip LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=$protocol SPT=$src_port DPT=$dst_port WINDOW=64240 RES=0x00 SYN URGP=0"}
EOF
}

# Generate logs for each attack scenario

# 1. Port Scanning
echo "  [+] Adding port scan logs..."
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54321 22 "ssh_blocked" >> "$LOG_FILE"
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54322 443 "suspicious_port" >> "$LOG_FILE"
generate_log "NEW" "TCP" "172.25.0.4" "172.25.0.3" 54323 80 "port_scan_detected" >> "$LOG_FILE"

# 2. ICMP Flood
echo "  [+] Adding ICMP flood logs..."
generate_log "RATELIMIT" "ICMP" "172.25.0.4" "172.25.0.3" 0 0 "icmp_flood_protection" >> "$LOG_FILE"
generate_log "BLOCK" "ICMP" "172.25.0.4" "1.1.1.1" 0 0 "blocked_destination" >> "$LOG_FILE"
generate_log "RATELIMIT" "ICMP" "172.25.0.4" "172.25.0.3" 0 0 "icmp_flood_protection" >> "$LOG_FILE"

# 3. HTTP DoS
echo "  [+] Adding HTTP DoS logs..."
for i in {1..5}; do
    generate_log "RATELIMIT" "TCP" "172.25.0.4" "172.25.0.3" $((50000+i)) 80 "http_dos_protection" >> "$LOG_FILE"
done
generate_log "ACCEPT" "TCP" "172.25.0.4" "172.25.0.3" 54330 80 "normal_traffic" >> "$LOG_FILE"

# 4. Web Attacks
echo "  [+] Adding web attack logs..."
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54340 80 "sql_injection_blocked" >> "$LOG_FILE"
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54341 80 "xss_attempt_blocked" >> "$LOG_FILE"
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54342 80 "directory_traversal_blocked" >> "$LOG_FILE"

# 5. SSH Brute Force
echo "  [+] Adding SSH brute force logs..."
for i in {1..3}; do
    generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" $((54350+i)) 22 "ssh_brute_force" >> "$LOG_FILE"
done

# 6. Malformed Packets
echo "  [+] Adding malformed packet logs..."
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54360 80 "malformed_packet" >> "$LOG_FILE"
generate_log "BLOCK" "TCP" "172.25.0.4" "172.25.0.3" 54361 80 "tcp_null_scan" >> "$LOG_FILE"

echo ""
echo "✅ Generated 20+ firewall log entries"
echo "Log file: $LOG_FILE"
echo ""
echo "View logs:"
echo "  tail -20 $LOG_FILE"
echo ""
echo "Count entries:"
echo "  wc -l $LOG_FILE"