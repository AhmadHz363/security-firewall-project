#!/bin/bash
################################################################################
# Container Firewall Rules with Comprehensive Logging
# This script runs INSIDE the target_web container
################################################################################

set -e

echo "[Firewall] Initializing iptables rules..."

# Ensure log directory exists
mkdir -p /logs
touch /logs/firewall.log
chmod 666 /logs/firewall.log

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies (we'll implement deny via explicit rules)
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Zero all counters
iptables -Z

################################################################################
# Create custom chains for logging
################################################################################
iptables -N LOG_DROP
iptables -N LOG_ACCEPT
iptables -N LOG_RATELIMIT

################################################################################
# Basic Security - Allow loopback and established connections
################################################################################
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

################################################################################
# Malformed Packet Detection
################################################################################
# Invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG_DROP

# New connections without SYN flag
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j LOG_DROP

# TCP NULL scan (no flags set)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m comment --comment "FIREWALL_TCP_NULL" -j LOG_DROP

# TCP XMAS scan (FIN, PSH, URG flags)
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m comment --comment "FIREWALL_TCP_XMAS" -j LOG_DROP

# TCP FIN scan
iptables -A INPUT -p tcp --tcp-flags ALL FIN -m comment --comment "FIREWALL_TCP_FIN" -j LOG_DROP

################################################################################
# SSH Protection (Block all SSH - simulate SSH server protection)
################################################################################
iptables -A INPUT -p tcp --dport 22 -m comment --comment "FIREWALL_SSH_BLOCK" -j LOG_DROP

################################################################################
# HTTP (Port 80) DoS Protection with Rate Limiting
################################################################################
# Create tracking for HTTP connections
iptables -A INPUT -p tcp --dport 80 --syn -m recent --name HTTP_CONN --set

# Rate limit: Max 30 new connections per 5 seconds per IP
iptables -A INPUT -p tcp --dport 80 --syn \
    -m recent --name HTTP_CONN --update --seconds 5 --hitcount 30 \
    -m comment --comment "FIREWALL_HTTP_FLOOD" \
    -j LOG_RATELIMIT

# Allow normal HTTP traffic
iptables -A INPUT -p tcp --dport 80 -m comment --comment "FIREWALL_HTTP_ALLOW" -j LOG_ACCEPT

################################################################################
# ICMP Flood Protection
################################################################################
# Track ICMP echo requests
iptables -A INPUT -p icmp --icmp-type echo-request -m recent --name ICMP_FLOOD --set

# Rate limit: Max 20 pings per 3 seconds
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m recent --name ICMP_FLOOD --update --seconds 3 --hitcount 20 \
    -m comment --comment "FIREWALL_ICMP_FLOOD" \
    -j LOG_RATELIMIT

# Allow normal ICMP
iptables -A INPUT -p icmp --icmp-type echo-request -j LOG_ACCEPT

################################################################################
# Block specific attacker IP (demonstration)
################################################################################
ATTACKER_IP="172.25.0.4"
iptables -A INPUT -s $ATTACKER_IP -p icmp --icmp-type echo-request \
    -m comment --comment "FIREWALL_BLOCK_ATTACKER_ICMP" \
    -j LOG_DROP

# Block attacker SSH attempts
iptables -A INPUT -s $ATTACKER_IP -p tcp --dport 22 \
    -m comment --comment "FIREWALL_BLOCK_ATTACKER_SSH" \
    -j LOG_DROP

################################################################################
# Port Scan Detection (high connection attempt rate to different ports)
################################################################################
# This is handled by tracking in the monitoring script

################################################################################
# Default Deny (log all other traffic)
################################################################################
iptables -A INPUT -m comment --comment "FIREWALL_DEFAULT_DROP" -j LOG_DROP

################################################################################
# Logging Chains Implementation
################################################################################

# LOG_DROP chain - Log and drop
iptables -A LOG_DROP -j LOG --log-prefix "[FIREWALL_BLOCK] " --log-level 4 --log-tcp-options --log-ip-options
iptables -A LOG_DROP -j DROP

# LOG_ACCEPT chain - Log and accept
iptables -A LOG_ACCEPT -j LOG --log-prefix "[FIREWALL_PASS] " --log-level 4 --log-tcp-options --log-ip-options
iptables -A LOG_ACCEPT -j ACCEPT

# LOG_RATELIMIT chain - Log rate limiting and drop
iptables -A LOG_RATELIMIT -j LOG --log-prefix "[FIREWALL_RATELIMIT] " --log-level 4 --log-tcp-options --log-ip-options
iptables -A LOG_RATELIMIT -j DROP

################################################################################
# Display final rules
################################################################################
echo "[Firewall] Rules applied successfully!"
echo ""
echo "=== INPUT Chain Rules ==="
iptables -L INPUT -n -v --line-numbers
echo ""
echo "=== Custom Chains ==="
iptables -L LOG_DROP -n -v --line-numbers
iptables -L LOG_ACCEPT -n -v --line-numbers
iptables -L LOG_RATELIMIT -n -v --line-numbers
echo ""
echo "[Firewall] Firewall is now active and monitoring traffic"