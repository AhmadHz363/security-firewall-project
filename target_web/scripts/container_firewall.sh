#!/bin/bash
################################################################################
# Container Firewall Rules with NFLOG Logging
# This script runs INSIDE the target_web container
################################################################################

set -e

echo "=========================================="
echo "   iptables Firewall Configuration"
echo "=========================================="
echo ""

# Ensure log directory exists
mkdir -p /logs
touch /logs/firewall.log
chmod 666 /logs/firewall.log

echo "[Firewall] Clearing existing rules..."

# Clear existing rules
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t nat -X 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -t mangle -X 2>/dev/null || true

# Set default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Zero all counters
iptables -Z 2>/dev/null || true

echo "[Firewall] ✓ Cleared existing rules"

################################################################################
# Create custom chains for logging
################################################################################
echo "[Firewall] Creating logging chains..."

iptables -N LOG_DROP 2>/dev/null || true
iptables -N LOG_ACCEPT 2>/dev/null || true
iptables -N LOG_RATELIMIT 2>/dev/null || true

echo "[Firewall] ✓ Logging chains created"

################################################################################
# Basic Security - Allow loopback and established connections
################################################################################
echo "[Firewall] Configuring basic security rules..."

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[Firewall] ✓ Basic rules configured"

################################################################################
# Malformed Packet Detection
################################################################################
echo "[Firewall] Configuring malformed packet detection..."

# Invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j LOG_DROP

# New connections without SYN flag
iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j LOG_DROP

# TCP NULL scan (no flags set)
iptables -A INPUT -p tcp --tcp-flags ALL NONE \
    -m comment --comment "FIREWALL_TCP_NULL" \
    -j LOG_DROP

# TCP XMAS scan (FIN,PSH,URG flags)
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG \
    -m comment --comment "FIREWALL_TCP_XMAS" \
    -j LOG_DROP

# TCP FIN scan
iptables -A INPUT -p tcp --tcp-flags ALL FIN \
    -m comment --comment "FIREWALL_TCP_FIN" \
    -j LOG_DROP

echo "[Firewall] ✓ Malformed packet rules configured"

################################################################################
# SSH Protection
################################################################################
echo "[Firewall] Configuring SSH protection..."

iptables -A INPUT -p tcp --dport 22 \
    -m comment --comment "FIREWALL_SSH_BLOCK" \
    -j LOG_DROP

echo "[Firewall] ✓ SSH blocked on port 22"

################################################################################
# HTTP DoS Protection with Rate Limiting
################################################################################
echo "[Firewall] Configuring HTTP flood protection..."

# Create tracking for HTTP connections
iptables -A INPUT -p tcp --dport 80 --syn \
    -m recent --name HTTP_CONN --set

# Rate limit: Max 30 new connections per 5 seconds per IP
iptables -A INPUT -p tcp --dport 80 --syn \
    -m recent --name HTTP_CONN --update --seconds 5 --hitcount 30 \
    -m comment --comment "FIREWALL_HTTP_FLOOD" \
    -j LOG_RATELIMIT

# Allow normal HTTP traffic
iptables -A INPUT -p tcp --dport 80 \
    -m comment --comment "FIREWALL_HTTP_ALLOW" \
    -j LOG_ACCEPT

echo "[Firewall] ✓ HTTP rate limiting configured (30 conn/5sec)"

################################################################################
# ICMP Flood Protection
################################################################################
echo "[Firewall] Configuring ICMP flood protection..."

# Track ICMP echo requests
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m recent --name ICMP_FLOOD --set

# Rate limit: Max 20 pings per 3 seconds
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m recent --name ICMP_FLOOD --update --seconds 3 --hitcount 20 \
    -m comment --comment "FIREWALL_ICMP_FLOOD" \
    -j LOG_RATELIMIT

# Allow normal ICMP
iptables -A INPUT -p icmp --icmp-type echo-request -j LOG_ACCEPT

echo "[Firewall] ✓ ICMP rate limiting configured (20 pings/3sec)"

################################################################################
# Block Specific Attacker IP (demonstration)
################################################################################
echo "[Firewall] Configuring attacker IP blocking..."

ATTACKER_IP="172.25.0.4"

# Block attacker ICMP
iptables -A INPUT -s $ATTACKER_IP -p icmp --icmp-type echo-request \
    -m comment --comment "FIREWALL_BLOCK_ATTACKER_ICMP" \
    -j LOG_DROP

# Block attacker SSH
iptables -A INPUT -s $ATTACKER_IP -p tcp --dport 22 \
    -m comment --comment "FIREWALL_BLOCK_ATTACKER_SSH" \
    -j LOG_DROP

echo "[Firewall] ✓ Attacker IP $ATTACKER_IP rules configured"

################################################################################
# Default Deny
################################################################################
echo "[Firewall] Configuring default deny..."

iptables -A INPUT \
    -m comment --comment "FIREWALL_DEFAULT_DROP" \
    -j LOG_DROP

echo "[Firewall] ✓ Default deny configured"

################################################################################
# Logging Chains Implementation - NFLOG VERSION
################################################################################
echo "[Firewall] Configuring NFLOG logging chains..."

# Clear logging chains first
iptables -F LOG_DROP 2>/dev/null || true
iptables -F LOG_ACCEPT 2>/dev/null || true
iptables -F LOG_RATELIMIT 2>/dev/null || true

# LOG_DROP chain - Use NFLOG group 1
iptables -A LOG_DROP \
    -j NFLOG --nflog-group 1 --nflog-prefix "FIREWALL_BLOCK" --nflog-threshold 1

iptables -A LOG_DROP -j DROP

# LOG_ACCEPT chain - Use NFLOG group 1
iptables -A LOG_ACCEPT \
    -j NFLOG --nflog-group 1 --nflog-prefix "FIREWALL_PASS" --nflog-threshold 1

iptables -A LOG_ACCEPT -j ACCEPT

# LOG_RATELIMIT chain - Use NFLOG group 1
iptables -A LOG_RATELIMIT \
    -j NFLOG --nflog-group 1 --nflog-prefix "FIREWALL_RATELIMIT" --nflog-threshold 1

iptables -A LOG_RATELIMIT -j DROP

echo "[Firewall] ✓ NFLOG logging configured (group 1)"

################################################################################
# Display Final Rules
################################################################################
echo ""
echo "=========================================="
echo "   Firewall Rules Summary"
echo "=========================================="
echo ""

echo "=== INPUT Chain Rules ==="
iptables -L INPUT -n -v --line-numbers

echo ""
echo "=== Custom Logging Chains ==="
echo ""
echo "--- LOG_DROP Chain ---"
iptables -L LOG_DROP -n -v --line-numbers

echo ""
echo "--- LOG_ACCEPT Chain ---"
iptables -L LOG_ACCEPT -n -v --line-numbers

echo ""
echo "--- LOG_RATELIMIT Chain ---"
iptables -L LOG_RATELIMIT -n -v --line-numbers

echo ""
echo "=========================================="
echo "   Firewall Configuration Complete"
echo "=========================================="
echo ""
echo "[Firewall] ✓ All rules applied successfully"
echo "[Firewall] ✓ NFLOG logging active on group 1"
echo "[Firewall] ✓ Ready to monitor traffic"
echo ""
