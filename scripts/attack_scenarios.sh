#!/bin/bash
################################################################################
# Attack Simulation Scripts for Security Testing
# CLEARLY SEPARATED: Firewall Attacks vs Zeek IDS Attacks
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "  Security Testing Suite"
echo "  Firewall (iptables) + Zeek IDS"
echo "=========================================="
echo ""

# Configuration
TARGET_IP="172.25.0.3"
TARGET_PORT="80"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[*]${NC} $1"; }
print_attack() { echo -e "${RED}[!]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
print_firewall() { echo -e "${CYAN}[FIREWALL]${NC} $1"; }
print_zeek() { echo -e "${YELLOW}[ZEEK IDS]${NC} $1"; }

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    if ! docker ps | grep -q "target_web"; then
        print_warning "target_web container is not running!"
        exit 1
    fi
    
    if ! docker ps | grep -q "attacker"; then
        print_warning "attacker container is not running!"
        exit 1
    fi
    
    print_info "Installing attack tools..."
    docker exec attacker bash -c "
        command -v curl >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq curl 2>/dev/null)
        command -v ping >/dev/null 2>&1 || apt-get install -y -qq iputils-ping 2>/dev/null
        command -v nc >/dev/null 2>&1 || apt-get install -y -qq netcat-openbsd 2>/dev/null
        command -v nmap >/dev/null 2>&1 || apt-get install -y -qq nmap 2>/dev/null
        command -v ab >/dev/null 2>&1 || apt-get install -y -qq apache2-utils 2>/dev/null
    " > /dev/null 2>&1
    
    print_status "All prerequisites satisfied"
    echo ""
}

################################################################################
# FIREWALL-FOCUSED ATTACKS
# These attacks test iptables rules and generate firewall.log entries
################################################################################

#------------------------------------------------------------
# FIREWALL ATTACK 1: SSH Port Blocking
#------------------------------------------------------------
firewall_attack_1_ssh_block() {
    echo ""
    echo "=========================================="
    print_firewall "ATTACK 1: SSH Port Blocking Test"
    echo "=========================================="
    print_info "Target: iptables firewall rules"
    print_info "Expected: SSH connections blocked by firewall"
    print_info "Logs: logs/firewall.log (action: 'block', dst_port: 22)"
    echo ""
    
    print_attack "Attempting 20 SSH connections to port 22..."
    docker exec attacker bash -c "
        for i in {1..20}; do
            timeout 1 nc -w 1 $TARGET_IP 22 2>/dev/null &
        done
        wait
        echo 'SSH connection attempts completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'dst_port.*22' logs/firewall.log | tail -5"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# FIREWALL ATTACK 2: HTTP Rate Limiting (DoS)
#------------------------------------------------------------
firewall_attack_2_http_flood() {
    echo ""
    echo "=========================================="
    print_firewall "ATTACK 2: HTTP Flood / Rate Limiting"
    echo "=========================================="
    print_info "Target: iptables HTTP rate limit rules"
    print_info "Expected: Excess connections rate-limited after 30/5sec threshold"
    print_info "Logs: logs/firewall.log (action: 'rate_limit', reason: 'http_flood_detected')"
    echo ""
    
    print_attack "Sending 100 rapid HTTP requests to trigger rate limit..."
    docker exec attacker bash -c "
        for i in {1..100}; do
            curl -s http://$TARGET_IP/ > /dev/null &
        done
        wait
        echo 'HTTP flood completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'rate_limit' logs/firewall.log | tail -5"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# FIREWALL ATTACK 3: ICMP Flood
#------------------------------------------------------------
firewall_attack_3_icmp_flood() {
    echo ""
    echo "=========================================="
    print_firewall "ATTACK 3: ICMP Flood (Ping Flood)"
    echo "=========================================="
    print_info "Target: iptables ICMP rate limit rules"
    print_info "Expected: Excess pings rate-limited after 20/3sec threshold"
    print_info "Logs: logs/firewall.log (action: 'rate_limit', reason: 'icmp_flood_detected')"
    echo ""
    
    print_attack "Sending 50 rapid ICMP packets..."
    docker exec attacker bash -c "
        ping -c 50 -i 0.05 $TARGET_IP 2>/dev/null | tail -3
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'icmp_flood' logs/firewall.log | tail -5"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# FIREWALL ATTACK 4: Blocked Attacker IP
#------------------------------------------------------------
firewall_attack_4_blocked_ip() {
    echo ""
    echo "=========================================="
    print_firewall "ATTACK 4: Blocked Attacker IP Test"
    echo "=========================================="
    print_info "Target: iptables IP-based blocking rules"
    print_info "Expected: Attacker IP (172.25.0.4) is blocked for certain traffic"
    print_info "Logs: logs/firewall.log (reason: 'attacker_ip_blocked')"
    echo ""
    
    print_attack "Testing blocked IP restrictions..."
    docker exec attacker bash -c "
        echo 'Attempting ICMP from blocked IP...'
        ping -c 5 $TARGET_IP 2>/dev/null | tail -2
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'attacker_ip_blocked' logs/firewall.log | tail -3"
    echo ""
    sleep 2
}

################################################################################
# ZEEK IDS-FOCUSED ATTACKS
# These attacks test Zeek detection rules and generate notice.log alerts
################################################################################

#------------------------------------------------------------
# ZEEK ATTACK 1: Port Scanning Detection
#------------------------------------------------------------
zeek_attack_1_port_scan() {
    echo ""
    echo "=========================================="
    print_zeek "ATTACK 1: Port Scanning Detection"
    echo "=========================================="
    print_info "Target: Zeek port scan detection module"
    print_info "Expected: Zeek detects scanning of 10+ ports"
    print_info "Logs: logs/zeek/notice.log (note: 'Port_Scan_Detected')"
    echo ""
    
    print_attack "Launching Nmap port scan on ports 1-100..."
    docker exec attacker bash -c "
        nmap -sS -p 1-100 --max-retries 1 -T4 $TARGET_IP 2>/dev/null | head -15
    " 2>/dev/null
    
    sleep 3
    print_status "Attack completed"
    print_info "Verify: grep 'Port_Scan_Detected' logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# ZEEK ATTACK 2: SQL Injection Detection
#------------------------------------------------------------
zeek_attack_2_sql_injection() {
    echo ""
    echo "=========================================="
    print_zeek "ATTACK 2: SQL Injection Detection"
    echo "=========================================="
    print_info "Target: Zeek HTTP analysis (SQL injection patterns)"
    print_info "Expected: Zeek detects SQL injection in HTTP parameters"
    print_info "Logs: logs/zeek/notice.log (note: 'SQL_Injection_Attempt')"
    echo ""
    
    print_attack "Sending SQL injection payloads..."
    docker exec attacker bash -c "
        curl -s \"http://$TARGET_IP/login?username=admin&password=1' OR '1'='1\" > /dev/null
        curl -s \"http://$TARGET_IP/search?q=1' UNION SELECT NULL,NULL,NULL--\" > /dev/null
        curl -s \"http://$TARGET_IP/api/users?id=1' OR 1=1--\" > /dev/null
        echo 'SQL injection attempts completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'SQL_Injection' logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# ZEEK ATTACK 3: XSS (Cross-Site Scripting) Detection
#------------------------------------------------------------
zeek_attack_3_xss() {
    echo ""
    echo "=========================================="
    print_zeek "ATTACK 3: XSS Detection"
    echo "=========================================="
    print_info "Target: Zeek HTTP analysis (XSS patterns)"
    print_info "Expected: Zeek detects XSS payloads in HTTP"
    print_info "Logs: logs/zeek/notice.log (note: 'XSS_Attempt')"
    echo ""
    
    print_attack "Sending XSS payloads..."
    docker exec attacker bash -c "
        curl -s \"http://$TARGET_IP/search?q=<script>alert(1)</script>\" > /dev/null
        curl -s \"http://$TARGET_IP/page?name=<img src=x onerror=alert(1)>\" > /dev/null
        curl -s \"http://$TARGET_IP/comment?text=<script>document.cookie</script>\" > /dev/null
        echo 'XSS attempts completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'XSS_Attempt' logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# ZEEK ATTACK 4: Directory Traversal Detection
#------------------------------------------------------------
zeek_attack_4_directory_traversal() {
    echo ""
    echo "=========================================="
    print_zeek "ATTACK 4: Directory Traversal Detection"
    echo "=========================================="
    print_info "Target: Zeek HTTP analysis (path traversal patterns)"
    print_info "Expected: Zeek detects directory traversal attempts"
    print_info "Logs: logs/zeek/notice.log (note: 'Directory_Traversal_Attempt')"
    echo ""
    
    print_attack "Sending directory traversal payloads..."
    docker exec attacker bash -c "
        curl -s \"http://$TARGET_IP/page?file=../../../etc/passwd\" > /dev/null
        curl -s \"http://$TARGET_IP/download?file=../../etc/shadow\" > /dev/null
        curl -s \"http://$TARGET_IP/view?path=....//....//etc/hosts\" > /dev/null
        echo 'Directory traversal attempts completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'Directory_Traversal' logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# ZEEK ATTACK 5: Command Injection Detection
#------------------------------------------------------------
zeek_attack_5_command_injection() {
    echo ""
    echo "=========================================="
    print_zeek "ATTACK 5: Command Injection Detection"
    echo "=========================================="
    print_info "Target: Zeek HTTP analysis (command injection patterns)"
    print_info "Expected: Zeek detects OS command injection attempts"
    print_info "Logs: logs/zeek/notice.log (note: 'Command_Injection_Attempt')"
    echo ""
    
    print_attack "Sending command injection payloads..."
    docker exec attacker bash -c "
        curl -s \"http://$TARGET_IP/search?q=test;ls -la\" > /dev/null
        curl -s \"http://$TARGET_IP/exec?cmd=cat /etc/passwd\" > /dev/null
        curl -s \"http://$TARGET_IP/ping?host=google.com;whoami\" > /dev/null
        curl -s \"http://$TARGET_IP/run?script=test|id\" > /dev/null
        echo 'Command injection attempts completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'Command_Injection' logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# ZEEK ATTACK 6: HTTP Flood Detection
#------------------------------------------------------------
zeek_attack_6_http_flood() {
    echo ""
    echo "=========================================="
    print_zeek "ATTACK 6: HTTP Flood Detection (Zeek)"
    echo "=========================================="
    print_info "Target: Zeek HTTP flood detection (50+ requests/10sec)"
    print_info "Expected: Zeek detects abnormal HTTP request rate"
    print_info "Logs: logs/zeek/notice.log (note: 'HTTP_Flood_Detected')"
    echo ""
    
    print_attack "Sending 80 rapid HTTP requests..."
    docker exec attacker bash -c "
        for i in {1..80}; do
            curl -s http://$TARGET_IP/ > /dev/null &
        done
        wait
        echo 'HTTP flood completed'
    " 2>/dev/null
    
    sleep 2
    print_status "Attack completed"
    print_info "Verify: grep 'HTTP_Flood' logs/zeek/notice.log"
    echo ""
    sleep 2
}

################################################################################
# RUN ALL ATTACKS
################################################################################

run_all_firewall_attacks() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║  FIREWALL ATTACK SCENARIOS             ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    firewall_attack_1_ssh_block
    firewall_attack_2_http_flood
    firewall_attack_3_icmp_flood
    firewall_attack_4_blocked_ip
    
    echo ""
    echo "=========================================="
    print_firewall "FIREWALL ATTACKS COMPLETED"
    echo "=========================================="
    print_info "View results: tail -20 logs/firewall.log"
    print_info "Block count: grep 'block' logs/firewall.log | wc -l"
    print_info "Rate limits: grep 'rate_limit' logs/firewall.log | wc -l"
    echo ""
}

run_all_zeek_attacks() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║  ZEEK IDS ATTACK SCENARIOS             ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    zeek_attack_1_port_scan
    zeek_attack_2_sql_injection
    zeek_attack_3_xss
    zeek_attack_4_directory_traversal
    zeek_attack_5_command_injection
    zeek_attack_6_http_flood
    
    echo ""
    echo "=========================================="
    print_zeek "ZEEK IDS ATTACKS COMPLETED"
    echo "=========================================="
    print_info "View alerts: grep -v 'Zeek_Started' logs/zeek/notice.log"
    print_info "Alert count: grep -v 'Zeek_Started' logs/zeek/notice.log | wc -l"
    print_info "Connections: wc -l logs/zeek/conn.log"
    echo ""
}

run_all_attacks() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║  COMPREHENSIVE SECURITY TEST           ║"
    echo "║  Firewall + Zeek IDS                   ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    read -p "Press ENTER to start all attacks or Ctrl+C to cancel..."
    
    START_TIME=$(date +%s)
    
    run_all_firewall_attacks
    sleep 3
    run_all_zeek_attacks
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    echo ""
    echo "=========================================="
    echo "  ALL ATTACKS COMPLETED"
    echo "=========================================="
    print_status "Total execution time: ${DURATION} seconds"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "SUMMARY:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    print_firewall "Firewall Results:"
    echo "  Total logs: $(wc -l < logs/firewall.log) lines"
    echo "  Blocks: $(grep -c 'block' logs/firewall.log 2>/dev/null || echo 0)"
    echo "  Rate limits: $(grep -c 'rate_limit' logs/firewall.log 2>/dev/null || echo 0)"
    echo ""
    print_zeek "Zeek IDS Results:"
    echo "  Total connections: $(wc -l < logs/zeek/conn.log) connections"
    echo "  Alerts: $(grep -v 'Zeek_Started' logs/zeek/notice.log 2>/dev/null | wc -l) alerts"
    echo ""
    echo "View detailed status: ./check_status.sh"
    echo ""
}

################################################################################
# MENU SYSTEM
################################################################################

show_menu() {
    clear
    echo "╔════════════════════════════════════════╗"
    echo "║  Security Testing Menu                 ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    echo "FIREWALL ATTACKS (iptables):"
    echo "  1) SSH Port Blocking Test"
    echo "  2) HTTP Rate Limiting / DoS"
    echo "  3) ICMP Flood"
    echo "  4) Blocked IP Test"
    echo "  5) → Run ALL Firewall Attacks"
    echo ""
    echo "ZEEK IDS ATTACKS:"
    echo "  6) Port Scan Detection"
    echo "  7) SQL Injection Detection"
    echo "  8) XSS Detection"
    echo "  9) Directory Traversal Detection"
    echo " 10) Command Injection Detection"
    echo " 11) HTTP Flood Detection (Zeek)"
    echo " 12) → Run ALL Zeek Attacks"
    echo ""
    echo " 99) ★ RUN ALL ATTACKS (Firewall + Zeek)"
    echo ""
    echo "  0) Exit"
    echo ""
    echo "=========================================="
    read -p "Enter your choice: " choice
    echo ""
    
    case $choice in
        1) firewall_attack_1_ssh_block; pause ;;
        2) firewall_attack_2_http_flood; pause ;;
        3) firewall_attack_3_icmp_flood; pause ;;
        4) firewall_attack_4_blocked_ip; pause ;;
        5) run_all_firewall_attacks; pause ;;
        6) zeek_attack_1_port_scan; pause ;;
        7) zeek_attack_2_sql_injection; pause ;;
        8) zeek_attack_3_xss; pause ;;
        9) zeek_attack_4_directory_traversal; pause ;;
        10) zeek_attack_5_command_injection; pause ;;
        11) zeek_attack_6_http_flood; pause ;;
        12) run_all_zeek_attacks; pause ;;
        99) run_all_attacks; pause ;;
        0) exit 0 ;;
        *) echo "Invalid choice"; sleep 2; show_menu ;;
    esac
}

pause() {
    echo ""
    read -p "Press ENTER to return to menu..."
    show_menu
}

################################################################################
# MAIN
################################################################################

check_prerequisites

if [ "$1" == "--all" ]; then
    run_all_attacks
    exit 0
elif [ "$1" == "--firewall" ]; then
    run_all_firewall_attacks
    exit 0
elif [ "$1" == "--zeek" ]; then
    run_all_zeek_attacks
    exit 0
fi

show_menu