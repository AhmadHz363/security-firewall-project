# Demo Cheat Sheet - Quick Reference

## Before Demo

```bash
# 1. Complete fresh start
docker compose down -v
rm -f logs/firewall.log
rm -rf logs/zeek/*
./setup.sh --fresh

docker ps
curl http://localhost:8080
curl http://localhost:9200
curl http://localhost:5601/api/status
```

---

## Demo Commands (Copy-Paste Ready)

### Firewall Tests

```bash
# Test 1: SSH Block
./scripts/attack_scenarios.sh
# Select: 10
tail -10 logs/firewall.log | jq .

tail -f logs/firewall.log | jq .

tail -f logs/zeek/notice.log | jq .

# Test 2: HTTP Rate Limit  
./scripts/attack_scenarios.sh
# Select: 2
grep "rate_limit" logs/firewall.log | tail -5 | jq .

# Test 3: ICMP Flood
./scripts/attack_scenarios.sh
# Select: 3
grep "icmp_flood" logs/firewall.log | tail -5 | jq .
```

### Zeek IDS Tests

```bash
# Test 1: SQL Injection
./scripts/attack_scenarios.sh
# Select: 7
sleep 3
grep "SQL_Injection" logs/zeek/notice.log | jq .

# Test 2: XSS
./scripts/attack_scenarios.sh
# Select: 8
sleep 3
grep "XSS_Attempt" logs/zeek/notice.log | jq .

# Test 3: Port Scan
./scripts/attack_scenarios.sh
# Select: 6
sleep 5
grep "Port_Scan" logs/zeek/notice.log | jq .

# Test 4: Directory Traversal
./scripts/attack_scenarios.sh
# Select: 9
sleep 3
grep "Directory_Traversal" logs/zeek/notice.log | jq .
```

### Run Everything

```bash
./scripts/attack_scenarios.sh --all
```

### Show Summary

```bash
echo "=== FIREWALL ==="
echo "Total: $(wc -l < logs/firewall.log)"
echo "Blocks: $(grep -c '"action":"block"' logs/firewall.log)"
echo "Rate Limits: $(grep -c '"action":"rate_limit"' logs/firewall.log)"
echo ""
echo "=== ZEEK IDS ==="
echo "Connections: $(wc -l < logs/zeek/conn.log)"
echo "Alerts: $(grep -v 'Zeek_Started' logs/zeek/notice.log | wc -l)"
echo ""
echo "Alert Types:"
grep -o '"note":"[^"]*"' logs/zeek/notice.log | sort | uniq -c | sort -rn
```

---

## Kibana Quick Guide

1. Open: `http://localhost:5601`
2. Menu → **Discover**
3. Select index: **firewall-*** or **zeek-***
4. Time: **Last 1 hour**
5. Add fields:
   - firewall: `action`, `src_ip`, `dst_port`, `reason`
   - zeek: `note`, `src`, `msg`, `sub`

---

## Manual Test (if attack_scenarios.sh fails)

```bash
# SQL Injection
docker exec attacker curl -s "http://172.25.0.3/login?username=admin&password=1' OR '1'='1"
sleep 2
grep "SQL" logs/zeek/notice.log | tail -1 | jq .

# XSS
docker exec attacker curl -s "http://172.25.0.3/search?q=<script>alert(1)</script>"
sleep 2
grep "XSS" logs/zeek/notice.log | tail -1 | jq .

# Port Scan
docker exec attacker nmap -sS -p 1-50 172.25.0.3
sleep 5
grep "Port_Scan" logs/zeek/notice.log | tail -1 | jq .
```

---

## Emergency Recovery

```bash
# If something breaks
docker compose restart target_web zeek filebeat
sleep 15

# Check status
./check_status.sh

# Restart everything
docker compose down
docker compose up -d
sleep 60
```

---

## Key File Locations

- **Firewall logs**: `logs/firewall.log`
- **Zeek alerts**: `logs/zeek/notice.log`
- **Zeek connections**: `logs/zeek/conn.log`
- **Zeek HTTP**: `logs/zeek/http.log`
- **Attack script**: `./scripts/attack_scenarios.sh`
- **Status check**: `./check_status.sh`

---

## Expected Results

### Firewall Log Example
```json
{
  "@timestamp": "2026-02-01T15:18:32Z",
  "action": "block",
  "protocol": "tcp",
  "src_ip": "172.25.0.4",
  "dst_ip": "172.25.0.3",
  "dst_port": 22,
  "reason": "ssh_blocked"
}
```

### Zeek Alert Example
```json
{
  "ts": 1769962441.033077,
  "note": "SecurityMonitor::SQL_Injection_Attempt",
  "msg": "SQL injection attempt detected from 172.25.0.4",
  "src": "172.25.0.4",
  "dst": "172.25.0.3",
  "sub": "/login?username=admin&password=1' OR '1'='1"
}
```

---

## Common Issues

| Issue | Solution |
|-------|----------|
| No Zeek alerts | Wait 5 seconds after attack, check `logs/zeek/notice.log` |
| No firewall logs | Check `docker exec target_web ps aux \| grep ulogd` |
| Kibana no data | Restart filebeat: `docker compose restart filebeat` |
| Container not running | `docker compose up -d <service>` |
| Port already in use | `docker compose down -v` then retry |

---

## Questions & Answers

**Q: Why use both firewall and IDS?**  
A: Firewall blocks at network layer (ports, IPs). IDS detects application attacks (SQL injection, XSS).

**Q: How does Zeek see blocked traffic?**  
A: Zeek shares network stack with target (network_mode: service), sees traffic before iptables.

**Q: Real-world deployment?**  
A: Add HTTPS support, distributed architecture, tuning, whitelisting, scaling.

---

## Demo Timeline (45 min)

- 00:00 - Introduction & Architecture (5 min)
- 05:00 - Firewall Demo (10 min)
- 15:00 - Zeek IDS Demo (15 min)
- 30:00 - Kibana Visualization (10 min)
- 40:00 - Full Test & Summary (5 min)

---

## Success Checklist

- [ ] All containers running
- [ ] Can access web server (port 8080)
- [ ] Can access Kibana (port 5601)
- [ ] Firewall blocks SSH
- [ ] Firewall rate-limits HTTP
- [ ] Zeek detects SQL injection
- [ ] Zeek detects XSS
- [ ] Zeek detects port scans
- [ ] Logs visible in Kibana
- [ ] Attack scenarios script works