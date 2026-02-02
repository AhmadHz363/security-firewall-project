# Security Firewall Project

> A comprehensive security demonstration platform combining network-level firewall protection with application-layer intrusion detection using Zeek IDS, log shipping with Filebeat, and centralized visualization through Kibana.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://www.docker.com/)
[![Zeek](https://img.shields.io/badge/Zeek-IDS-green.svg)](https://zeek.org/)

## 📋 Overview

This project demonstrates a complete security monitoring stack designed to detect and block malicious traffic at both network and application layers. It combines:

- **Network Firewall**: iptables-based packet filtering with rate limiting and protocol blocking
- **Zeek IDS**: Signature-based intrusion detection for SQL injection, XSS, port scans, and directory traversal
- **Log Aggregation**: Filebeat-powered log shipping to Elasticsearch
- **Visualization**: Kibana dashboards for real-time threat monitoring

Perfect for security teams, educational purposes, and proof-of-concept demonstrations.

## 🎯 Features

### Firewall Protection
- ✅ SSH blocking and protocol filtering
- ✅ HTTP rate limiting (DOS prevention)
- ✅ ICMP flood detection
- ✅ TCP/UDP filtering with action logging
- ✅ Real-time JSON formatted logs

### Intrusion Detection (Zeek)
- ✅ SQL injection detection
- ✅ Cross-Site Scripting (XSS) detection
- ✅ Port scan detection
- ✅ Directory traversal detection
- ✅ Connection and HTTP traffic logging

### Monitoring & Analytics
- ✅ Centralized log aggregation via Filebeat
- ✅ Elasticsearch indexing with proper data types
- ✅ Kibana dashboards and discovery
- ✅ Real-time alert visualization
- ✅ Attack pattern analysis

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Attacker Container                   │
│              (Attack Scenario Simulator)                │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│                    Target Web Server                    │
│   ┌──────────────────────────────────────────────────┐  │
│   │     iptables Firewall (firewall_monitor.sh)      │  │
│   └──────────────────┬───────────────────────────────┘  │
│   ┌────────────────┬─────────────────────────────────┐  │
│   │  Port 8080     │  Firewall Logging               │  │
│   │  (HTTP)        │  (ulogd → firewall.log)         │  │
│   └────────────────┴─────────────────────────────────┘  │
└────────────────┬─────────────────────────────────────────┘
                 │
         ┌───────┴──────────┐
         │                  │
         ▼                  ▼
    ┌─────────────┐   ┌──────────────┐
    │  Zeek IDS   │   │  Filebeat    │
    │  (notice.   │   │  (log        │
    │   log)      │   │   shipper)   │
    └──────┬──────┘   └──────┬───────┘
           │                 │
           └────────┬────────┘
                    ▼
            ┌──────────────────┐
            │  Elasticsearch   │
            │  (Data indexing) │
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │     Kibana       │
            │  (Visualization) │
            │ (Port 5601)      │
            └──────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- macOS, Linux, or WSL on Windows
- 4GB+ RAM available
- Port availability: 8080 (web), 9200 (Elasticsearch), 5601 (Kibana)

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd security-firewall-project
```

2. **Run initial setup**
```bash
./setup.sh --fresh
```

3. **Verify containers are running**
```bash
./check_status.sh
```

4. **Access the services**
- Web Server: `http://localhost:8080`
- Elasticsearch: `http://localhost:9200`
- Kibana: `http://localhost:5601`

## 📝 Usage

### Running Attack Scenarios

```bash
# Interactive menu to select specific attacks
./scripts/attack_scenarios.sh

# Run all attack scenarios sequentially
./scripts/attack_scenarios.sh --all
```

### Available Attack Scenarios

| # | Attack Type | Detection |
|---|---|---|
| 1 | SSH Brute Force | Firewall Block |
| 2 | HTTP Rate Limiting | Firewall Rate Limit |
| 3 | ICMP Flood | Firewall Block |
| 6 | Port Scan | Zeek Alert |
| 7 | SQL Injection | Zeek Alert |
| 8 | XSS Attempt | Zeek Alert |
| 9 | Directory Traversal | Zeek Alert |
| 10 | SSH Connection | Firewall Block |

### Viewing Logs

**Real-time firewall logs:**
```bash
tail -f logs/firewall.log | jq .
```

**Real-time Zeek alerts:**
```bash
tail -f logs/zeek/notice.log | jq .
```

**Filter by action:**
```bash
grep "block" logs/firewall.log | jq .
grep "rate_limit" logs/firewall.log | jq .
```

### Kibana Exploration

1. Open `http://localhost:5601`
2. Navigate to **Discover**
3. Select index: `firewall-*` or `zeek-*`
4. Set time range: **Last 1 hour**
5. Add fields for analysis:
   - **Firewall**: `action`, `src_ip`, `dst_port`, `reason`
   - **Zeek**: `note`, `src`, `msg`, `dst`

## 📊 Log Formats

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

## 🔧 Configuration

### Firewall Rules
Edit `target_web/scripts/container_firewall.sh` to customize:
- Blocked ports and protocols
- Rate limiting thresholds
- Whitelisted IPs

### Zeek Signatures
Edit `zeek/local.zeek` to add custom detection rules:
- Application layer patterns
- Protocol violations
- Anomalous behavior

### Filebeat Pipeline
Edit `filebeat/filebeat.yml` to configure:
- Log input paths
- Parsing rules
- Output destinations

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Containers not starting | Run `docker compose down -v && ./setup.sh --fresh` |
| No Zeek alerts | Wait 5 seconds after attack, verify `logs/zeek/notice.log` |
| Firewall rules not applied | Restart container: `docker compose restart target_web` |
| Kibana shows no data | Restart Filebeat: `docker compose restart filebeat` |
| Port conflicts | Run `docker compose down -v` before setup |

## 📚 Project Structure

```
security-firewall-project/
├── README.md                 # This file
├── docker-compose.yml        # Service orchestration
├── setup.sh                  # Initial setup script
├── check_status.sh          # System health check
├── filebeat/
│   └── filebeat.yml         # Log shipper configuration
├── scripts/
│   ├── attack_scenarios.sh  # Attack simulator
│   ├── setup_elasticsearch.sh
│   └── firewall_logger.sh
├── target_web/              # Target application container
│   ├── Dockerfile
│   └── scripts/
│       ├── container_firewall.sh
│       ├── entrypoint.sh
│       └── firewall_monitor.sh
├── zeek/                     # IDS configuration
│   └── local.zeek
└── target/
    └── html/
        └── index.html        # Sample web application
```

## 🔐 Security Considerations

This is a **demonstration project** designed for:
- ✅ Educational purposes
- ✅ Security team training
- ✅ Proof-of-concept testing
- ✅ Lab environments

**Not recommended for:**
- ❌ Production use without hardening
- ❌ Public exposure without additional security layers
- ❌ Handling sensitive data

For production deployment:
1. Add HTTPS/TLS termination
2. Implement distributed architecture
3. Enable authentication on Kibana
4. Configure network isolation
5. Add backup and failover mechanisms
6. Implement custom detection rules

## 📖 Documentation

- [Zeek Documentation](https://docs.zeek.org/)
- [Elasticsearch Guide](https://www.elastic.co/guide/index.html)
- [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)

## 🤝 Contributing

Contributions are welcome! Areas for enhancement:
- Additional attack scenarios
- Custom Zeek signatures
- Kibana dashboard templates
- Performance optimizations
- Documentation improvements

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💼 Author

Ahmad Hijazi

## 🙏 Acknowledgments

- [Zeek IDS](https://zeek.org/) for network analysis framework
- [Elasticsearch](https://www.elastic.co/) for data indexing
- [Kibana](https://www.elastic.co/kibana) for visualization tools
- [Docker](https://www.docker.com/) for containerization

## 📞 Support

For issues, questions, or suggestions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review logs: `./check_status.sh`
3. Restart services: `docker compose restart`
4. Open an issue on GitHub

---

**Last Updated**: February 2026  
**Status**: Active Development  
**Maintenance**: Regular updates and security patches
