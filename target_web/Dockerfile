FROM nginx:1.25-bookworm

# Install required packages for firewall and logging
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    kmod \
    curl \
    procps \
    conntrack \
    ulogd2 \
    ulogd2-json \
    rsyslog \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /logs /scripts /var/log/ulogd

# Copy scripts
COPY scripts/container_firewall.sh /scripts/container_firewall.sh
COPY scripts/firewall_monitor.sh /scripts/firewall_monitor.sh
COPY scripts/entrypoint.sh /entrypoint.sh

# Make scripts executable
RUN chmod +x /scripts/*.sh /entrypoint.sh

# Entrypoint will set up firewall and start monitoring
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
