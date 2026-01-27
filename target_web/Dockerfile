FROM nginx:alpine

# Install required packages for firewall and logging
RUN apk add --no-cache \
    iptables \
    iptables-legacy \
    bash \
    coreutils \
    procps \
    iproute2 \
    curl

# Create directories
RUN mkdir -p /logs /scripts

# Copy scripts
COPY scripts/container_firewall.sh /scripts/container_firewall.sh
COPY scripts/firewall_monitor.sh /scripts/firewall_monitor.sh
COPY scripts/entrypoint.sh /entrypoint.sh

# Make scripts executable
RUN chmod +x /scripts/*.sh /entrypoint.sh

# Entrypoint will set up firewall and start monitoring
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]