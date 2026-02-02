#!/bin/bash
################################################################################
# Container Entrypoint
# Sets up firewall, starts monitoring, and launches nginx
################################################################################

set -e

echo "=========================================="
echo "  Target Web Server Initialization"
echo "=========================================="
echo ""

# Wait for logs directory to be mounted
MAX_WAIT=30
WAIT_COUNT=0
while [ ! -d "/logs" ] && [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    echo "Waiting for /logs directory to be mounted..."
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [ ! -d "/logs" ]; then
    echo "ERROR: /logs directory not mounted after ${MAX_WAIT} seconds"
    exit 1
fi

echo "[Entrypoint] Logs directory is ready"

# Apply firewall rules
echo "[Entrypoint] Applying firewall rules..."
/scripts/container_firewall.sh

# Start firewall monitor in background
echo "[Entrypoint] Starting firewall monitor..."
/scripts/firewall_monitor.sh &
MONITOR_PID=$!
echo "[Entrypoint] Firewall monitor started (PID: $MONITOR_PID)"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "[Entrypoint] Shutting down..."
    if [ -n "$MONITOR_PID" ]; then
        kill $MONITOR_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT

echo "[Entrypoint] Starting nginx..."
echo ""
echo "=========================================="
echo "  System Ready"
echo "=========================================="
echo "  Web Server: http://localhost:8080"
echo "  Firewall: Active"
echo "  Monitoring: Active"
echo "=========================================="
echo ""

# Start nginx in foreground
exec "$@"
