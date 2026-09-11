#!/bin/bash
# abox-monitor-agent - Stream Tetragon events to the host monitor device
# This script runs as a systemd service and pipes events to the host over the
# backend-specific transport device ({{.Device}}: a virtio-serial port on
# libvirt, or a serial pipe on VMware).

set -euo pipefail

MONITOR_DEVICE="{{.Device}}"
TETRA_BIN="/usr/local/bin/tetra"
DEVICE_TIMEOUT=60
TETRAGON_TIMEOUT=120

# Wait for the monitor device to be available (timeout after 60s)
counter=0
while [ ! -e "$MONITOR_DEVICE" ]; do
    if [ $counter -ge $DEVICE_TIMEOUT ]; then
        echo "Timeout waiting for monitor device $MONITOR_DEVICE" >&2
        exit 1
    fi
    sleep 1
    counter=$((counter + 1))
done

# Wait for Tetragon to be ready (timeout after 120s)
# Use 'tetra status' which returns 0 when healthy, not 'getevents --timeout'
# which returns non-zero when timeout expires even if Tetragon is healthy
counter=0
logged_error=false
while ! "$TETRA_BIN" status >/dev/null 2>&1; do
    if [ $counter -ge $TETRAGON_TIMEOUT ]; then
        echo "Timeout waiting for Tetragon to be ready" >&2
        exit 1
    fi
    if [ "$logged_error" = false ]; then
        echo "Waiting for Tetragon (tetra status failed, will retry for ${TETRAGON_TIMEOUT}s)..." >&2
        "$TETRA_BIN" status 2>&1 | head -5 >&2 || true
        logged_error=true
    fi
    sleep 2
    counter=$((counter + 2))
done

# Stream Tetragon events to the monitor device
# The -o json flag outputs events as JSON, one per line
# stderr goes to systemd journal automatically since this runs as a service
exec "$TETRA_BIN" getevents -o json > "$MONITOR_DEVICE"
