#!/bin/bash
# abox-monitor-agent - Stream Tetragon events to virtio-serial
# This script runs as a systemd service and pipes events to the host

set -euo pipefail

VIRTIO_PORT="/dev/virtio-ports/abox.monitor.0"
TETRA_BIN="/usr/local/bin/tetra"
VIRTIO_TIMEOUT=60
TETRAGON_TIMEOUT=120

# Wait for virtio port to be available (timeout after 60s)
counter=0
while [ ! -e "$VIRTIO_PORT" ]; do
    if [ $counter -ge $VIRTIO_TIMEOUT ]; then
        echo "Timeout waiting for virtio port $VIRTIO_PORT" >&2
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

# Stream Tetragon events to virtio-serial
# The -o json flag outputs events as JSON, one per line
# stderr goes to systemd journal automatically since this runs as a service
exec "$TETRA_BIN" getevents -o json > "$VIRTIO_PORT"
