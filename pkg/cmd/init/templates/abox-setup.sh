#!/bin/bash
# Abox infrastructure setup: CA certificates and proxy
set -e

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates
elif command -v dnf &>/dev/null; then
    dnf install -y ca-certificates
fi

# Update CA certificates (picks up abox proxy CA)
if command -v update-ca-certificates &>/dev/null; then
    update-ca-certificates
elif command -v update-ca-trust &>/dev/null; then
    update-ca-trust
fi

# Configure apt/docker/snap for HTTP proxy
abox-proxy-setup
