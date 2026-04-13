#!/bin/bash
# Install Docker and docker-compose
set -e

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y docker.io docker-compose
elif command -v dnf &>/dev/null; then
    dnf install -y docker docker-compose
fi

systemctl enable docker

# Add user to docker group
usermod -aG docker "$ABOX_USER"

# Configure docker for HTTP proxy
abox-proxy-setup
