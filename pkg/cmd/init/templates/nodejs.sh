#!/bin/bash
# Install Node.js 22.x LTS via NodeSource
set -e

curl -fsSL https://deb.nodesource.com/setup_22.x | bash -

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y nodejs
elif command -v dnf &>/dev/null; then
    dnf install -y nodejs
fi
