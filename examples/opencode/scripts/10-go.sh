#!/bin/bash
# Install Go (latest release)
set -e

GO_VERSION=$(curl -s 'https://go.dev/VERSION?m=text' | head -1)
curl -Lo go.tar.gz "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz"
tar -C /usr/local -xzf go.tar.gz
rm go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
