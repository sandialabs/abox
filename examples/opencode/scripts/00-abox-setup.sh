#!/bin/bash
# Abox infrastructure setup: CA certificates and proxy
set -e

export DEBIAN_FRONTEND=noninteractive

# Ensure ca-certificates package is installed
apt-get update
apt-get install -y ca-certificates

# Update CA certificates (picks up abox proxy CA)
update-ca-certificates

# Configure apt (and other services) for HTTP proxy
abox-proxy-setup
