#!/bin/bash
# Abox infrastructure setup: CA certificates and proxy
set -e

# Ensure ca-certificates package is installed
dnf install -y ca-certificates

# Update CA certificates (picks up abox proxy CA)
update-ca-trust

# Configure dnf (and other services) for HTTP proxy
abox-proxy-setup
