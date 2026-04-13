#!/bin/bash
# Install GitHub CLI (gh)
set -e

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y gh
elif command -v dnf &>/dev/null; then
    dnf install -y gh
fi
