#!/bin/bash
# Install Python tools (pip, venv)
set -e

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3-venv python3-pip python-is-python3
elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-pip
fi
