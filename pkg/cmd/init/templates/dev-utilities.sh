#!/bin/bash
# Install dev utilities: ripgrep, fd, jq, tmux, sqlite3
set -e

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ripgrep fd-find jq tmux sqlite3
elif command -v dnf &>/dev/null; then
    dnf install -y ripgrep fd-find jq tmux sqlite
fi
