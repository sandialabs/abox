#!/bin/bash
# Install system packages
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    docker.io \
    docker-compose \
    git \
    gh \
    unzip \
    python3-venv \
    python3-pip \
    python-is-python3 \
    build-essential \
    pkg-config \
    cmake \
    ripgrep \
    fd-find \
    jq \
    curl \
    wget \
    tmux \
    openjdk-21-jdk \
    nodejs \
    bubblewrap \
    socat

# Configure docker for HTTP proxy
abox-proxy-setup
