#!/bin/bash
# Install system packages
set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    git \
    gh \
    unzip \
    build-essential \
    pkg-config \
    cmake \
    ripgrep \
    fd-find \
    jq \
    curl \
    wget \
    tmux \
    bubblewrap \
    socat
