#!/bin/bash
# Install system packages (RHEL/AlmaLinux)
set -e

# Enable EPEL and CRB for additional packages
dnf install -y epel-release
dnf config-manager --set-enabled crb

dnf install -y \
    podman \
    podman-compose \
    git \
    gh \
    unzip \
    python3 \
    python3-pip \
    gcc \
    gcc-c++ \
    make \
    pkg-config \
    cmake \
    ripgrep \
    fd-find \
    jq \
    curl \
    wget \
    tmux \
    java-21-openjdk-devel \
    nodejs \
    bubblewrap \
    socat
