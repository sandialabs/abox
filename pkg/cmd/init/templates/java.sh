#!/bin/bash
# Install OpenJDK 21
set -e

if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y openjdk-21-jdk
elif command -v dnf &>/dev/null; then
    dnf install -y java-21-openjdk-devel
fi
