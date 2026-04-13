#!/bin/bash
# Install minimal GNOME desktop and xrdp
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ubuntu-desktop-minimal xrdp dbus-x11

# Add xrdp user to ssl-cert group for TLS certificate access
usermod -a -G ssl-cert xrdp
