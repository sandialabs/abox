#!/bin/bash
# Set password for ubuntu user and display connection instructions
set -e

# Set password for ubuntu user (for RDP login)
echo "ubuntu:ubuntu" | chpasswd

echo ""
echo "================================================"
echo "GNOME desktop with xrdp installed successfully!"
echo "================================================"
echo ""
echo "After 'abox up' completes, run:"
echo "  abox forward add gnome-desktop 3389:3389"
echo ""
echo "Then connect via RDP to localhost:3389"
echo "  Username: ubuntu"
echo "  Password: ubuntu"
echo ""
