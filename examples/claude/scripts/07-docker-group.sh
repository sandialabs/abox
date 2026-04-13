#!/bin/bash
# Add user to docker group
set -e

usermod -aG docker "$ABOX_USER"
