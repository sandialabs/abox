#!/bin/bash
# Install Rust via rustup (as $ABOX_USER)
set -e

su - "$ABOX_USER" -c 'curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
