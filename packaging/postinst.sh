#!/bin/sh
set -e

# Create the abox system group if it doesn't exist
if ! getent group abox >/dev/null 2>&1; then
    groupadd --system abox
fi

# Set ownership and setuid permissions on abox-helper.
# Only handles /usr/bin (package install path). Manual installs via
# 'make install-helper' set permissions on /usr/local/bin/abox-helper directly.
if [ -f /usr/bin/abox-helper ]; then
    chown root:abox /usr/bin/abox-helper
    chmod 4750 /usr/bin/abox-helper
fi
