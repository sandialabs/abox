#!/bin/bash
# Install OpenCode (as $ABOX_USER)
set -e

su - "$ABOX_USER" -c 'curl -fsSL "https://opencode.ai/install" | bash'
