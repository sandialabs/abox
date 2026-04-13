#!/bin/bash
# Install Claude Code native installer (as $ABOX_USER)
set -e

su - "$ABOX_USER" -c 'curl -fsSL https://claude.ai/install.sh | bash'
