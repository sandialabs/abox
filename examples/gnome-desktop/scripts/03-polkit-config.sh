#!/bin/bash
# Configure polkit for colord (prevents authentication dialogs)
set -e

if [ -d /etc/polkit-1/rules.d ]; then
    # Modern polkit (AL9+, Ubuntu 24.04+, Debian 12+): JavaScript rules
    cat > /etc/polkit-1/rules.d/45-allow-colord.rules << 'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.color-manager.") == 0 &&
        subject.active) {
        return polkit.Result.YES;
    }
});
EOF
else
    # Legacy polkit (AL8, older distros): .pkla format
    mkdir -p /etc/polkit-1/localauthority/50-local.d
    cat > /etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla << 'EOF'
[Allow Colord all Users]
Identity=unix-user:*
Action=org.freedesktop.color-manager.create-device;org.freedesktop.color-manager.create-profile;org.freedesktop.color-manager.delete-device;org.freedesktop.color-manager.delete-profile;org.freedesktop.color-manager.modify-device;org.freedesktop.color-manager.modify-profile
ResultAny=no
ResultInactive=no
ResultActive=yes
EOF
fi
