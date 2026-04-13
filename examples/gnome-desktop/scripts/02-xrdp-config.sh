#!/bin/bash
# Configure xrdp to use GNOME session
set -e

cat > /etc/xrdp/startwm.sh << 'EOF'
#!/bin/sh
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR
exec /usr/bin/gnome-session
EOF
chmod +x /etc/xrdp/startwm.sh

# Enable xrdp service
systemctl enable xrdp
