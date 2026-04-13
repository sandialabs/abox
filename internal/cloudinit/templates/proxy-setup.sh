#!/bin/bash
# abox-proxy-setup - Configure proxy for installed services
# Run from provision scripts after installing apt/docker/containerd/snap

set -e

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: abox-proxy-setup"
    echo ""
    echo "Configure HTTP proxy for installed services (apt, docker, containerd, snap)."
{{- if .CACert }}
    echo "Also configures CA certificate for pip, npm, and git."
{{- end }}
    echo "Run this after installing new services that need proxy configuration."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)" >&2
    exit 1
fi

PROXY_URL="http://{{.Gateway}}:{{.HTTPPort}}"
NO_PROXY="localhost,127.0.0.1,{{.Gateway}}"
NEED_DAEMON_RELOAD=false
{{- if .CACert }}
# Find CA cert (works on both Debian and RHEL)
if [[ -f /usr/local/share/ca-certificates/abox-proxy-ca.crt ]]; then
    ABOX_CA_CERT="/usr/local/share/ca-certificates/abox-proxy-ca.crt"
elif [[ -f /etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt ]]; then
    ABOX_CA_CERT="/etc/pki/ca-trust/source/anchors/abox-proxy-ca.crt"
fi
{{- end }}

# APT (Debian/Ubuntu)
if command -v apt &>/dev/null; then
    echo "Configuring APT proxy..."
    cat > /etc/apt/apt.conf.d/99abox-proxy << EOF
Acquire::http::Proxy "$PROXY_URL";
Acquire::https::Proxy "$PROXY_URL";
EOF
fi

# DNF (RHEL 8+/Fedora/AlmaLinux/Rocky)
if command -v dnf &>/dev/null; then
    echo "Configuring DNF proxy..."
    if ! grep -q "^proxy=" /etc/dnf/dnf.conf 2>/dev/null; then
        echo "proxy=$PROXY_URL" >> /etc/dnf/dnf.conf
    fi
fi

# YUM (older RHEL/CentOS - only if DNF is not present)
if command -v yum &>/dev/null && ! command -v dnf &>/dev/null; then
    echo "Configuring YUM proxy..."
    if ! grep -q "^proxy=" /etc/yum.conf 2>/dev/null; then
        echo "proxy=$PROXY_URL" >> /etc/yum.conf
    fi
fi

# Docker
if command -v docker &>/dev/null; then
    echo "Configuring Docker proxy..."
    mkdir -p /etc/systemd/system/docker.service.d
    cat > /etc/systemd/system/docker.service.d/http-proxy.conf << EOF
[Service]
Environment="HTTP_PROXY=$PROXY_URL"
Environment="HTTPS_PROXY=$PROXY_URL"
Environment="NO_PROXY=$NO_PROXY"
EOF
    NEED_DAEMON_RELOAD=true

    # daemon.json: proxy injected into build & run containers (Docker 23.0+)
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
  "proxies": {
    "http-proxy": "$PROXY_URL",
    "https-proxy": "$PROXY_URL",
    "no-proxy": "$NO_PROXY"
  }
}
EOF
fi

# containerd
if command -v containerd &>/dev/null; then
    echo "Configuring containerd proxy..."
    mkdir -p /etc/systemd/system/containerd.service.d
    cat > /etc/systemd/system/containerd.service.d/http-proxy.conf << EOF
[Service]
Environment="HTTP_PROXY=$PROXY_URL"
Environment="HTTPS_PROXY=$PROXY_URL"
Environment="NO_PROXY=$NO_PROXY"
EOF
    NEED_DAEMON_RELOAD=true
fi

# Reload systemd if any service configs were written
if $NEED_DAEMON_RELOAD; then
    systemctl daemon-reload
    # Restart services if they're running
    if systemctl is-active --quiet docker; then
        systemctl restart docker
    fi
    if systemctl is-active --quiet containerd; then
        systemctl restart containerd
    fi
fi

# snap
if command -v snap &>/dev/null; then
    echo "Configuring snap proxy..."
    snap set system proxy.http="$PROXY_URL" || true
    snap set system proxy.https="$PROXY_URL" || true
fi
{{- if .CACert }}

# pip
if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
    echo "Configuring pip CA certificate..."
    cat > /etc/pip.conf << EOF
[global]
cert = $ABOX_CA_CERT
EOF
fi

# npm
if command -v npm &>/dev/null; then
    echo "Configuring npm CA certificate..."
    npm config set --global cafile "$ABOX_CA_CERT"
fi

# git
if command -v git &>/dev/null; then
    echo "Configuring git CA certificate..."
    git config --system http.sslCAInfo "$ABOX_CA_CERT"
fi
{{- end }}

echo "Done."
