# Provision Scripts

Provision scripts are shell scripts that run inside the VM to install packages, configure the environment, and set up your development tools.

## Overview

Scripts run as root via SSH and are executed:
- During the first `abox up` (if defined in `abox.yaml`)
- Manually via `abox provision <name> -s <script>`

## Environment Variables

Provision scripts have access to the following environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `ABOX_NAME` | Instance name | `dev` |
| `ABOX_USER` | SSH username | `ubuntu` |
| `ABOX_IP` | VM IP address | `10.10.10.50` |
| `ABOX_GATEWAY` | Gateway IP | `10.10.10.1` |
| `ABOX_SUBNET` | Subnet CIDR | `10.10.10.0/24` |
| `ABOX_OVERLAY` | Overlay mount point (only set when overlay is used) | `/tmp/abox/overlay` |
| `DEBIAN_FRONTEND` | Set to `noninteractive` to suppress dpkg prompts | `noninteractive` |
| `NEEDRESTART_SUSPEND` | Set to `1` to prevent needrestart from restarting services | `1` |

### Example Usage

```bash
#!/bin/bash
set -e

echo "Provisioning instance: $ABOX_NAME"
echo "VM IP: $ABOX_IP"

# Install packages as root
apt-get update
apt-get install -y git curl

# Set up user-specific configuration
sudo -u "$ABOX_USER" bash <<EOF
cd /home/$ABOX_USER
git config --global user.name "Developer"
EOF
```

**Note:** The examples below use `apt-get` (Debian/Ubuntu). For RHEL-based images like AlmaLinux, use `dnf` instead (e.g., `dnf install -y git curl`).

## Best Practices

### Use `set -e` for Error Handling

Always start scripts with `set -e` to exit immediately if any command fails:

```bash
#!/bin/bash
set -e

apt-get update
apt-get install -y nodejs  # Script stops here if this fails
npm install -g yarn
```

### Use `set -x` for Debugging

Add `set -x` to print each command before execution:

```bash
#!/bin/bash
set -ex

# All commands are printed before running
apt-get update
apt-get install -y git
```

### Check Root Privileges

Provision scripts run as root, but you can verify:

```bash
#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi
```

### Use `ABOX_USER` for User Operations

When installing user-specific files or running commands as the non-root user:

```bash
#!/bin/bash
set -e

# Install system packages as root
apt-get install -y zsh

# Configure for the user
sudo -u "$ABOX_USER" chsh -s /usr/bin/zsh

# Create user directories
sudo -u "$ABOX_USER" mkdir -p "/home/$ABOX_USER/.config"
```

## Using Overlays

The overlay feature copies files from the host into the VM before running provision scripts. This is useful for configuration files, scripts, or other resources.

### Command Line

```bash
abox provision dev -s setup.sh --overlay ./files
```

### In abox.yaml

```yaml
name: dev
overlay: files/
provision:
  - setup.sh
```

### Accessing Overlay Files

When an overlay is mounted, `ABOX_OVERLAY` points to the directory (default: `/tmp/abox/overlay`):

```bash
#!/bin/bash
set -e

# Check if overlay was provided
if [ -n "$ABOX_OVERLAY" ]; then
    # Copy configuration files
    cp "$ABOX_OVERLAY/.bashrc" "/home/$ABOX_USER/.bashrc"
    cp "$ABOX_OVERLAY/.vimrc" "/home/$ABOX_USER/.vimrc"

    # Run an overlay script
    if [ -f "$ABOX_OVERLAY/extra-setup.sh" ]; then
        bash "$ABOX_OVERLAY/extra-setup.sh"
    fi
fi
```

### Conditional Logic

```bash
#!/bin/bash
set -e

# Base setup always runs
apt-get update
apt-get install -y git curl

# Overlay-specific setup
if [ -d "$ABOX_OVERLAY/dotfiles" ]; then
    echo "Installing dotfiles from overlay..."
    cp -r "$ABOX_OVERLAY/dotfiles/." "/home/$ABOX_USER/"
    chown -R "$ABOX_USER:$ABOX_USER" "/home/$ABOX_USER"
fi
```

## Example Scripts

### Basic Development Setup

```bash
#!/bin/bash
set -e

echo "Setting up development environment for $ABOX_NAME"

# Update system
apt-get update
apt-get upgrade -y

# Install common tools
apt-get install -y \
    git \
    curl \
    wget \
    vim \
    htop \
    jq

# Configure git for the user
sudo -u "$ABOX_USER" git config --global init.defaultBranch main
```

### Node.js Setup

```bash
#!/bin/bash
set -e

# Install Node.js via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Install global packages
npm install -g yarn pnpm

# Verify installation
node --version
npm --version
```

### Python Setup

```bash
#!/bin/bash
set -e

apt-get update
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv

# Install user tools
sudo -u "$ABOX_USER" pip3 install --user pipx
sudo -u "$ABOX_USER" /home/$ABOX_USER/.local/bin/pipx ensurepath
```

### Docker Setup

```bash
#!/bin/bash
set -e

# Install Docker
curl -fsSL https://get.docker.com | sh

# Add user to docker group
usermod -aG docker "$ABOX_USER"

# Configure Docker to use the abox proxy (required for pulling images)
abox-proxy-setup

# Start Docker
systemctl enable docker
systemctl start docker
```

### Multi-Stage Setup

Split complex setups into multiple scripts for better organization:

```yaml
# abox.yaml
name: full-stack
provision:
  - scripts/01-system.sh
  - scripts/02-docker.sh
  - scripts/03-nodejs.sh
  - scripts/04-python.sh
```

Each script focuses on one concern, making debugging easier.

## Configuring Proxy for Services

When network filtering is enabled, outbound HTTP/HTTPS traffic goes through the abox HTTP proxy. Basic proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) are set automatically for shell sessions, but some services require explicit configuration.

### The `abox-proxy-setup` Helper

A helper script at `/usr/local/bin/abox-proxy-setup` configures proxy settings for common services. Run it after installing services that need proxy access:

```bash
#!/bin/bash
set -e

# Install Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$ABOX_USER"

# Configure Docker to use the proxy
sudo abox-proxy-setup

systemctl enable docker
systemctl start docker
```

The helper configures:

| Service | Configuration File |
|---------|-------------------|
| APT | `/etc/apt/apt.conf.d/99abox-proxy` |
| Docker | `/etc/systemd/system/docker.service.d/http-proxy.conf` |
| containerd | `/etc/systemd/system/containerd.service.d/http-proxy.conf` |
| snap | System proxy via `snap set system` |

The script is idempotent—you can run it multiple times safely. It automatically:
- Detects which services are installed
- Creates configuration files only for installed services
- Runs `systemctl daemon-reload` if needed
- Restarts running services to pick up the new configuration

### When to Use

Run `abox-proxy-setup` after installing any of these services:
- Docker or containerd (for pulling images)
- snap packages that make network requests

You don't need to run it for:
- APT—it's configured automatically on first run
- Applications that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables
- pip, npm, curl, wget—these use environment variables

### Manual Configuration

If you need to configure a service not covered by the helper, use the same proxy URL:

```bash
# Proxy URL format
http://$ABOX_GATEWAY:8080
```

For example, configuring a custom service:

```bash
#!/bin/bash
set -e

# Install your service
apt-get install -y myservice

# Configure proxy manually
cat > /etc/myservice/proxy.conf << EOF
proxy_url = http://$ABOX_GATEWAY:8080
EOF

systemctl restart myservice
```

## Troubleshooting

### Script Fails Silently

Add `set -ex` at the start to see which command failed:

```bash
#!/bin/bash
set -ex
# Commands are printed and script exits on first failure
```

### Permission Denied

Remember scripts run as root. For user files, use `sudo -u "$ABOX_USER"`:

```bash
# Wrong - creates file owned by root
echo "export PATH=$PATH:/opt/bin" >> /home/$ABOX_USER/.bashrc

# Correct - creates file owned by user
sudo -u "$ABOX_USER" bash -c 'echo "export PATH=$PATH:/opt/bin" >> ~/.bashrc'
```

### SSH Connection Lost During Provisioning

On Ubuntu 24.04, the `needrestart` service can automatically restart `ssh.service` after package installations, killing the SSH session that runs the provision script. abox mitigates this in two ways:

1. **Prevention:** abox sets `NEEDRESTART_SUSPEND=1` automatically in every provision script, which tells needrestart to skip automatic service restarts.

2. **Recovery:** If SSH drops anyway (exit status 255), abox waits for SSH to come back and checks whether the script had already completed. If it had, provisioning continues with a warning. If the script was still running when the connection dropped, provisioning fails with a clear error.

If you see the recovery message during provisioning, the script completed successfully — no action is needed. If you need to deliberately restart SSH in a script, do so as the last command so the completion marker is written first.

### Re-running Provision

Provision scripts only run automatically on first `abox up`. To re-run:

```bash
abox provision dev -s setup.sh
```

### Checking Variables

Debug environment variables by echoing them:

```bash
#!/bin/bash
echo "ABOX_NAME=$ABOX_NAME"
echo "ABOX_USER=$ABOX_USER"
echo "ABOX_IP=$ABOX_IP"
echo "ABOX_GATEWAY=$ABOX_GATEWAY"
echo "ABOX_SUBNET=$ABOX_SUBNET"
echo "ABOX_OVERLAY=$ABOX_OVERLAY"
```

## See Also

- [Configuration Reference](abox-yaml.md) - Declarative provisioning via abox.yaml
- [Filtering](filtering.md) - Network access during provisioning
