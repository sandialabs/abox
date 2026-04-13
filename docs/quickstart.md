# Quickstart Guide

Get started with abox in five minutes.

## Prerequisites

A Linux system with:
- KVM support (check with `lscpu | grep Virtualization`)
- libvirt/QEMU installed
- Go 1.25+ (for building)

## Installation

### 1. Install Dependencies

Install the required packages for your distribution. See [System Requirements: Installation Commands](requirements.md#installation-commands) for per-distro instructions.

### 2. Build abox

```bash
git clone https://github.com/sandialabs/abox.git
cd abox
go build -o abox ./cmd/abox
```

### 3. Add to PATH

```bash
# Option 1: Move to a directory in PATH
sudo mv abox /usr/local/bin/

# Option 2: Add current directory to PATH
export PATH="$PWD:$PATH"
```

### 4. Verify Dependencies

```bash
abox check-deps
```

All required dependencies should show "ok". If you see "missing", install the indicated package.

### 5. Download a Base Image

```bash
abox base pull ubuntu-24.04
```

This downloads the Ubuntu 24.04 cloud image to `~/.local/share/abox/base/`.

Run `abox base list` to see all available images including AlmaLinux, Debian, and Ubuntu.

## Your First Instance

### Create and Start

```bash
# Create an instance named "dev"
abox create dev --cpus 2 --memory 4096

# Start it
abox start dev

# SSH into the VM
abox ssh dev
```

### Apply Security Restrictions

DNS and HTTP filter daemons start automatically with `abox start`, but the
proxy-only network restriction (nwfilter) must be applied separately:

```bash
# Apply network filter (proxy-only outbound)
abox net filter dev active

# Verify status
abox status dev
abox dns status dev
abox http status dev
```

**Note:** `abox up` applies all security restrictions automatically. When using
the manual `create`/`start` workflow, run `abox net filter` yourself.

### Manage Allowlist

```bash
# Add domains the VM can access
abox allowlist add dev github.com
abox allowlist add dev "*.anthropic.com"

# List allowed domains
abox allowlist list dev
```

### Stop and Remove

```bash
# Stop the instance
abox stop dev

# Remove (delete all data)
abox remove dev
```

## Using abox.yaml (Recommended)

### Generate Configuration

Use `abox init` to interactively generate an `abox.yaml` file:

```bash
# Interactive mode - prompts for configuration values
abox init

# Non-interactive with defaults
abox init --defaults

# Preview without writing file
abox init --dry-run
```

### Feature Selection

In interactive mode, `abox init` offers common tool setups:

| Feature | Suggested Domains |
|---------|-------------------|
| Claude Code | api.anthropic.com, platform.claude.com, claude.ai |
| Docker | *.docker.io, registry-1.docker.io, production.cloudflare.docker.com |
| Node.js | deb.nodesource.com, registry.npmjs.org |
| Go | go.dev, proxy.golang.org, sum.golang.org |
| Rust | sh.rustup.rs, static.rust-lang.org, crates.io |
| Python tools | pypi.org, files.pythonhosted.org |
| Java (OpenJDK 21) | — |
| GitHub CLI | github.com, *.githubusercontent.com, cli.github.com |
| Dev utilities (ripgrep, fd, jq, tmux, sqlite3) | — |

Selected features generate provision scripts in `scripts/` and suggest
allowlist domains for the required network access.

### Manual Configuration

For reproducible setups, create an `abox.yaml` file:

```yaml
version: 1
name: my-agent
cpus: 4
memory: 8192
provision:
  - provision.sh
allowlist:
  - "*.github.com"
  - "*.anthropic.com"
```

Create a `provision.sh` (this example uses Ubuntu/Debian packages; for RHEL-based images like AlmaLinux or Rocky, use `dnf` instead of `apt-get`):

```bash
#!/bin/bash
apt-get update
apt-get install -y git nodejs npm
npm install -g @anthropic-ai/claude-code
```

Then run:

```bash
abox up
```

This creates, starts, provisions, and secures the instance in one command.

See [abox.yaml Reference](abox-yaml.md) for all configuration options.

## Common Workflows

### Setup Mode

For installing packages that need unrestricted network access during development:

```bash
# Enable passive mode to allow all traffic temporarily
abox net filter dev passive

# Install packages
abox ssh dev
# Inside VM: apt install ...

# Return to active filtering (blocking mode)
abox net filter dev active
```

For more details on filter modes, see [Filtering: Operating Modes](filtering.md#operating-modes).

### Discover Required Domains

Use passive mode to capture what domains your application needs, then export the results to your allowlist. See [Filtering: Domain Profiling](filtering.md#domain-profiling) for the full workflow.

### File Transfer

```bash
# Copy files to VM
abox scp ./myfile.txt dev:/home/$ABOX_USER/  # e.g., /home/ubuntu/ or /home/almalinux/

# Copy from VM
abox scp dev:/var/log/app.log ./

# Mount VM filesystem
abox mount dev ~/mnt/dev
```

### Snapshots

```bash
# Create checkpoint before changes
abox snapshot create dev clean-state

# List snapshots
abox snapshot list dev

# Revert to a snapshot (instance must be stopped)
abox stop dev
abox snapshot revert dev clean-state
abox start dev

# Remove a snapshot
abox snapshot remove dev clean-state
```

### Base Image Management

```bash
# List available images (remote and local)
abox base list

# Download an image
abox base pull ubuntu-24.04

# Import a custom qcow2 image
abox base import my-image /path/to/image.qcow2

# Remove a downloaded image
abox base remove ubuntu-24.04

# Remove all unused images and stale instances
abox prune -n          # Preview what would be removed
abox prune -f          # Actually remove
```

### Instance Configuration

```bash
# View instance configuration
abox config view dev

# Edit instance resources
abox config edit dev --cpus 4 --memory 8192

# Restart to apply CPU/memory changes
abox restart dev
```

## Global Flags

These flags are available on all commands:

| Flag | Env Variable | Description |
|------|-------------|-------------|
| `--log-level` | `ABOX_LOG_LEVEL` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `--log-format` | `ABOX_LOG_FORMAT` | Log format: `text`, `json` |
| `--log-file` | `ABOX_LOG_FILE` | Write logs to a file (in addition to stderr) |

Example:

```bash
abox start dev --log-level debug --log-file /tmp/abox-debug.log
```

## Built-in Help

abox includes CLI help topics for quick reference:

    abox help quickstart      # Quick start guide
    abox help commands        # Full command listing
    abox help yaml            # abox.yaml reference
    abox help environment     # Environment variables (host and guest)
    abox help filtering       # DNS/HTTP filtering details
    abox help provisioning    # Provision script guide

## Next Steps

- [Security Design](security.md) - Understand abox's security model
- [abox.yaml Reference](abox-yaml.md) - Full configuration options
- [VM Access](vm-access.md) - SSH, SCP, port forwarding, and SSHFS mounting
- [Export/Import](export-import.md) - Move instances between machines
- [Filtering](filtering.md) - DNS and HTTP proxy filtering
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [System Requirements](requirements.md) - Detailed compatibility info
