# abox.yaml Configuration Reference

The `abox.yaml` file provides declarative configuration for abox instances, similar to a Vagrantfile. Place this file in your project directory and use `abox up` to create, start, and provision your instance.

## Overview

Instead of running multiple commands:

```bash
abox create my-agent --cpus 4 --memory 8192
abox start my-agent
abox provision my-agent -s provision.sh
abox allowlist add my-agent github.com
abox net filter my-agent active
```

You can define everything in `abox.yaml`:

```yaml
version: 1
name: my-agent
cpus: 4
memory: 8192
provision:
  - provision.sh
allowlist:
  - "*.github.com"
```

And run a single command:

```bash
abox up
```

## Full Example

```yaml
# Version (required)
version: 1

# Instance name (required)
name: my-agent

# Resource allocation
cpus: 4
memory: 8192
disk: "50G"

# Base image
base: ubuntu-24.04

# SSH user (auto-detected from base image if not set)
# user: ubuntu

# Network configuration (optional - auto-allocated if not specified)
subnet: "10.10.20.0/24"

# Provision scripts (run in order)
provision:
  - scripts/base-setup.sh
  - scripts/install-tools.sh

# Directory to copy into VM (available at /tmp/abox/overlay during provisioning)
overlay: files/

# Domain allowlist (shared by DNS and HTTP filters)
allowlist:
  - "*.github.com"
  - "*.githubusercontent.com"
  - "*.anthropic.com"
  - "*.openai.com"
  - "*.pypi.org"
  - "*.npmjs.org"

# DNS configuration
dns:
  # Upstream DNS server
  upstream: "1.1.1.1:53"

# Agent monitoring
monitor:
  enabled: true
  # version: v1.3.0  # Optional: pin to specific version
  # kprobes:          # Optional: select specific curated kprobes (default: file + network only)
  #   - security_socket_connect
  #   - security_file_open
  #   - security_bprm_check    # opt-in: exec check
  #   - do_init_module         # opt-in: kernel module loading
  # policies:         # Optional: supply custom TracingPolicy YAML files (mutually exclusive with kprobes)
  #   - ./my-tracing-policy.yaml
```

**Note:** The allowlist is shared by both the DNS filter and HTTP proxy. Domains added via `allowlist` apply to both filters.

## Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | (required) | Configuration version. Must be `1`. |
| `name` | string | (required) | Instance identifier. Must start with a letter, contain only letters/numbers/underscores/hyphens, max 63 chars. |
| `backend` | string | (auto) | VM backend to use. Currently only "libvirt" is supported. If not specified, auto-detected. |
| `cpus` | int | 2 | Number of virtual CPU cores |
| `memory` | int | 4096 | RAM in megabytes |
| `disk` | string | "20G" | Disk size (e.g., "20G", "50G", "100G") |
| `base` | string | "ubuntu-24.04" | Base image to use. Run `abox base list` for available images |
| `user` | string | (auto-detected from base image) | SSH username for connecting to the VM |
| `subnet` | string | (auto) | Custom /24 subnet (e.g., "10.10.20.0/24"). If not specified, automatically allocated from 10.10.x.0/24 |
| `provision` | []string | [] | List of shell script paths to run during initial setup |
| `overlay` | string | "" | Directory to copy into the VM at /tmp/abox/overlay during provisioning |
| `allowlist` | []string | [] | Domain allowlist entries (shared by DNS and HTTP filters) |
| `dns` | object | {} | DNS configuration (see below) |
| `dns.upstream` | string | "8.8.8.8:53" | Upstream DNS server for allowed queries. Port defaults to 53 if not specified (e.g., "8.8.8.8" is valid). |
| `http` | object | {} | HTTP proxy configuration (see below) |
| `http.mitm` | bool | true | Enable TLS MITM for HTTPS inspection and domain fronting protection |
| `monitor` | object | {} | Agent monitoring configuration (see below) |
| `monitor.enabled` | bool | false | Enable Tetragon monitoring via virtio-serial |
| `monitor.version` | string | "" | Tetragon version to use (empty = latest, e.g., "v1.3.0") |
| `monitor.kprobe_multi` | bool | false | Enable BPF kprobe_multi attachment. Disabled by default because some kernels silently fail to fire kprobes attached via kprobe_multi. Set to `true` for slight efficiency gain after verifying it works on your kernel. |
| `monitor.kprobes` | []string | (all defaults) | Curated kprobe names to monitor. Omit for all defaults. Mutually exclusive with `policies`. **File:** `security_file_open`, `vfs_unlink`, `vfs_rename`. **Network:** `security_socket_connect`, `inet_csk_listen_start`, `tcp_close`. **Security:** `security_bprm_check` (exec check), `commit_creds` (credential changes, high volume), `do_init_module` (module loading), `sys_setuid` (setuid to root). **Behavioral:** `sys_ptrace`, `path_mount`. Non-default kprobes are opt-in only. |
| `monitor.policies` | []string | [] | Paths to custom Tetragon TracingPolicy YAML files. Mutually exclusive with `kprobes`. |
| `overrides` | object | {} | Backend-specific overrides (see below) |
| `overrides.libvirt.template` | string | "" | Path to a custom libvirt domain XML template (Go text/template). Overrides the default hardened template. |

## Commands

### abox up

Create, start, and provision an instance from `abox.yaml`.

```bash
# Use abox.yaml in current directory
abox up

# Use abox.yaml in a specific directory
abox up -d /path/to/project
```

**What `abox up` does:**

1. Reads `abox.yaml` from current directory (or `-d` path)
2. Creates the instance if it doesn't exist
3. Starts the instance if not running
4. Applies DNS allowlist entries
5. Runs provision scripts (first time only)
6. Applies network filter and sets filters to active mode

**Subsequent runs are idempotent** - if the instance already exists and is running, `abox up` does nothing.

### abox down

Stop an instance defined in `abox.yaml`.

```bash
# Stop the instance
abox down

# Stop and remove (delete all data)
abox down --remove

# Stop and remove, skip confirmation
abox down --remove -f

# Use abox.yaml from specific directory
abox down -d /path/to/project
```

## Provisioning

Scripts listed in `provision` run as root inside the VM during the first `abox up`.
The `overlay` directory is copied to `/tmp/abox/overlay` in the VM before scripts run.
For examples, environment variables, and best practices, see [Provisioning](provisioning.md).

## Allowlist

The `allowlist` field specifies domains the VM can access (shared by DNS and HTTP filters):

```yaml
allowlist:
  - "*.github.com"
  - "api.anthropic.com"
  - "pypi.org"
```

For detailed syntax and wildcard matching rules, see [Filtering: Allowlist Syntax](filtering.md#allowlist-syntax).

## Path Resolution

Paths in `provision` and `overlay` are resolved relative to the directory containing `abox.yaml`:

```yaml
# If abox.yaml is in /home/user/project/
provision:
  - scripts/setup.sh        # Resolves to /home/user/project/scripts/setup.sh
  - /opt/shared/common.sh   # Absolute paths also work
overlay: files/             # Resolves to /home/user/project/files/
```

## Validation

The configuration is validated before any operations:

- `name` is required and must match the naming rules
- Provision script paths must exist
- Overlay path must be a directory (if specified)

Errors are reported immediately:

```
$ abox up
Error: provision script not found: scripts/missing.sh
```

## Example Workflows

### Minimal Configuration

```yaml
version: 1
name: dev
```

Uses all defaults: 2 CPUs, 4GB RAM, 20GB disk, Ubuntu 24.04, auto-detected user.

### Development Environment

```yaml
version: 1
name: dev-agent
cpus: 4
memory: 8192
provision:
  - provision.sh
allowlist:
  - "*.github.com"
  - "*.anthropic.com"
```

### Custom Network

```yaml
version: 1
name: isolated
subnet: "10.10.50.0/24"
dns:
  upstream: "1.1.1.1"  # Port defaults to 53
```

### Disable TLS MITM

For applications that use certificate pinning (e.g., some mobile app backends), you may need to disable TLS MITM:

```yaml
version: 1
name: pinned-app
http:
  mitm: false  # Disable for certificate-pinning apps
```

**Warning:** Setting `http.mitm: false` disables domain fronting protection. HTTPS connections will be proxied without inspection, so attackers could potentially bypass the allowlist by using domain fronting techniques.

### Multiple Provision Scripts

```yaml
version: 1
name: full-stack
provision:
  - scripts/01-system.sh
  - scripts/02-docker.sh
  - scripts/03-nodejs.sh
  - scripts/04-python.sh
allowlist:
  - "*.docker.io"
  - "*.docker.com"
  - "*.npmjs.org"
  - "*.pypi.org"
```

## Backend Overrides

The `overrides` section lets you replace backend-specific defaults. Currently only `libvirt.template` is supported.

### Custom Domain Template

To customize the libvirt domain XML (e.g., add CPU pinning, change disk caching, enable nested virt):

```bash
# Export the default template
abox overrides dump libvirt.template > domain.xml.tmpl

# Edit it
vim domain.xml.tmpl

# Reference it in abox.yaml
```

```yaml
version: 1
name: custom-vm
overrides:
  libvirt:
    template: domain.xml.tmpl
```

The template uses Go `text/template` syntax. Available variables are listed in `abox overrides dump --help`.

**Warning:** Custom templates bypass abox's default VM hardening (QEMU sandbox, disabled nested virt, disabled USB/balloon/video, `nosharepages`). You are responsible for maintaining appropriate isolation in your template. See [Hardening](hardening.md) for what the defaults provide.

## See Also

- [Provisioning](provisioning.md) - Detailed script documentation and examples
- [Filtering](filtering.md) - Allowlist syntax and filtering behavior
- [Security Design](security.md) - Security modes and defense layers
