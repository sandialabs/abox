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
| `backend` | string | (auto) | VM backend for the instance. Auto-detects `libvirt` on Linux and `vfkit` on macOS. The `vmware` backend is not auto-detected; select it with `ABOX_BACKEND=vmware` (see `abox help environment`). |
| `cpus` | int | 2 | Number of virtual CPU cores |
| `memory` | int | 4096 | RAM in megabytes |
| `disk` | string | "20G" | Disk size (e.g., "20G", "50G", "100G") |
| `base` | string | "ubuntu-24.04" | Base image to use. Run `abox base list` for available images; see [Base Images](base-images.md) to create a custom base |
| `user` | string | (auto-detected from base image) | SSH username for connecting to the VM |
| `subnet` | string | (auto) | Custom /24 subnet (e.g., "10.10.20.0/24"). If not specified, automatically allocated from 10.10.x.0/24 |
| `provision` | []string | [] | List of shell script paths to run during initial setup |
| `overlay` | string | "" | Directory to copy into the VM at /tmp/abox/overlay during provisioning |
| `allowlist` | []string | [] | Domain allowlist entries (shared by DNS and HTTP filters) |
| `dns` | object | {} | DNS configuration (see below) |
| `dns.upstream` | string | host system resolver | Upstream DNS server for allowed queries. When unset, abox uses the host's system resolver (from `/etc/resolv.conf`, or SystemConfiguration on macOS), falling back to a public resolver (`8.8.8.8:53`) only if it can't be determined. Port defaults to 53 if not specified (e.g., "8.8.8.8" is valid). |
| `http` | object | {} | HTTP proxy configuration (see below) |
| `http.mitm` | bool | true | Enable TLS MITM for HTTPS inspection and domain fronting protection |
| `http.max_connections` | int | 512 | Cap on concurrent client connections to the HTTP proxy, bounding host fd/goroutine use against a runaway or hostile VM. Raise for heavy parallel workloads; keep below the host's `ulimit -n`. Existing instances without this key use the default automatically. |
| `http.allow_private_targets` | []string | [] | Opt-in list of CIDRs the DNS/HTTP filters may connect to despite the default SSRF deny of private/loopback/link-local/metadata ranges. Shared by both filters. See [Reaching internal hosts](#reaching-internal-hosts). |
| `http.secret_injections` | []object | [] | Bind host-side secret values to outbound request headers so the guest never holds the raw credential. See [Secret injection](#secret-injection) and [docs/secrets.md](secrets.md). |
| `http.secret_injections[].key` | string | (required) | Name of the value in the per-instance secret store (`abox secrets set`). |
| `http.secret_injections[].host` | string | (required) | Exact host to inject into (e.g. `api.anthropic.com`). |
| `http.secret_injections[].header` | string | (required) | Header name to set (e.g. `x-api-key`, `Authorization`). |
| `http.secret_injections[].path_prefix` | string | "" | Only inject when the request path is within this prefix (e.g. `/v1/`). Empty = all paths. Narrows the reflection risk (see [docs/secrets.md](secrets.md)). |
| `http.secret_injections[].value_prefix` | string | "" | Prepended to the stored value (e.g. `"Bearer "` for `Authorization`). |
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

### Reaching internal hosts

The DNS and HTTP filters run on the host and make outbound connections *on behalf of* the guest. To prevent server-side request forgery (SSRF), they deny any connection whose resolved target is a private, loopback, link-local, or cloud-metadata address (e.g. `169.254.169.254`) — **even for allowlisted domains**. This is checked against the address the connection actually resolves to, so a public domain that is DNS-rebound or poisoned to a private IP is blocked, not just literal-IP requests.

If your agent legitimately needs to reach an internal host, allowlist the domain **and** opt its address range into `http.allow_private_targets`:

```yaml
version: 1
name: dev
allowlist:
  - internal.corp.example.com   # domain allow (unchanged)
http:
  allow_private_targets:        # empty by default => all private targets denied
    - 10.0.5.0/24
    - 192.168.1.10/32           # a single host is /32
```

With the above, `internal.corp.example.com` resolving into `10.0.5.0/24` is permitted, while an allowlisted public domain rebound to `169.254.169.254` (not in the list) is still blocked. Entries must be CIDR notation. The list is shared by the DNS rebinding check and the HTTP proxy.

> Note: when an upstream proxy (`https_proxy`) is configured, the target is resolved by that proxy rather than locally, so a private-IP upstream proxy itself must be listed here to be dialable.

### Secret injection

Keep API keys out of the guest: store the value on the host and have the HTTP
proxy inject it into outbound requests. The agent can *use* the credential but
never *holds* it at rest.

```yaml
version: 1
name: dev
allowlist:
  - api.anthropic.com
http:
  secret_injections:
    - key: anthropic          # value stored via: abox secrets set dev anthropic --from-file ./key.txt
      host: api.anthropic.com
      header: x-api-key
      path_prefix: /v1/       # only inject on API paths
```

Store and manage the value with the `abox secrets` commands:

```bash
abox secrets set dev anthropic --from-file ./key.txt
abox secrets set dev anthropic --from-env ANTHROPIC_API_KEY
abox secrets list dev
abox secrets remove dev anthropic
```

Requirements and caveats:

- Requires `http.mitm: true` (the default) — the proxy must intercept the request
  to modify it. Injection is refused at startup if MITM is disabled or the filter
  runs in passive mode.
- Changing a **binding** (the `secret_injections` block) after `abox create`
  requires re-creating the instance or hand-editing its `config.yaml` — there is no
  `abox update`. Changing a **value** requires `abox stop` then `abox start` so the
  HTTP filter reloads it.
- There is an important trust boundary: if the bound host reflects request headers
  on a reachable path, the agent can read the key back. See
  [docs/secrets.md](secrets.md) for the full threat model and how `path_prefix`
  mitigates it.

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

**Constraint:** A custom template **must** keep the network interface as `<model type='virtio'/>` with `<driver name='vhost'/>` (as the default template does). abox applies and removes the egress `nwfilter` at runtime via `virsh update-device`, which must match the running interface's model and driver — a template that changes them will cause egress apply/remove to fail (fail-closed: the VM will not start unfiltered).

## See Also

- [Provisioning](provisioning.md) - Detailed script documentation and examples
- [Filtering](filtering.md) - Allowlist syntax and filtering behavior
- [Security Design](security.md) - Security modes and defense layers
