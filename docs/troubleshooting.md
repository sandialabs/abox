# Troubleshooting Guide

Common issues and how to resolve them.

## Diagnostic Commands

Start troubleshooting with these commands:

```bash
# Check all dependencies are installed
abox check-deps

# Check instance status
abox status dev

# Check DNS filter status
abox dns status dev

# View instance configuration
abox config view dev
```

### Automated Diagnostics

Run the built-in diagnostic tool for a comprehensive health check:

```bash
abox doctor dev

# Plain text output (no TUI)
abox doctor dev --plain
```

This checks: host configuration, VM state, network, DNS/HTTP filter services, SSH connectivity, and in-VM network configuration.

## Common Issues

### Instance Won't Start

**Symptoms:**
- `abox start dev` fails
- Error about libvirt connection

**Possible causes:**

1. **libvirtd not running**
   ```bash
   sudo systemctl start libvirtd
   sudo systemctl enable libvirtd
   ```

2. **Not in libvirt group**
   ```bash
   sudo usermod -aG libvirt $USER
   # Log out and back in for group change to take effect
   ```

3. **virsh not accessible**
   ```bash
   abox check-deps
   # If virsh shows "missing", install libvirt-clients
   ```

4. **KVM not available**
   ```bash
   # Check if KVM is loaded
   lsmod | grep kvm

   # Check if virtualization is enabled
   lscpu | grep Virtualization
   ```

### DNS Not Working

**Symptoms:**
- VM can't resolve any domains
- `dig` queries time out from inside VM

**Troubleshooting steps:**

1. **Check if DNS filter is running:**
   ```bash
   abox dns status dev
   ```
   If it shows "DNS filter is not running", restart the instance:
   ```bash
   abox restart dev
   ```
   **Tip:** Enable debug logging for more detail: `abox dns level dev debug`

2. **Test DNS from host:**
   ```bash
   # Find the DNS port
   abox config view dev | grep dns_port

   # Test directly
   dig @127.0.0.1 -p 5353 github.com
   ```

3. **Check iptables rules:**
   ```bash
   sudo iptables -t nat -L PREROUTING -n | grep abox
   ```

4. **Verify allowlist has entries:**
   ```bash
   abox allowlist list dev
   ```

### Domain Being Blocked

**Symptoms:**
- Specific domain returns NXDOMAIN
- Application fails to connect to a service

**Resolution:**

1. **Check if domain is allowlisted:**
   ```bash
   abox allowlist list dev | grep domain.com
   ```

2. **Add the domain:**
   ```bash
   abox allowlist add dev domain.com
   # Or with wildcard for all subdomains
   abox allowlist add dev "*.domain.com"
   ```

3. **Use profile mode to discover dependencies:**
   ```bash
   abox net filter dev passive
   # Run your application
   abox net profile dev show
   # Add discovered domains
   abox net filter dev active
   ```
   For the full profiling workflow, see [Filtering: Domain Profiling](filtering.md#domain-profiling).

4. **Check for related domains:**
   Some services use multiple domains. For example, GitHub uses:
   - github.com
   - githubusercontent.com
   - githubassets.com

### HTTP Proxy Not Working

**Symptoms:**
- HTTP/HTTPS requests fail from VM
- `curl` commands hang or return connection refused
- Applications can't reach web services

**Troubleshooting steps:**

1. **Check if HTTP filter is running:**
   ```bash
   abox http status dev
   ```
   If it shows "HTTP filter: not running", restart the instance:
   ```bash
   abox restart dev
   ```
   **Tip:** Enable debug logging for more detail: `abox http level dev debug`

2. **Verify proxy environment variables:**
   ```bash
   abox ssh dev -- 'echo $HTTP_PROXY'
   abox ssh dev -- 'echo $HTTPS_PROXY'
   ```
   These should show `http://<gateway>:<port>`.

3. **Test proxy connectivity:**
   ```bash
   # From inside the VM
   abox ssh dev -- 'curl -v --proxy $HTTP_PROXY https://github.com'
   ```

4. **Check if domain is allowlisted:**
   ```bash
   abox allowlist list dev | grep domain.com
   ```
   The HTTP proxy uses the same allowlist as DNS filtering.

### VM Has No IP Address

**Symptoms:**
- `abox ssh dev` hangs
- `abox status dev` shows no IP

**Troubleshooting:**

1. **Wait for boot to complete:**
   New VMs need time to boot. Wait 30-60 seconds after starting.

2. **Check if VM is running:**
   ```bash
   virsh list --all | grep abox-dev
   ```

3. **Check network is active:**
   ```bash
   virsh net-list | grep abox-dev
   ```

4. **Restart DHCP:**
   ```bash
   abox restart dev
   ```

5. **Check VM console for errors:**
   ```bash
   virsh console abox-dev
   # Press Enter to see login prompt
   # Ctrl+] to exit
   ```

### Permission Denied Errors

**Symptoms:**
- "Permission denied" when running abox commands
- pkexec password prompts

**Resolution:**

1. **Add user to libvirt group:**
   ```bash
   sudo usermod -aG libvirt $USER
   newgrp libvirt  # Apply immediately, or log out/in
   ```
   For verification steps, see [Requirements: libvirt Group Membership](requirements.md#libvirt-group-membership).

2. **If using pkexec, configure polkit** — see [Requirements: Polkit Configuration](requirements.md#polkit-configuration-optional).

### Base Image Not Found

**Symptoms:**
- `abox create dev` fails with "base image not found"

**Resolution:**

1. **List available images:**
   ```bash
   abox base list
   ```

2. **Pull the required image:**
   ```bash
   abox base pull ubuntu-24.04
   ```

3. **Check image directory:**
   ```bash
   ls -la ~/.local/share/abox/base/
   ```

### Network Conflict

**Symptoms:**
- "Network already exists" errors
- Subnet conflicts with existing networks

**Resolution:**

1. **Use a custom subnet:**
   ```bash
   abox create dev --subnet 10.10.50.0/24
   ```

2. **Clean up orphaned networks:**
   ```bash
   virsh net-list --all
   virsh net-destroy abox-dev
   virsh net-undefine abox-dev
   ```

### Mount Command Fails

**Symptoms:**
- `abox mount dev ~/mnt` fails
- SSHFS errors

**Resolution:**

1. **Install SSHFS:**
   ```bash
   # Debian/Ubuntu
   sudo apt install sshfs fuse3

   # Fedora
   sudo dnf install sshfs fuse3
   ```

2. **Create mount point:**
   ```bash
   mkdir -p ~/mnt/dev
   ```

3. **Check FUSE permissions:**
   ```bash
   # User should be in fuse group or have access to /dev/fuse
   ls -l /dev/fuse
   ```

4. **Unmount stale mounts:**
   ```bash
   fusermount -u ~/mnt/dev
   # Or force unmount
   sudo umount -l ~/mnt/dev
   ```

### macOS-Specific Issues

#### abox is "killed" Immediately on Launch

**Symptoms:**
- Running `abox` (e.g. `abox version`) prints `killed` and exits with code 137
- This happens right after building/installing from source
- A crash report under `~/Library/Logs/DiagnosticReports/abox-*.ips` shows
  `SIGKILL (Code Signature Invalid)`

**Cause:** With `CGO_ENABLED=0`, Go's internal linker applies an ad-hoc
signature flagged `linker-signed`. macOS 26's hardened Code Signing Monitor
rejects that signature at `exec()` and kills the process — even though
`codesign -v` validates the binary at rest.

**Resolution:** re-sign the binary with a plain ad-hoc signature:

```bash
codesign --force --sign - ~/.local/bin/abox
```

`make build` and `make install` do this automatically on macOS, so this only
affects binaries built with a bare `go build`.

#### VM Exits Immediately After Start

**Symptoms:**
- `abox start dev` returns quickly; `abox status dev` shows the VM is stopped
- `logs/console.log` is empty or contains no kernel output

**Cause:** The base image architecture does not match the host.
Apple Silicon requires **arm64** guests. `abox base pull` downloads
arm64 on macOS automatically, but a base image imported via
`abox base import` from an amd64 source will boot-loop silently.

**Resolution:** re-pull the image or import an arm64 variant:

```bash
abox base remove ubuntu-24.04
abox base pull ubuntu-24.04     # arm64 on macOS
```

#### VM Can Reach Blocked Domains

**Symptoms:**
- `abox dns status dev` shows the filter running
- `curl` from inside the VM still reaches non-allowlisted hosts
- Filter logs show no blocked queries

**Cause:** abox's PF anchor references are not wired into `/etc/pf.conf`,
so per-instance `pfctl` rules load but the kernel never evaluates them.

**Resolution:** run the doctor check and follow its hint:

```bash
abox doctor dev
```

The PF anchors check reports one of three states:

| State | Meaning | Fix |
|-------|---------|-----|
| Passed | Wired correctly | — |
| Missing, auto-wire available | Apple markers present; first `abox start` will wire automatically | Next `abox start` (may prompt for sudo) |
| Missing, custom pf.conf | Apple markers absent | Edit `/etc/pf.conf` manually — see [macOS Support: Custom or MDM-Managed pf.conf](macos.md#custom-or-mdm-managed-pfconf) |

#### abox start Prompts for sudo Every Time

This is expected. macOS does not support the setuid `abox-helper` path,
so every privilege helper launch goes through `sudo`. The helper is
launched per privileged command and exits when that command finishes;
repeat prompts are suppressed by sudo's credential cache (typically 5
minutes), so most sessions see only a single prompt. See
[macOS Support: Privilege Escalation](macos.md#privilege-escalation).

#### Other VMs Lost Network After abox start

**Symptoms:**
- Docker Desktop / OrbStack / Podman Machine lose connectivity
  immediately after the very first `abox start` on a fresh install
- Only happens once — subsequent `abox start` invocations have no effect

**Cause:** the first `abox start` runs `pfctl -f /etc/pf.conf`, which
discards the in-memory rules vmnet installed at runtime for the other
VM runtimes.

**Resolution:** restart the affected VM runtime once. Subsequent abox
starts do not reload the main ruleset. See [macOS Support: One-Time
Network Disruption Warning](macos.md#one-time-network-disruption-warning).

### Provision Script Fails

**Symptoms:**
- `abox provision dev` fails partway through
- Packages fail to install

**Resolution:**

1. **Run in passive mode (allows all traffic):**
   ```bash
   abox net filter dev passive
   abox provision dev -s script.sh
   abox net filter dev active
   ```

2. **Add required allowlist entries first:**
   ```bash
   abox allowlist add dev "*.ubuntu.com"
   abox allowlist add dev "*.debian.org"
   ```

3. **SSH in and debug manually:**
   ```bash
   abox ssh dev
   # Run script commands one by one
   ```

## Log Locations

Instance data is stored at `~/.local/share/abox/instances/<name>/`.

Key logs for troubleshooting:

| File | Content | Platform |
|------|---------|----------|
| `logs/dns.log` | DNS allow/block decisions | all |
| `logs/http.log` | HTTP allow/block decisions | all |
| `logs/monitor.log` | Tetragon events (when enabled) | Linux only |
| `logs/keys.log` | TLS session keys for `abox tap` decryption | all |
| `logs/*-service.log` | Daemon stderr logs | all |
| `logs/console.log` | vfkit serial console output (guest kernel + boot) | macOS |
| `logs/vfkit.log` | vfkit process stderr | macOS |
| `logs/privilege-helper.log` | Per-instance privilege helper stderr | macOS |

**Log rotation:** Log files are automatically rotated at 10MB with 3 backups kept (e.g., `dns.log`, `dns.log.1`, `dns.log.2`, `dns.log.3`).

### Filtering Logs with `--jq`

Use `--jq` to filter JSON log output with jq expressions:

```bash
# Show only blocked DNS queries
abox dns logs dev --jq 'select(.action == "blocked")'

# Extract just the queried domain names
abox dns logs dev --jq '.query'

# Show HTTP requests to a specific domain
abox http logs dev --jq 'select(.host | test("github"))'

# Show monitor events of a specific type
abox monitor logs dev --jq 'select(.event_type == "exec")'
```

The `--jq` flag works with `abox dns logs`, `abox http logs`, and `abox monitor logs`. Non-JSON lines (such as log preamble) pass through unchanged.

### Advanced Debugging

The filter daemons can be run manually for debugging:

```bash
# Run DNS filter manually (bypasses normal daemon management)
abox dns serve dev

# Run HTTP filter manually
abox http serve dev

# Run monitor daemon manually
abox monitor serve dev
```

These commands run the filter in the foreground with direct log output, useful for diagnosing startup failures.

### System Logs

**Linux:**
```bash
# libvirt logs
journalctl -u libvirtd

# Audit events (all privileged operations)
journalctl -t abox

# Check for VM errors
virsh dominfo abox-dev
virsh dumpxml abox-dev
```

The `journalctl -t abox` audit log records: instance create, start, stop, remove, import, export, SSH access, SCP transfers, provision runs, mount/unmount, and filter mode changes.

**macOS:**
```bash
# Per-instance privilege helper stderr (audit of pfctl, file ops, etc.)
tail -f ~/.local/share/abox/instances/dev/logs/privilege-helper.log

# vfkit process and guest console
tail -f ~/.local/share/abox/instances/dev/logs/vfkit.log
tail -f ~/.local/share/abox/instances/dev/logs/console.log

# Active PF rules for an instance
sudo pfctl -a abox/dev -s rules
sudo pfctl -a abox/dev -s nat
```

`journalctl` is not available on macOS — audit output lands in the per-instance `privilege-helper.log` instead of a system journal.

## Getting Help

If you can't resolve an issue:

1. **Check existing issues:** https://github.com/sandialabs/abox/issues

2. **Gather diagnostic info:**
   ```bash
   abox check-deps
   abox status <name>
   abox dns status <name>
   virsh list --all
   virsh net-list --all
   ```

3. **File a new issue** with:
   - What you were trying to do
   - The exact error message
   - Output from diagnostic commands
   - Your OS version (`uname -a`, `cat /etc/os-release`)

## See Also

- [System Requirements](requirements.md) - Supported platforms and dependencies
- [macOS Support](macos.md) - macOS install, PF anchors, platform limitations
- [Filtering](filtering.md) - DNS and HTTP proxy filtering details
- [Privilege Helper](privilege-helper.md) - Passwordless privilege escalation
