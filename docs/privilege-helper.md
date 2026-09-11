# Privilege Helper

abox requires root privileges for two host-side jobs:

1. **Egress enforcement** — installing the iptables DNS REDIRECT + INPUT accepts
   for the per-instance dnsfilter/httpfilter ports.
2. **Disk storage root** — the ONE privileged step disk handling needs:
   provisioning the caller's per-user storage root
   (`/var/lib/libvirt/images/abox/<uid>`), owned by the caller and setgid to the
   QEMU runtime group. Every image the caller then creates underneath inherits
   that group, so the VM process (libvirt-qemu/qemu) reads them by group
   membership — **no ACLs and no `$HOME` traversal**. All per-instance disk
   operations (create/copy/import/qemu-img) run unprivileged.

By default abox spawns a privilege helper process via `sudo` or `pkexec`, which
prompts for a password.

On macOS the helper instead exposes a separate pfctl-only `Pf` service (the
egress enforcement mechanism there is a pf anchor, not iptables); see
[docs/macos.md](macos.md). The `Egress` service described below is the Linux path.

The helper exposes a minimal `Egress` gRPC service — 6 RPCs total:

| RPC | Purpose |
|-----|---------|
| `EnsureStorageRoot` | provision the caller's per-user disk storage root (owned by the caller, setgid to the QEMU group), idempotent. The helper derives the caller from the socket peer uid and creates only `<parent>/<uid>` — never an arbitrary path. With `regroup` set (used by `abox migrate`) it also re-groups the caller's own subtree to the QEMU group after files were relocated. |
| `Apply`    | install the DNS REDIRECT (nat table) + INPUT accepts for a bridge (idempotent) |
| `Remove`   | flush abox's egress rules for a bridge — scoped to abox's own ports so unrelated rules survive (idempotent) |
| `Verify`   | report whether the host-side DNS redirect + accepts are in force |
| `Ping`     | health check (no auth required) |
| `Shutdown` | graceful helper shutdown |

## Disk storage ownership

The per-user storage root is created **once** (root-owned shared parent
`/var/lib/libvirt/images/abox`, then the per-user `<uid>` subdir owned by the
caller and setgid `2750` to the resolved QEMU group). The QEMU group is resolved
from, in order: an uncommented `group = "..."` in `/etc/libvirt/qemu.conf`, the
QEMU runtime user's primary group, then the known names (`libvirt-qemu`, `qemu`,
`kvm`). If it resolves via the broad `kvm` fallback the helper emits a warning —
the storage tree would then be group-readable by every `kvm` member, so pin the
exact group with `group = "..."` in `qemu.conf`.

Disk files are mode `0640` (owner-rw, group-**read**) and directories `2750`
(setgid). This assumes libvirtd's default `dynamic_ownership = 1`, under which
libvirt chowns the writable disk to the QEMU user at VM start (granting
owner-write). **Caveat:** if you set `dynamic_ownership = 0` in `qemu.conf`, the
writable disk must be group-**writable**; adjust the disk mode accordingly, since
the VM process would otherwise be unable to write its CoW layer.

> **UFW removed.** Earlier versions used `ufw allow in on <bridge>` to open the
> bridge. The helper now installs scoped iptables INPUT accepts for exactly the
> dnsfilter and httpfilter ports instead, so it works on default-DROP hosts
> without ufw and never depends on `ufw`. **Upgrade note:** instances created by
> an older abox while ufw was active left a `ufw allow in on <bridge>` rule that
> the new code no longer removes; remove it manually with
> `sudo ufw delete allow in on <bridge>` if desired.
>
> The helper still runs setuid-root; scoping it to `CAP_NET_ADMIN` is a planned
> follow-up.

For automated/headless workflows, there are two ways to eliminate password prompts.

## Option 1: Setuid Helper (Recommended)

The `abox-helper` binary is a minimal setuid root binary that can be installed to allow members of the `abox` group to perform privileged operations without sudo prompts.

### Installation

**From source:**

```bash
make build-helper
make install-helper  # Creates abox group, installs with setuid
```

**From deb package:**

The package postinst script automatically creates the `abox` group and sets up the setuid binary.

### Setup

Add your user to the `abox` group:

```bash
sudo usermod -aG abox $USER
newgrp abox  # Apply group membership in current shell
```

### How it works

The setuid helper binary is installed at `/usr/local/bin/abox-helper` (or `/usr/bin/abox-helper` from packages) with these permissions:

```
-rwsr-x--- root abox /usr/local/bin/abox-helper
```

When abox detects this binary, it spawns it directly instead of using sudo/pkexec. The helper performs extensive security hardening at startup:

1. Clears the environment and sets a safe PATH
2. Closes all inherited file descriptors
3. Ensures stdin/stdout/stderr are open (prevents fd-reuse attacks)
4. Disables core dumps
5. Verifies the caller is in the `abox` group
6. Verifies it is running as a setuid invocation (not directly as root)

The helper then starts the same gRPC privilege server used by the sudo/pkexec path, with identical token authentication, UID checking, and input validation.

### Audit trail

All privileged operations are logged to syslog:

```bash
journalctl -t abox
```

Each log entry includes the RPC method called and the result (success/error).

### Detection priority

abox checks for privilege escalation methods in this order:

1. **External helper** (`ABOX_PRIVILEGE_SOCKET` + `ABOX_PRIVILEGE_TOKEN` env vars) - for e2e tests
2. **Setuid helper** - checks `/usr/local/bin/abox-helper` and `/usr/bin/abox-helper`
3. **sudo/pkexec** - interactive password prompt

### Uninstalling

```bash
sudo rm /usr/local/bin/abox-helper
sudo groupdel abox  # Optional: remove the group
```

## Option 2: sudoers.d NOPASSWD

If you prefer not to use a setuid binary, you can configure sudoers to allow password-free execution of the abox privilege helper.

Create `/etc/sudoers.d/abox`:

```
# Allow members of the abox group to run the abox privilege helper without a password.
# The privilege-helper subcommand is an internal command that starts a gRPC server
# on a Unix socket; all actual operations are validated by the helper.
%abox ALL=(root) NOPASSWD: /usr/local/bin/abox privilege-helper *
%abox ALL=(root) NOPASSWD: /usr/bin/abox privilege-helper *
```

Then add your user to the `abox` group:

```bash
sudo groupadd --system abox
sudo usermod -aG abox $USER
```

**Note:** The sudoers approach relies on sudo's own audit logging. The setuid helper provides its own syslog audit trail.

## Security Comparison

| Property | Setuid helper | sudoers NOPASSWD |
|----------|--------------|------------------|
| Password prompt | No | No |
| Headless/automated | Yes | Yes |
| System configuration | Group only | sudoers file |
| Audit trail | syslog (self) | sudo logs |
| Attack surface | setuid exec transition | sudo configuration |
| Environment sanitization | Built-in | sudo's env_reset |
| Binary update | Retains setuid | No action needed |

Both approaches use the same underlying gRPC privilege server with identical input validation, token authentication, and UID checking. The security boundary (validation of all privileged operations) is the same regardless of how the helper process is started.

## See Also

- [Security Design](security.md) - abox's security model
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
