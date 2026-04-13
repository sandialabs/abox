# Privilege Helper

abox requires root privileges for certain operations (iptables rules, disk image management, UFW firewall rules). By default, it spawns a privilege helper process via `sudo` or `pkexec`, which prompts for a password.

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
