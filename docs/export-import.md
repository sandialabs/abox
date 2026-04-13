# Export and Import

Move abox instances between machines or create backups using the export/import commands.

## Overview

`abox export` creates a portable `.abox.tar.gz` archive containing:
- Instance configuration
- Disk image
- SSH keys
- DNS allowlist

`abox import` restores an instance from an archive, automatically allocating new network resources to avoid conflicts.

## Export

### Basic Export

```bash
# Stop the instance first (recommended)
abox stop dev

# Export to dev.abox.tar.gz in current directory
abox export dev
```

### Custom Output Path

```bash
abox export dev ./backups/dev-backup.abox.tar.gz
```

### Overwrite Existing Archive

```bash
abox export dev -f
```

### Export Modes

**Full Export (default):**
```bash
abox export dev
```

The disk image is "flattened" - merged with its base image to create a standalone disk. The archive is larger but fully portable; no base image required on the target machine.

**Snapshot Export:**
```bash
abox export dev --snapshot
```

Exports only the CoW (copy-on-write) delta from the base image. Much smaller archive, but the target machine must have the same base image installed.

| Mode | Size | Portability |
|------|------|-------------|
| Full (default) | Larger (includes base) | Complete - works anywhere |
| Snapshot (`-s`) | Smaller (delta only) | Requires same base image |

## Import

### Basic Import

```bash
abox import dev.abox.tar.gz
```

Creates an instance with the same name as the original.

### Import with New Name

```bash
abox import dev.abox.tar.gz dev-copy
```

### Override Resources

```bash
abox import dev.abox.tar.gz --cpus 4 --memory 8192
```

### What Happens on Import

1. Archive is extracted
2. New network resources are allocated (subnet, DNS port, MAC address)
3. Configuration is updated with new network settings
4. Instance is registered but not started

After import:
```bash
abox start dev
abox ssh dev
```

## Workflow Examples

### Machine Migration

Move an instance to a new computer:

```bash
# On source machine
abox stop my-agent
abox export my-agent
# Transfer my-agent.abox.tar.gz to new machine

# On target machine
abox import my-agent.abox.tar.gz
abox start my-agent
```

### Backup Before Changes

Create a backup before risky operations:

```bash
abox stop dev
abox export dev ./backups/dev-$(date +%Y%m%d).abox.tar.gz
abox start dev
# Make changes...

# If something goes wrong:
abox remove dev
abox import ./backups/dev-20240115.abox.tar.gz
```

### Share Preconfigured Environment

Create a standardized development environment for your team:

```bash
# Set up the instance
abox create team-env --cpus 4 --memory 8192
abox start team-env
abox provision team-env -s setup.sh
abox stop team-env

# Export for distribution
abox export team-env

# Team members import
abox import team-env.abox.tar.gz
```

### Clone an Instance

Create a copy of an existing instance:

```bash
abox stop dev
abox export dev --snapshot  # Use snapshot for speed
abox import dev.abox.tar.gz dev-test
abox start dev
abox start dev-test
```

## Archive Contents

The `.abox.tar.gz` archive contains:

```
dev.abox.tar.gz
├── config.yaml       # Instance configuration
├── disk.qcow2        # Disk image (flattened or CoW)
├── id_ed25519        # SSH private key
├── id_ed25519.pub    # SSH public key
├── allowlist.conf    # DNS allowlist
└── manifest.json     # Export metadata (base image, mode, etc.)
```

## Snapshot Archives

When using `--snapshot`, the archive includes only the CoW delta. On import:

1. abox checks if the required base image exists
2. If missing, shows an error with the required image name
3. Install the base image and retry:

```bash
$ abox import dev.abox.tar.gz
Error: base image "ubuntu-24.04" required but not found
Run: abox base pull ubuntu-24.04

$ abox base pull ubuntu-24.04
$ abox import dev.abox.tar.gz
```

## Troubleshooting

### "Archive already exists"

Use `-f` to overwrite:
```bash
abox export dev -f
```

### "Base image required"

For snapshot archives, install the required base image:
```bash
abox base pull ubuntu-24.04
abox import dev.abox.tar.gz
```

### Import fails with "instance exists"

The instance name is already in use. Either:
- Remove the existing instance: `abox remove dev`
- Import with a new name: `abox import dev.abox.tar.gz dev-new`

### Large archive size

Use snapshot export if the target has the same base image:
```bash
abox export dev --snapshot
# Creates ~1GB instead of ~5GB for typical Ubuntu instance
```

## See Also

- [VM Access](vm-access.md) - SSH, SCP, port forwarding, and SSHFS mounting
- [Quickstart Guide](quickstart.md) - Get started with abox
