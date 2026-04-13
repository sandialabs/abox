# VM Access

This document covers connecting to and interacting with abox instances: SSH sessions, file transfer, and port forwarding.

## SSH

Connect to a running instance with an interactive shell or run commands directly.

### Interactive Shell

```bash
abox ssh dev
```

### Run Commands

Use `--` to separate the instance name from the command:

```bash
abox ssh dev -- ls -la
abox ssh dev -- 'cat /etc/os-release'
abox ssh dev -- sudo apt update
```

### How It Works

- Uses the instance's auto-generated SSH key (`~/.local/share/abox/instances/<name>/id_ed25519`)
- Connects to the VM's IP on the isolated bridge network
- Replaces the current process with SSH (clean terminal handling)

## File Transfer (SCP)

Copy files between your host and the VM using `abox scp`.

### Host to VM

```bash
# Copy a single file
abox scp ./script.sh dev:

# Copy a directory recursively
abox scp -r ./myproject dev:

# Copy with preserved modification times
abox scp -p ./data.csv dev:/tmp/
```

### VM to Host

```bash
# Copy a file from the VM
abox scp dev:/var/log/app.log ./

# Copy a directory from the VM
abox scp -r dev:output ./results/
```

### Flags

| Flag | Description |
|------|-------------|
| `-r, --recursive` | Copy directories recursively |
| `-p, --preserve` | Preserve modification times |

### Path Format

Use `<instance>:<path>` for VM paths:
- `dev:/var/log/app.log` - Absolute path on VM
- `dev:myfile.txt` - Relative to home directory
- `./local-file.txt` - Local path (no colon)

## Port Forwarding

Expose VM services on your host using SSH tunnels. Useful for accessing web servers, databases, or development servers running in the VM.

### Add a Forward

```bash
# Forward host:8080 → VM:80 (access VM's web server at localhost:8080)
abox forward add dev 8080:80

# Forward matching ports (Node.js dev server)
abox forward add dev 3000:3000

# Forward multiple ports
abox forward add dev 5432:5432    # PostgreSQL
abox forward add dev 6379:6379    # Redis
```

### Reverse Port Forwarding

Allow the VM to access services running on your host:

```bash
# VM can access host:8000 at localhost:8000
abox forward add dev 8000:8000 -R

# VM accesses host's database
abox forward add dev 5432:5432 --reverse
```

Reverse forwards use SSH remote port forwarding (`ssh -R`). The guest port is bound inside the VM, forwarding connections back to the host port.

### List Active Forwards

```bash
abox forward list dev
```

Output:
```
HOST   GUEST  DIRECTION   STATUS
8080   80     host→guest  running
3000   3000   host→guest  running
```

### Remove a Forward

```bash
# Remove by host port
abox forward remove dev 8080

# Shorthand
abox forward rm dev 3000
```

### Restart Forwards

Restart inactive or failed forwards:

```bash
# Restart all inactive forwards for an instance
abox forward restart dev

# Restart a specific forward by host port
abox forward restart dev 8080
```

### How It Works

Port forwards use SSH tunneling. Each forward runs as a background SSH process:

- **Local forwards** (`abox forward add dev 8080:80`) use `ssh -L` — connections to `localhost:8080` on your host are tunneled to the VM's port 80
- **Reverse forwards** (`abox forward add dev 8000:8000 -R`) use `ssh -R` — the VM can connect to `localhost:8000` which tunnels back to your host's port 8000

The SSH tunnel runs in the background until removed or the instance stops.

### Use Cases

**Web Development:**
```bash
# In VM: python -m http.server 8000
abox forward add dev 8000:8000
# Access at http://localhost:8000
```

**Database Access:**
```bash
abox forward add dev 5432:5432
psql -h localhost -p 5432 -U postgres
```

**API Development:**
```bash
# Forward your API server
abox forward add dev 3000:3000

# Access from host
curl http://localhost:3000/api/health
```

## Mounting Filesystems (SSHFS)

For more seamless file access, mount the VM's filesystem on your host.

### Mount

```bash
# Mount VM home directory
abox mount dev ~/mnt/dev

# Mount a specific path
abox mount dev:/var/log ~/mnt/logs

# Mount read-only
abox mount --read-only dev ~/mnt/dev

# Allow other users to access the mount
abox mount --allow-other dev ~/mnt/dev
```

### Unmount

```bash
# By mount path
abox unmount ~/mnt/dev

# By instance name (unmounts all mounts for that instance)
abox unmount dev

# Unmount all abox mounts across all instances
abox unmount --all
```

### Requirements

SSHFS must be installed on your host:

```bash
# Debian/Ubuntu
sudo apt install sshfs

# Fedora
sudo dnf install sshfs

# Arch
sudo pacman -S sshfs
```

## Troubleshooting

### "Connection refused" on SSH

The instance may not be running or still booting:

```bash
abox status dev
# Wait for "running" status, then try again
```

### Port forward not working

Check if the service is running in the VM:

```bash
abox ssh dev -- ss -tlnp
```

Verify the forward is active:

```bash
abox forward list dev
```

### SCP permission denied

Use sudo for system paths:

```bash
abox ssh dev -- sudo cp /etc/config ./
abox scp dev:config ./
```

Or copy to home first:

```bash
abox ssh dev -- 'sudo cp /etc/nginx/nginx.conf ~/'
abox scp dev:nginx.conf ./
```

For more troubleshooting help, see [Troubleshooting Guide](troubleshooting.md).
