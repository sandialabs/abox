# Hardening

abox applies host-side hardening automatically to every VM. Guest-level hardening is optional and applied via [provision scripts](provisioning.md).

## Host Hardening

These measures are applied automatically when abox creates a VM. No user configuration is needed.

### VM Isolation

| Measure | Effect |
|---------|--------|
| `nosharepages` | Prevents KSM from merging identical memory pages across VMs (side-channel defense) |
| Nested virt disabled (`vmx`/`svm`) | Prevents guest from running its own hypervisor to escape isolation |
| `on_crash=destroy` | Destroys VM on crash instead of preserving state for inspection |
| QEMU sandbox flags | `obsolete=deny`, `elevateprivileges=deny`, `spawn=deny`, `resourcecontrol=deny` |

### Attack Surface Reduction

| Measure | Effect |
|---------|--------|
| `memballoon=none` | Removes memory balloon device (not needed, eliminates attack surface) |
| `video=none` | No emulated GPU or display |
| USB controller `none` | No USB bus emulated |

### Performance Tuning

| Measure | Effect |
|---------|--------|
| `iothreads=1` | Dedicated I/O thread for disk, reducing vCPU contention |
| Disk: `cache=none`, `io=native` | Host page cache bypassed; direct I/O for lower latency |
| Disk: `detect_zeroes=unmap` | Zero writes converted to TRIM, reclaiming space on thin-provisioned images |
| `kvmclock` timer | Stable paravirtual clock; avoids drift from TSC/HPET |
| vhost multiqueue (`queues=min(vCPUs,4)`) | Spreads network RX/TX across vCPUs via multiple virtio-net queues |

**Note:** If you use a custom domain template via `overrides.libvirt.template` in `abox.yaml`, these host hardening measures are not automatically applied. Your custom template must include them explicitly. See [abox.yaml: Backend Overrides](abox-yaml.md#backend-overrides).

## Guest Hardening

Guest-level hardening is left to you via [provision scripts](provisioning.md), so you can tune settings to your workload.

This section covers recommended hardening for Ubuntu/Debian guests. RHEL-family distros use similar sysctls but different GRUB paths (`grub2-mkconfig -o /boot/grub2/grub.cfg`).

### Sysctl Hardening

Create a provision script (e.g., `harden.sh`):

```bash
#!/bin/bash
set -euo pipefail

# Write sysctl hardening settings
cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
# Hide kernel logs from unprivileged users
kernel.dmesg_restrict=1

# Hide kernel pointers in /proc/kallsyms and dmesg
kernel.kptr_restrict=2

# Disable magic SysRq key
kernel.sysrq=0

# Restrict ptrace to child processes only
kernel.yama.ptrace_scope=1

# Block unprivileged BPF program loading
kernel.unprivileged_bpf_disabled=1

# Harden BPF JIT compiler (blinding constants)
net.core.bpf_jit_harden=2
SYSCTL

sysctl --system
```

Apply it:

```bash
abox provision myvm -s harden.sh
```

Or include it in your `abox.yaml`:

```yaml
provision:
  - harden.sh
```

### GRUB Boot Parameters

Some hardening settings can only be applied at boot time via kernel command-line parameters. These require a reboot to take effect.

```bash
#!/bin/bash
set -euo pipefail

# Write GRUB hardening config
cat > /etc/default/grub.d/99-hardening.cfg << 'GRUB'
GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX vsyscall=none debugfs=off slab_nomerge init_on_alloc=1 page_alloc.shuffle=1 randomize_kstack_offset=on"
GRUB

# Regenerate GRUB config
if command -v update-grub >/dev/null 2>&1; then
    update-grub
elif command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o /boot/grub2/grub.cfg
fi

echo "Reboot required for boot parameters to take effect."
```

What each parameter does:

| Parameter | Effect |
|-----------|--------|
| `vsyscall=none` | Disable legacy vsyscall page (eliminates a known ROP gadget) |
| `debugfs=off` | Disable debugfs (large kernel attack surface) |
| `slab_nomerge` | Prevent slab cache merging (heap exploitation hardening) |
| `init_on_alloc=1` | Zero-fill memory on allocation (~1% perf cost) |
| `page_alloc.shuffle=1` | Randomize page allocator freelists |
| `randomize_kstack_offset=on` | Randomize kernel stack offset per syscall |

### Removing Sudo Access

If your agent only needs to edit code, run tests, and use git, you can remove sudo access to limit the blast radius of a compromise:

```bash
#!/bin/bash
set -euo pipefail

# Remove the user from the sudo group
deluser "$ABOX_USER" sudo 2>/dev/null || true

# Remove the cloud-init NOPASSWD sudoers entry
rm -f /etc/sudoers.d/90-cloud-init-users
```

**Trade-offs:**

- Without sudo, the agent cannot install packages, modify system config, or run Docker (unless the user is in the `docker` group).
- Workflows that typically need sudo: Docker, package installs (`apt`, `pip install --system`), systemd service management.
- Workflows that typically don't: code editing, git operations, running tests, building projects, language-specific package managers (`npm install`, `cargo build`, `pip install --user`).

If you need Docker without sudo, add the user to the `docker` group before removing sudo:

```bash
usermod -aG docker "$ABOX_USER"
deluser "$ABOX_USER" sudo 2>/dev/null || true
rm -f /etc/sudoers.d/90-cloud-init-users
```

### Intentionally Omitted Settings

These settings were considered but excluded due to compatibility or performance concerns:

| Setting | Why omitted |
|---------|-------------|
| `init_on_free=1` | ~5% performance hit; `init_on_alloc=1` covers the most common attack vector |
| `lockdown=confidentiality` | Breaks kernel module loading and container runtimes |
| `kernel.modules_disabled=1` | Breaks package installs that load kernel modules (e.g., installing a VPN client) |
| `kernel.unprivileged_userns_clone=0` | Breaks container runtimes that use unprivileged user namespaces |
