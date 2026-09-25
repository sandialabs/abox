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
| `machine=q35` (pinned) | PCIe topology with native AHCI; drops the legacy i440fx/PIIX3 southbridge (ISA bridge, legacy IDE, ACPI PM) and removes the host-dependent default-machine ambiguity |
| `virtio-non-transitional` devices | Network, RNG, and virtio-serial run modern virtio 1.0 only, dropping the legacy virtio config-plane exposed to guest drivers |

### Network Filtering (L2)

| Measure | Effect |
|---------|--------|
| `no-mac-spoofing` nwfilter | Pins the guest to its assigned MAC; frames with a spoofed source MAC are dropped |
| `no-arp-spoofing` nwfilter | Drops ARP whose sender addresses the guest doesn't own (ARP cache-poisoning defense) |
| STP disabled on bridge | Host-only bridge has no loop/uplink, so spanning-tree is removed as guest-facing (BPDU) attack surface |

The per-instance `abox-<name>-traffic` filter remains a stateful, default-deny
allowlist (inbound: host→guest SSH only; outbound: DNS + HTTP proxy + gateway
ICMP; IPv6 fully dropped). IP-source anti-spoofing is intentionally not layered
on: guests are statically addressed (no DHCP lease for libvirt to learn the IP),
and egress is already destination-pinned to the gateway.

### Operator Session (`abox ssh`)

| Measure | Effect |
|---------|--------|
| `ForwardAgent=no` | Guest root can never use the operator's ssh-agent to sign with keys it cannot read (blocks VM-compromise → credential-theft) |
| `ForwardX11=no` / `ForwardX11Trusted=no` | No X11 channel back to the operator's display (keystroke-injection / screen-capture surface) |

These are set as explicit command-line options, so they override any
`ForwardAgent`/`ForwardX11` the operator may have enabled globally in
`~/.ssh/config`. The `abox forward` tunnel feature (explicit `-L`/`-R`) is
unaffected. Guest-side sshd config is only defense-in-depth here — guest root
could re-enable forwarding — so the client-side setting is the load-bearing one.

### Log Rendering

Traffic and monitor logs contain guest-influenced strings (Tetragon exec
args/paths, DNS query names, HTTP URLs). `abox dns/http/monitor logs` renders
them through a sanitizing writer that strips terminal control bytes (ANSI/OSC
escape sequences, `0x7f`), so a malicious guest cannot spoof or corrupt the
operator's terminal. The on-disk log files stay byte-for-byte faithful for
forensics and machine parsing — only the terminal rendering is sanitized.

### DNS Query Types

In enforcing (active) mode, the DNS filter answers only `A`/`AAAA` queries for
allowlisted names. Every other query type (`TXT`, `MX`, `NS`, `SRV`, `ANY`,
`HTTPS`/`SVCB`, ...) receives an empty `NOERROR` (NODATA) response and is never
forwarded upstream, shrinking the DNS-tunneling/exfiltration surface. Clients
that probe for `HTTPS`/`SVCB` records fall back to `A`/`AAAA` automatically.
Passive (profiling) mode still forwards all query types so allowlist discovery
stays faithful.

### Performance Tuning

| Measure | Effect |
|---------|--------|
| `iothreads=1` | Dedicated I/O thread for disk, reducing vCPU contention |
| Disk: `cache=none`, `io=native` | Host page cache bypassed; direct I/O for lower latency |
| Disk: `detect_zeroes=unmap` | Zero writes converted to TRIM, reclaiming space on thin-provisioned images |
| `kvmclock` timer | Stable paravirtual clock; avoids drift from TSC/HPET |
| vhost multiqueue (`queues=min(vCPUs,4)`) | Spreads network RX/TX across vCPUs via multiple virtio-net queues |

**Note:** If you use a custom domain template via `overrides.libvirt.template` in `abox.yaml`, these host hardening measures are not automatically applied. Your custom template must include them explicitly. See [abox.yaml: Backend Overrides](abox-yaml.md#backend-overrides).

## Host-Side Prerequisites (Operator Responsibility)

Some of the isolation posture depends on host configuration that abox cannot set
or verify from the VM definition. These are the operator's responsibility on the
hypervisor host.

### Speculative-Execution Posture

abox uses `<cpu mode='host-model'>`, so the guest vCPU inherits the host CPU's
microcode-based mitigation flags automatically. To make that meaningful:

- Ensure host microcode is current and exposes `MD_CLEAR` (MDS/MFBS mitigation).
  Verify with `cat /sys/devices/system/cpu/vulnerabilities/*`.
- Disable SMT (hyper-threading) **or** enforce core scheduling so sibling
  threads never co-schedule different security domains — cross-VM sibling
  leakage (L1TF/MDS) is not mitigated by microcode alone.
- Consider a vCPU model without TSX (`hle`/`rtm`) if your workload doesn't need
  it, to remove TAA exposure.

### Unprivileged QEMU and Host Confinement

- Run QEMU as an unprivileged user/group via `user=`/`group=` in
  `/etc/libvirt/qemu.conf`. abox's storage layer assumes this (per-uid setgid
  image dirs — see [privilege-helper.md](privilege-helper.md)) but does **not**
  enforce it; a root-run QEMU widens the blast radius of any escape.
- Enable libvirtd's own seccomp sandbox (`seccomp_sandbox = 1` in `qemu.conf`)
  for defense-in-depth on top of abox's `-sandbox` QEMU flags.
- Keep host AppArmor/SELinux (svirt) confinement of the QEMU process enabled
  (the distro default on Ubuntu/RHEL); abox does not add a per-domain
  `<seclabel>`, so per-VM confinement comes from the host security driver.
- Keep host QEMU/libvirt/kernel patched. abox uses the `vhost` virtio-net
  backend (not slirp), which avoids the userspace slirp escape history.

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
