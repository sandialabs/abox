# System Requirements

This document details the system requirements and dependencies for running abox.

## Supported Operating Systems

Abox is tested on:

- **Ubuntu 22.04+** (LTS recommended)
- **Debian 13+** (Trixie and newer)
- **Fedora 38+**
- **Arch Linux** (rolling release)

Other Linux distributions with libvirt 8.0+ and QEMU 6.0+ should work.

## Required Software

### Build Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Go | 1.25+ | Building the abox binary |

### Runtime Dependencies

| Tool | Required | Package (Debian/Ubuntu) | Package (Fedora) | Used For |
|------|----------|------------------------|------------------|----------|
| virsh | Yes | libvirt-clients | libvirt | All VM/network operations |
| qemu-img | Yes | qemu-utils | qemu-img | Disk creation, base images |
| qemu-system-x86_64 | Yes | qemu-system-x86 | qemu-kvm | VM execution |
| ssh | Yes | openssh-client | openssh-clients | SSH access to VMs |
| scp | Yes | openssh-client | openssh-clients | File transfers |
| ssh-keygen | Yes | openssh-client | openssh-clients | SSH key generation |
| iptables | Yes | iptables | iptables | DNS redirect rules |
| pkexec | Yes* | policykit-1 | polkit | Privilege escalation |
| sudo | Yes* | sudo | sudo | Privilege escalation (fallback) |
| sshfs | Yes | sshfs | sshfs | Mount command |
| fusermount | Yes | fuse3 | fuse3 | Unmount command |
| genisoimage | Yes** | genisoimage | cdrkit | Cloud-init ISO creation |
| xorriso | Yes** | xorriso | xorriso | Cloud-init ISO creation |
| tcpdump | No | tcpdump | tcpdump | Packet capture (tap command) |

*At least one of pkexec or sudo is required.
**At least one of genisoimage or xorriso is required.

### Check Dependencies

Use the built-in dependency checker:

```bash
abox check-deps
```

Output shows status of each dependency:

```
Checking dependencies...
  virsh        ok
  qemu-img     ok
  ssh          ok
  scp          ok
  sshfs        ok
  ssh-keygen   ok
  genisoimage  ok
  xorriso      missing (optional, needed for 'create (cloud-init ISO, required if genisoimage not installed)')
  pkexec       ok
  sudo         ok
  iptables     ok
  fusermount   ok
  tcpdump      ok

  libvirt group: member
  libvirt-qemu/kvm group: member
  libvirt images access: ok

All required dependencies are installed.
```

## Installation Commands

### Debian/Ubuntu

```bash
# Required packages
sudo apt install \
  libvirt-daemon-system \
  libvirt-clients \
  qemu-kvm \
  qemu-utils \
  openssh-client \
  iptables \
  sshfs \
  fuse3 \
  genisoimage

# Add user to libvirt group
sudo usermod -aG libvirt $USER
```

### Fedora

```bash
# Required packages
sudo dnf install \
  libvirt \
  libvirt-client \
  qemu-kvm \
  qemu-img \
  openssh-clients \
  iptables \
  sshfs \
  fuse3 \
  genisoimage

# Add user to libvirt group
sudo usermod -aG libvirt $USER

# Start libvirtd
sudo systemctl enable --now libvirtd
```

### Arch Linux

```bash
# Required packages
sudo pacman -S \
  libvirt \
  qemu-full \
  openssh \
  iptables \
  sshfs \
  cdrkit

# Add user to libvirt group
sudo usermod -aG libvirt $USER

# Start libvirtd
sudo systemctl enable --now libvirtd
```

## User Configuration

### libvirt Group Membership

For abox to manage VMs without constant privilege escalation, add your user to the libvirt group:

```bash
sudo usermod -aG libvirt $USER
```

**Important:** Log out and back in for the group change to take effect. Verify with:

```bash
groups | grep libvirt
```

If not in the libvirt group, abox will use pkexec or sudo for virsh commands, which may prompt for passwords.

### Polkit Configuration (Optional)

To avoid password prompts when not in the libvirt group, create a polkit rule:

`/etc/polkit-1/rules.d/50-libvirt.rules`:
```javascript
polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage" &&
        subject.isInGroup("libvirt")) {
        return polkit.Result.YES;
    }
});
```

## Hardware Requirements

### Minimum

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU cores | 2 | 4+ |
| RAM | 4 GB | 8 GB+ |
| Disk | 20 GB free | 50 GB+ free |
| Virtualization | VT-x or AMD-V | Required |

### CPU Virtualization

Verify virtualization support:

```bash
# Check CPU flags
lscpu | grep Virtualization

# Should show: VT-x (Intel) or AMD-V (AMD)
```

If virtualization is not shown:
1. Enable VT-x/AMD-V in BIOS/UEFI settings
2. Ensure you're not running inside another VM (nested virtualization)

### Disk Space

Each instance uses:
- **Base image:** ~600 MB - 2 GB (shared, copy-on-write)
- **Instance disk:** Up to the configured size (default 20 GB)
- **Snapshots:** Variable, depends on changes from snapshot point

The default disk uses qcow2 with copy-on-write, so actual space usage grows only as data is written.

## Known Compatibility Issues

### WSL2

Abox does not work in WSL2:
- WSL2 does not support KVM/nested virtualization
- libvirt is not available in WSL

**Workaround:** Run abox on a native Linux system or a Linux VM with nested virtualization enabled.

### VirtualBox Conflict

Running abox inside a VirtualBox VM requires:
1. Nested VT-x/AMD-V enabled in VirtualBox settings
2. Host CPU must support nested virtualization

Note: Performance will be significantly reduced.

### Docker Desktop

Docker Desktop for Linux may conflict with libvirt networking. If you experience issues:
1. Stop Docker Desktop when using abox
2. Or use Docker Engine instead of Docker Desktop

### Secure Boot

If Secure Boot is enabled and KVM modules aren't signed:
1. Sign the modules yourself
2. Or disable Secure Boot in BIOS/UEFI
3. Or use the `modprobe` approach with MOK (Machine Owner Key)

### Debian 11/12 Cloud Images

Debian 11 (Bullseye) and Debian 12 (Bookworm) cloud images have broken network initialization under libvirt/QEMU. The guest VM never sends any network traffic — no DHCP requests, no ARP — resulting in "No route to host" errors. Diagnostics confirmed empty DHCP leases, `FAILED` ARP entries, and no nwfilter interference during the boot window. The root cause is suspected to be pre-baked network configuration in the Debian cloud images that conflicts with cloud-init's NoCloud network-config. Debian 13 (Trixie) and newer work correctly. Abox only offers Debian 13+ as base images.

## Network Requirements

### Host Networking

Abox creates isolated bridge networks for each instance. This requires:
- iptables for NAT and DNS redirection
- Bridge networking support in the kernel (usually built-in)

### Firewall Configuration

If using a firewall (ufw, firewalld), you may need to allow libvirt traffic:

**UFW:**
```bash
sudo ufw allow in on virbr0
sudo ufw allow in on abox-*
```

**Firewalld:**
```bash
sudo firewall-cmd --add-interface=virbr0 --zone=libvirt --permanent
sudo firewall-cmd --reload
```

## Version Compatibility

### Minimum Versions

| Component | Minimum Version |
|-----------|----------------|
| libvirt | 8.0 |
| QEMU | 6.0 |
| Linux kernel | 5.4 |

### Checking Versions

```bash
# libvirt version
virsh --version

# QEMU version
qemu-system-x86_64 --version

# Kernel version
uname -r
```

## See Also

- [Quickstart Guide](quickstart.md) - Get started with abox
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
