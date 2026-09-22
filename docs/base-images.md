# Base Images

A **base image** is the disk image an instance is created from — a cloud image of
a Linux distribution (Ubuntu, Debian, AlmaLinux) plus whatever you bake into it.
Every instance's disk starts from a base; abox then customizes it at boot with a
static IP, SSH key, and hostname.

This page covers managing bases, what an image must satisfy to work as an abox
base, and how to **create your own custom base** with tools pre-installed.

## Managing bases

```bash
# List available images (remote catalog + locally downloaded)
abox base list

# Download an official cloud image
abox base pull ubuntu-24.04

# Import a local image as a base (see "Creating a custom base" below)
abox base import my-base ./my-image.qcow2

# Remove a downloaded/imported base (alias: rm)
abox base remove my-base

# Remove all unused images and stale instances
abox prune -n     # preview
abox prune -f     # apply
```

Downloaded and imported bases live in `~/.local/share/abox/base/`. Each backend
also keeps a converted copy in its own store (see
[Platform / backend differences](#platform--backend-differences)).

Select a base for an instance with `--base` on `abox create`, or `base:` in
`abox.yaml`:

```bash
abox create dev --base my-base
```

```yaml
base: my-base
```

## What a valid base image must satisfy

If you bring your own image, it must meet these requirements or instances built
from it will fail to boot or be unreachable:

- **Cloud-init capable (NoCloud datasource).** abox has no DHCP server on its
  host-only networks — it injects the static IP, SSH key, and hostname at boot
  through a generated `cidata.iso`. An image with cloud-init removed will boot
  with no network and no SSH access. Official distro cloud images qualify; desktop
  ISOs and hand-built images without cloud-init do not.
- **Self-contained.** No backing file and no external VMDK extents. `abox base
  import` inspects the source by content and rejects images that reference other
  files. If you are capturing a running instance's disk, **flatten it first** (see
  below).
- **Any qemu-img-readable input format** — qcow2, raw, or a self-contained VMDK.
  On import abox converts to the host's native base format automatically (qcow2 on
  Linux, raw on macOS).
- **A recognized name prefix, or an explicit user.** The default SSH user is
  derived from the base *name prefix*: `almalinux-*` → `almalinux`, `rocky-*` →
  `cloud-user`, `centos-*` → `centos`, `debian-*` → `debian`, and everything else
  (including custom names like `my-toolbox`) → `ubuntu`. If your image's default
  account doesn't match, either name the base with a matching prefix or set the
  user explicitly with `--user` / `user:` in `abox.yaml`.

## Bake a base vs. provision at boot

You often don't need a custom base at all. abox can run **provision scripts**
inside a stock image at first boot (`provision:` in `abox.yaml`, or
`abox provision`). See [Provisioning](provisioning.md).

| Use provisioning when… | Bake a custom base when… |
|---|---|
| Setup is small or changes often | The same heavy toolchain is reused across many instances |
| You want the setup in version control alongside the project | You want fast, repeatable starts without re-running installs |
| Per-instance differences matter | You need instances to work offline / without downloading packages |

Provisioning is simpler and more transparent; a baked base trades that for speed
and reproducibility. Many setups use both — a base with the heavy toolchain, plus
a small provision script for project-specific bits.

## Creating a custom base

There are three practical ways to produce a base. All of them end with
`abox base import`.

### 1. Boot & capture (abox-native)

The most direct path, using only abox and `qemu-img`. **This flow is written for
Linux/libvirt** — see the [platform notes](#platform--backend-differences) for
macOS and VMware, where the capture step differs.

```bash
# 1. Start from a stock cloud image
abox base pull ubuntu-24.04
abox create builder --base ubuntu-24.04
abox start builder

# 2. Install your tools (interactively, or via a provision script)
abox ssh builder
#   inside the VM:
#     sudo apt-get update && sudo apt-get install -y <your tools>
#     ...

# 3. Reset instance identity so each future instance regenerates its own.
#    Run these inside the VM before shutting down:
#      sudo cloud-init clean --logs
#    For a base you'll reuse widely, also clear the machine-id and SSH host keys
#    (abox does not delete host keys at boot, so they would otherwise be shared
#    by every instance):
#      sudo truncate -s 0 /etc/machine-id
#      sudo rm -f /etc/ssh/ssh_host_*

# 4. Shut the instance down
abox stop builder
```

Now flatten the instance's copy-on-write disk into a self-contained image and
import it. The instance disk is a qcow2 overlay whose backing file is the base, so
it must be flattened before import (import rejects backing-file images):

```bash
# Locate the instance disk. On Linux it lives under the per-user libvirt storage
# root (uid-scoped); use `abox config view builder` or the storage-layout notes
# in docs/troubleshooting.md rather than assuming a fixed path.
qemu-img convert -O qcow2 <instance-disk.qcow2> ./my-base.qcow2

abox base import my-base ./my-base.qcow2
```

You can then delete the throwaway instance (`abox remove builder`) and create
instances from `my-base`.

### 2. virt-customize / virt-builder (libguestfs)

Edit a downloaded cloud image **offline, without booting it**, then import:

```bash
virt-customize -a ubuntu-24.04.qcow2 \
  --install git,build-essential \
  --run-command 'npm install -g @anthropic-ai/claude-code'
abox base import my-base ./ubuntu-24.04.qcow2
```

This is fast and scriptable but adds a **libguestfs** dependency that abox does
not otherwise require (it is not listed in [Requirements](requirements.md)). See
the [libguestfs / virt-customize documentation](https://libguestfs.org/virt-customize.1.html).

### 3. Packer (reproducible / CI builds)

For versioned, CI-friendly bases, build with Packer's QEMU builder, output a
self-contained qcow2, and import the result with `abox base import`. See the
[Packer QEMU builder documentation](https://developer.hashicorp.com/packer/integrations/hashicorp/qemu).

### Note: base import vs. instance export/import

`abox base import` registers a reusable **base**. This is different from
`abox export` / `abox import`, which move one **specific instance** between
machines (see [Export & Import](export-import.md)). To publish something others
create instances from, build a base with one of the methods above — not an
instance export.

## Verify a custom base

```bash
abox create test --base my-base
abox start test
abox ssh test        # confirm it's reachable and your tools are present
```

If the instance never becomes reachable, the most common cause is a base without
a working cloud-init NoCloud datasource. See
[Troubleshooting](troubleshooting.md) for "base image not found" and boot-hang
guidance.

## Platform / backend differences

Base handling spans **two independent axes** — keep them separate:

- **The stored base format follows the HOST OS, not the backend.** `abox base
  import` writes qcow2 on a Linux host and raw on a macOS host. It never writes
  vmdk.
- **The instance disk model — and any vmdk conversion — is a BACKEND concern.**
  The VMware backend converts the stored base to vmdk later, on the first
  instance-create, not at import time.

| Aspect | libvirt (default) | vfkit | vmware (experimental) |
|---|---|---|---|
| Typical host OS | Linux | macOS | Linux / macOS / Windows |
| `abox base import` stores base as | qcow2 | raw | qcow2 or raw — follows the host OS, **not** vmdk |
| Backend base format at create | qcow2 (same file) | raw (same file) | vmdk, converted from the stored qcow2/raw on first create |
| Instance disk model | qcow2 copy-on-write overlay on the base | standalone raw APFS clone (`disk.img`), no backing file | full standalone VMDK copy, no backing file |
| Boot-&-capture: flatten needed? | **yes** — `qemu-img convert -O qcow2` before import | no — `disk.img` is already standalone; import it directly | no — the instance VMDK is standalone; import it directly |

Storage layout is the same shape everywhere; only the backend store's root
differs:

- **User cache** (downloads and the `abox base import` destination):
  `~/.local/share/abox/base/` on every platform.
- **Backend store** (converted copy the VM actually boots from): uid-scoped under
  the per-user libvirt storage root for libvirt (e.g.
  `/var/lib/libvirt/images/abox/<uid>/base/`), and
  `~/.local/share/abox/disks/base/` for vfkit and vmware.

Other notes:

- **Portability is at the source-image level, not the on-disk format.** A qcow2
  base you build on Linux imports cleanly on a macOS host (re-converted to raw)
  and works under VMware (converted to vmdk at create) — import always
  re-converts to the host's native format.
- **Import format acceptance differs by path.** `abox base import` accepts any
  qemu-img-readable source. The VMware backend's *instance* disk import is
  stricter, restricting non-VMDK sources to qcow2 — that limit applies to
  instance imports, not to base imports.
- On macOS, the APFS clone used for instance disks falls back to a full copy on
  non-APFS volumes. See [macOS Support](macos.md).
- VMware is experimental and selected with `ABOX_BACKEND=vmware`. See
  [VMware Backend](vmware.md).

For a full capability matrix across backends, see the
[Support Matrix](support-matrix.md).
