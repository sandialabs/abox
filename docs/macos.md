# macOS Support

abox runs natively on macOS using [vfkit](https://github.com/crc-org/vfkit)
(Apple's Virtualization.framework) as the VM backend, `pfctl` for packet
filtering, and [vmnet-helper](https://github.com/nirs/vmnet-helper) for per-VM
networking. Each VM gets its own isolated vmnet interface (its own `bridgeN`) on
its own `/24`. This document covers installation, first-run behavior, and the
platform-specific differences from the Linux (libvirt) backend.

## Supported Platforms

- **Apple Silicon (arm64)** and **Intel (amd64)** Macs are both supported. abox
  downloads the cloud image matching the host architecture — arm64 images on
  Apple Silicon, amd64 images on Intel — so `abox base pull` and `abox create`
  work the same way on either.

## Installation

### 1. Install Dependencies

abox shells out to a small set of tools, all available via [Homebrew](https://brew.sh):

```bash
brew install vfkit qemu xorriso
```

- **vfkit** — launches the guest via Apple's Virtualization.framework. Must be
  recent enough to support the `--device virtio-net,unixSocketPath=` network
  device (abox connects the guest NIC to vmnet-helper over a unix socket); a
  current Homebrew vfkit is fine. `abox check-deps` prints the installed version.
- **qemu** — provides `qemu-img`, used to convert disk images between qcow2 and
  raw for import/export.
- **xorriso** — builds the cloud-init NoCloud ISO.

`pfctl`, `sudo`, `ssh`, `scp`, `ssh-keygen`, and `tcpdump` ship with macOS.

The `abox mount` command is optional and needs a FUSE + sshfs install that does
not ship with macOS — we recommend the kext-less **fuse-t** (no kernel extension
to approve, no reboot) — see [File Transfer](#file-transfer). You can skip it
unless you plan to mount instance filesystems.

#### vmnet-helper

[vmnet-helper](https://github.com/nirs/vmnet-helper) provides each VM's network
interface and is **required**. Install it per the upstream instructions
(https://github.com/nirs/vmnet-helper) — for example via Homebrew:

```bash
brew tap nirs/vmnet-helper
brew trust nirs/vmnet-helper   # Homebrew 6.0.0+ only: third-party taps must be trusted before install
brew install vmnet-helper
```

The `brew trust` step is required on Homebrew 6.0.0+ (June 2026) and can be
skipped on older versions. To avoid Homebrew entirely, use the upstream install
script instead:

```bash
curl -fsSL https://github.com/nirs/vmnet-helper/releases/latest/download/install.sh | bash
```

vmnet-helper installs **off `PATH`** (into a Homebrew `libexec` directory). abox
locates the binary at the standard install paths automatically; you can override
the location with `ABOX_VMNET_HELPER_PATH=/abs/path/to/vmnet-helper`.

On **macOS 15 and earlier**, vmnet-helper requires root, so abox launches it via
`sudo -n` (non-interactive). To avoid a password prompt on every `abox start`,
add a passwordless sudoers entry pinning the resolved absolute path. **Copy the
exact line `abox check-deps` prints** — it pins the path abox actually executes
(the stable `opt/.../libexec` symlink, not the version-specific `Cellar` path),
so it looks like:

```
<user> ALL=(root) NOPASSWD: /opt/homebrew/opt/vmnet-helper/libexec/vmnet-helper
```

(On an Intel Mac the path is `/usr/local/opt/vmnet-helper/libexec/vmnet-helper`;
if you set `ABOX_VMNET_HELPER_PATH`, the printed line pins that path instead.)
Add it with `sudo visudo`.

On macOS 15 and earlier abox also has to stop the same root-owned helper. An
interactive `abox stop` / `abox remove` / `abox down` prompts once for your
password to terminate it — the same prompt used to tear down the per-instance pf
anchor, so sudo's credential cache means you type it at most once per stop. A
**non-interactive** run (CI, scripts, pipes) cannot prompt: it leaves the helper
best-effort and prints an actionable error asking you to run the command from a
terminal. abox does **not** require a passwordless `sudo kill` entry.

On **macOS 26 and later**, vmnet-helper runs without root, so the sudoers entry
above is not needed and stop never prompts.

> abox connects the guest NIC to vmnet-helper over a **bound unix socket**
> (`vmnet-helper --socket …` ⇄ `vfkit --device virtio-net,unixSocketPath=…`), so
> no file descriptor is passed through `sudo`. That means **no `closefrom_override`
> sudoers change is required** — only the vmnet-helper binary `NOPASSWD` entry above.

Verify everything with:

```bash
abox check-deps
```

### 2. Build and Install abox

```bash
git clone https://github.com/sandialabs/abox.git
cd abox
make install
```

`make install` copies the `abox` binary to `~/.local/bin/`. Ensure that
directory is on your `PATH`.

> **Note:** `make install-helper` (the setuid privilege helper) is Linux-only —
> macOS does not use a setuid helper. See [Privilege Escalation](#privilege-escalation).

### 3. Download a Base Image

```bash
abox base pull ubuntu-24.04
```

The base image is downloaded for the host architecture (arm64 on Apple Silicon,
amd64 on Intel). The vfkit backend then converts the downloaded qcow2 to a raw
image, which is what Apple's Virtualization.framework requires — this conversion
is automatic. AlmaLinux and Debian base images behave the same way.

## First `abox start`

The first `abox start <name>` after installation wires abox's `pfctl` anchors
into the host firewall (subsequent starts do not repeat this):

1. **Edits `/etc/pf.conf`** to add abox's anchor references (see
   [PF Anchor Wiring](#pf-anchor-wiring)).
2. **Uses `sudo`** to run the privileged `pfctl` operations via the privilege
   helper. sudo's credential cache typically suppresses repeat prompts within a
   session.

If any other vmnet-based VM runtime (Docker Desktop, OrbStack, Podman Machine, a
manually launched vfkit/vz VM) is running when abox first reloads the PF ruleset,
it may briefly lose connectivity until restarted. Stopping other VM runtimes
before the first `abox start` on a fresh install avoids this one-time reset.

## Networking

Each abox instance gets its own [vmnet-helper](https://github.com/nirs/vmnet-helper)
process, which owns one vmnet interface — one `bridgeN` on the host — giving
every VM an isolated bridge, the structural analog of libvirt's per-VM bridge on
Linux.

- **Host mode, not shared.** The helper runs in vmnet `host` mode: there is no
  NAT path out of the VM. The host is the VM's gateway, DNS resolver, and HTTP
  proxy, and makes all external connections on the VM's behalf, enforced by
  `pfctl`. This is a stronger sandbox than shared-mode NAT.
- **Deterministic per-VM subnets.** abox allocates each instance its own `/24`
  from the `192.168.128.0/24 … 192.168.254.0/24` host-mode pool and pins
  vmnet-helper to exactly that subnet; the gateway (`.1`) is baked into cloud-init
  before boot. If the pool is fully in use, `abox create` fails with a clear
  "subnet pool exhausted" error rather than reusing an in-use subnet — remove an
  instance to free one.
- **Host-route-aware allocation.** Allocation skips both subnets other abox
  instances already claimed and any `/24` the host already routes elsewhere — a VPN
  split-include route, the host's own LAN, or a leftover bridge — so a fresh VM
  lands on a subnet reachable from the host. The probe is best-effort
  (`route -n get`) and fail-open, so it never blocks `create`. If you force a
  colliding subnet with `--subnet`, `abox create` warns but proceeds. A collision
  that slips through looks like: the VM boots and guest egress works (DNS/HTTP
  filter see traffic) but host-to-guest SSH/mount time out. Inspect with
  `netstat -rn` / `route -n get <gateway>` and pick a non-conflicting `--subnet`
  (or disconnect the VPN).
- **VM-to-VM isolation is automatic.** The per-instance `pfctl` rules
  default-deny everything from the VM except gateway traffic, which inherently
  blocks one VM from reaching another.

## PF Anchor Wiring

abox installs per-instance `pfctl` rules into sub-anchors named `abox/<instance>`.
The kernel only evaluates those rules if `/etc/pf.conf` references the abox
anchors. On first start, abox inserts the references adjacent to Apple's default
markers:

```
rdr-anchor "com.apple/*"
rdr-anchor "abox/*"        # <- inserted by abox (translation section)
...
anchor "com.apple/*"
anchor "abox/*"            # <- inserted by abox (filter section)
```

The placement next to the Apple markers is deliberate: `pfctl` rejects rulesets
whose sections are out of order (options, normalization, queueing, translation,
filtering), and the Apple markers anchor each section.

### Custom or MDM-Managed pf.conf

If `/etc/pf.conf` does not contain the standard `rdr-anchor "com.apple/*"` and
`anchor "com.apple/*"` lines (the file has been customized, replaced by a site
policy, or managed by MDM), abox refuses to edit it. Add the two references
manually in the correct sections:

```
# In the translation section:
rdr-anchor "abox/*"

# In the filter section:
anchor "abox/*"
```

### Removing the Anchors

`abox teardown-pf` removes the abox anchor references from `/etc/pf.conf`. It is
safe to run multiple times and no-ops when no abox lines are present. Run it
before deleting the `abox` binary if you want to leave `/etc/pf.conf` clean:

```bash
abox teardown-pf
rm ~/.local/bin/abox
```

## Privilege Escalation

On macOS, abox uses `sudo` to launch the privilege helper for operations that
require root (chiefly `pfctl`). There is no setuid `abox-helper`:
`make install-helper` is Linux-only and `/usr/local/bin/abox-helper` is never
installed on macOS.

The underlying gRPC privilege server and its security boundary (token
authentication, UID checking, allowed-command validation) are identical to the
Linux implementation — only the launch mechanism differs. See
[Privilege Helper](privilege-helper.md) for details on the gRPC protocol.

## macOS-Specific Limitations

| Feature | Status on macOS | Reason |
|---------|----------------|--------|
| Snapshots (`abox snapshot …`) | Not supported | vfkit has no native snapshot support |
| Monitor / Tetragon events | Not supported | Tetragon relies on eBPF, which is Linux-only |
| `abox mount` / `abox unmount` | Supported (extra deps) | Work via SSHFS; recommend the kext-less `fuse-t` + `fuse-t-sshfs` (see [File Transfer](#file-transfer)) |
| libvirt / nwfilter | Not used | Replaced by vfkit + vmnet-helper + pfctl |
| Setuid privilege helper | Not available | macOS uses sudo only |

`abox.yaml` with `monitor.enabled: true` is not usable on macOS — the vfkit
backend provides no monitor transport, so no Tetragon events are streamed.

### File Transfer

`abox scp` works out of the box for copying files between the host and the VM.

`abox mount`/`abox unmount` also work on macOS, but need a FUSE + `sshfs` install
that does not ship with the OS. We recommend **[fuse-t](https://www.fuse-t.org/)**
— a kext-less FUSE implementation that bridges to a local NFS server instead of a
kernel extension, so there is **no System Extension to approve and no reboot**
(unlike macFUSE, which requires enabling a kernel extension in **System Settings →
Privacy & Security**, a reboot, and *Reduced Security* mode on Apple Silicon):

```bash
brew tap macos-fuse-t/homebrew-cask
brew install fuse-t
brew install fuse-t-sshfs
```

Mounting then works the same as on Linux:

```bash
abox mount add dev ~/mnt/dev      # mount the guest home directory
abox mount remove ~/mnt/dev       # unmount (or: abox unmount ~/mnt/dev)
abox unmount -f ~/mnt/dev         # force unmount a busy volume
```

> **fuse-t note:** if directory listings under a mount fail with "Operation not
> permitted," enable **System Settings → Privacy & Security → Files and Folders →
> Network Volumes** for your terminal.

`abox check-deps` reports `sshfs` as an optional dependency on macOS and prints
these install commands when it is missing. One platform difference: `-f`/`--force`
performs a lazy unmount on Linux (`fusermount -z`) but a hard `diskutil unmount
force` on macOS, which has no lazy-unmount equivalent.

The older **macFUSE** stack (`brew install --cask macfuse` +
`brew install gromgit/fuse/sshfs-mac`) also works if you already have it, but the
kernel extension is the permission hassle fuse-t avoids. If you would rather not
install any FUSE, use `abox scp` instead.

## Export and Import

The vfkit backend stores instance disks as **raw** images, which have no
backing-file or copy-on-write-delta concept. As a result:

- **`abox export --snapshot` is not supported on macOS.** Snapshot mode exports
  only the CoW delta against a base image, which raw disks cannot produce. abox
  rejects `--snapshot`/`-s` with a message asking you to export a full,
  self-contained archive instead (the default). Full archives are portable and
  do not require the base image on the target machine.

- **Snapshot archives produced on Linux cannot be imported on macOS.** A Linux
  `--snapshot` archive is a qcow2 that references a separate base image. `abox
  import` detects that backing-file reference up front and fails with guidance to
  re-export the instance as a full archive (without `--snapshot`) and import that.

Full (non-snapshot) archives move freely in both directions between Linux and
macOS. See [Export & Import](export-import.md) for the full workflow.

## Storage Layout

abox uses the same XDG-based layout on macOS as on Linux — there is no
`/var/lib/libvirt/images` equivalent, and disk images live under your home
directory so disk operations run unprivileged:

| Path | Content |
|------|---------|
| `~/.local/share/abox/base/` | Downloaded base images (`abox base pull`) |
| `~/.local/share/abox/disks/base/` | Backend base images (raw, converted for vfkit) |
| `~/.local/share/abox/disks/instances/<name>/` | Per-instance raw disk and cloud-init ISO |
| `~/.local/share/abox/instances/<name>/` | Per-instance config (`config.yaml`), SSH keys, allowlist, logs |

(`XDG_DATA_HOME`, if set, replaces `~/.local/share`.)

## See Also

- [Quickstart Guide](quickstart.md) — general workflow (platform-neutral)
- [System Requirements](requirements.md) — dependency details
- [Support Matrix](support-matrix.md) — OS × backend × capability table
- [Troubleshooting](troubleshooting.md) — log locations and error states
- [Filtering](filtering.md) — DNS/HTTP filtering architecture
- [Privilege Helper](privilege-helper.md) — privilege escalation model
- [Export & Import](export-import.md) — moving instances between machines
