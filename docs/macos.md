# macOS Support

abox runs natively on macOS (Apple Silicon) using [vfkit](https://github.com/crc-org/vfkit) as the VM backend, `pfctl` for packet filtering, and macOS's built-in `vmnet` framework for networking. This document covers installation, first-run behavior, and platform-specific notes that differ from the Linux backend.

## Supported Platforms

- **macOS 13+ on Apple Silicon (arm64).** Intel Macs are not supported — Apple's Virtualization.framework only runs native arm64 guests, and the image providers download arm64 cloud images on macOS.

## Installation

### 1. Install Dependencies

abox shells out to a small set of tools, all available via [Homebrew](https://brew.sh):

```bash
brew install vfkit qemu xorriso
```

For `abox mount` (optional — SSHFS-based VM filesystem mounting):

```bash
brew install --cask macfuse
brew install gromgit/fuse/sshfs-mac
```

`pfctl`, `sudo`, `ssh`, `scp`, `ssh-keygen`, and `tcpdump` ship with macOS.

Verify with:

```bash
abox check-deps
```

### 2. Build and Install abox

```bash
git clone https://github.com/sandialabs/abox.git
cd abox
make install
```

`make install` copies the `abox` binary to `~/.local/bin/`. Ensure that directory is on your `PATH`.

**Note:** `make install-helper` is Linux-only. macOS does not use a setuid helper — see [Privilege Escalation](#privilege-escalation) below.

### 3. Download a Base Image

```bash
abox base pull ubuntu-24.04
```

On macOS this downloads the **arm64** variant of the cloud image. Other providers (AlmaLinux, Debian) behave the same way. x86_64 base images imported manually will not boot on Apple Silicon.

## First `abox start`

The very first `abox start <name>` after installation does three extra things that subsequent starts do not:

1. **Prompts for sudo** to launch the privilege helper (used for every `pfctl` operation). The helper stays running until the last instance stops, so you typically see the sudo prompt once per session.
2. **Edits `/etc/pf.conf`** to wire abox's anchor references into the main PF ruleset (see [PF Anchor Wiring](#pf-anchor-wiring)). abox prints a one-line notice when it does this.
3. **Reloads the main PF ruleset** via `pfctl -f /etc/pf.conf`. This can briefly disrupt other vmnet-based VMs — see the warning below.

### One-Time Network Disruption Warning

The first `pfctl -f /etc/pf.conf` discards in-memory rules that vmnet installs at runtime. If any of the following are running at the moment of your first `abox start`, they may lose network connectivity until restarted:

- Docker Desktop
- OrbStack
- Podman Machine
- Any other `abox` instance already started (very unlikely on first run)
- A manually launched `vfkit`/`vz` VM

**Recommendation:** stop other VM runtimes before the first `abox start` on a fresh install, or accept a one-time reset and restart them afterwards. Subsequent `abox start` invocations do not reload the main ruleset and do not risk this disruption.

## PF Anchor Wiring

abox installs per-instance `pfctl` rules into sub-anchors named `abox/<instance>`. The kernel only evaluates those rules if `/etc/pf.conf` contains two matching anchor references. On first start, abox inserts them adjacent to Apple's default markers:

```
rdr-anchor "com.apple/*"
rdr-anchor "abox/*"        # <- inserted by abox (translation section)
...
anchor "com.apple/*"
anchor "abox/*"            # <- inserted by abox (filter section)
```

The placement next to the Apple markers is deliberate: `pfctl` rejects rulesets whose sections are out of order (options, normalization, queueing, translation, filtering), and the Apple markers anchor each section.

### Custom or MDM-Managed pf.conf

If `/etc/pf.conf` does not contain the standard `rdr-anchor "com.apple/*"` and `anchor "com.apple/*"` lines (the file has been customized, replaced by a site policy, or managed by MDM), abox refuses to edit it and reports an error. Add the two lines manually:

```
# In the translation section:
rdr-anchor "abox/*"

# In the filter section:
anchor "abox/*"
```

The translation section precedes the filter section; keep each abox anchor in the correct section to avoid `pfctl` load errors. After adding them, `abox start` will proceed.

### Checking Wiring Status

`abox doctor` reports the wiring state as part of its host checks:

```bash
abox doctor <instance>
```

The PF anchors check distinguishes three outcomes:

| State | Meaning |
|-------|---------|
| Passed | Both anchor references are present in `/etc/pf.conf` |
| Missing, auto-wire available | Apple markers are present; next `abox start` will wire the references automatically |
| Missing, custom pf.conf | Apple markers are absent; add the references manually (see above) |

## Uninstallation

Uninstalling leaves `/etc/pf.conf` unchanged unless you explicitly tear the anchor references back out. `make uninstall` does this for you:

```bash
make uninstall
```

This calls `abox teardown-pf` (best-effort) before removing the binary from `~/.local/bin/`. If you remove the binary manually (e.g. `rm ~/.local/bin/abox`), the anchor references remain in `/etc/pf.conf`. Run the teardown command yourself before deletion:

```bash
abox teardown-pf
rm ~/.local/bin/abox
```

`abox teardown-pf` is safe to run multiple times and no-ops when no abox lines are present.

## Privilege Escalation

On macOS, abox uses `sudo` to launch the privilege helper. There is no setuid `abox-helper` equivalent: `make install-helper` is Linux-only (enforced by the Makefile), and `/usr/local/bin/abox-helper` is never installed.

The underlying gRPC privilege server and its security boundary (token authentication, UID checking, allowed-command validation) are identical to the Linux implementation — only the launch mechanism differs. See [Privilege Helper](privilege-helper.md) for details on the gRPC protocol.

## macOS-Specific Limitations

| Feature | Status on macOS | Reason |
|---------|----------------|--------|
| Snapshots (`abox snapshot …`) | Not supported | vfkit has no native snapshot support |
| Monitor / Tetragon events | Not supported | Tetragon relies on eBPF, which is Linux-only |
| libvirt / nwfilter | Not used | Replaced by vfkit + vmnet + pfctl |
| Setuid privilege helper | Not available | macOS uses sudo only |
| x86_64 guests | Not supported | Apple Silicon only; arm64 base images |

The `abox.yaml` `monitor.enabled: true` field is rejected at `abox start` time with a clear error on macOS.

## Storage Layout

Base images and instance data live under your home directory (no `/var/lib/libvirt/images` equivalent):

| Path | Content |
|------|---------|
| `~/Library/Application Support/abox/images/` | Base images (raw format, used directly by vfkit) |
| `~/.local/share/abox/instances/<name>/` | Per-instance config, keys, disk, logs |
| `~/Library/Caches/abox/filters/` | Filter marker files (`<filter>.applied`) |

Instance disks are raw-format APFS clones (`cp -c`) of the base image — effectively copy-on-write with no runtime overhead.

## See Also

- [Quickstart Guide](quickstart.md) — general workflow (platform-neutral)
- [System Requirements](requirements.md#macos) — dependency details
- [Troubleshooting](troubleshooting.md#macos-specific-issues) — macOS error states
- [Filtering](filtering.md) — DNS/HTTP filtering architecture
- [Privilege Helper](privilege-helper.md) — privilege escalation model
