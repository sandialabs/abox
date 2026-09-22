# Backend Support Matrix

abox drives VMs through a pluggable **backend** (see the capability seams in
`internal/backend/backend.go`). Each backend targets a different host OS and
hypervisor, and each implements a different subset of abox's optional
capabilities. This page consolidates the OS × backend × capability information
that is otherwise spread across [Requirements](requirements.md),
[macOS Support](macos.md), and the [VMware backend](vmware.md) docs.

The three backends are:

| Backend | Host OS | Hypervisor | Status |
|---------|---------|------------|--------|
| **libvirt** | Linux | QEMU/KVM via libvirt | Default, fully supported |
| **vfkit** | macOS | Apple Virtualization.framework via vfkit | Default on macOS, supported |
| **vmware** | Linux / macOS / Windows | VMware Workstation Pro / Fusion via `vmrun` | Experimental (opt-in via `ABOX_BACKEND=vmware`) |

## Capability Matrix

Legend: ✅ supported · ❌ not supported · ✅\* implemented but **experimental —
unvalidated on a real host** (see notes).

| Capability | libvirt (Linux) | vfkit (macOS) | vmware (experimental) |
|------------|:---------------:|:-------------:|:---------------------:|
| VM / disk lifecycle | ✅ | ✅ | ✅\* |
| Network lifecycle | ✅ | ✅ | ✅\* Linux · ⚠️ macOS `TODO(real-host)` <sup>[1]</sup> |
| Snapshots | ✅ | ❌ <sup>[2]</sup> | ✅\* |
| Monitor / Tetragon events | ✅ <sup>[3]</sup> | ❌ <sup>[4]</sup> | ✅\* <sup>[3]</sup> |
| DNS + HTTP filtering | ✅ | ✅ | ✅\* |
| Egress default-deny | ✅ | ✅ | ✅\* <sup>[5]</sup> |
| `mount` / `unmount` (SSHFS) | ✅ | ✅ <sup>[6]</sup> | ✅\* <sup>[6]</sup> |
| Setuid privilege helper | ✅ | ❌ <sup>[7]</sup> | ✅\* <sup>[7]</sup> |
| Networking model | Host-only isolated bridge, static guest IP | Host-only vmnet (vmnet-helper), static guest IP | Host-only vmnet, static guest IP |
| Disk format | qcow2 (copy-on-write backing file) | raw | vmdk (full copy, converted from qcow2) |

All three backends now use a uniform **host-only** networking model: the guest
has no NAT/uplink and reaches the internet only through the host's DNS filter and
HTTP proxy. Egress is enforced outside the guest by a host firewall default-deny
(iptables on Linux, `pfctl` on macOS) — plus, on libvirt, a libvirt nwfilter at
the VM tap as an independent second layer.

### Notes

1. **vmware network lifecycle on macOS.** Egress *enforcement* is wired on macOS
   (see note 5), and the per-instance host-only `vmnet` lifecycle is implemented
   via Fusion's own mechanism — a `vmnet-cli` call plus an answer-file edit
   (`/Library/Preferences/VMware Fusion/networking`), *not* the Workstation
   `vnetlib` binary (`internal/vmrun/netcfg_darwin.go`; see also
   [vmware.md](vmware.md)). Only the exact apply verbs are `TODO(real-host)`, so
   the Fusion backend remains experimental and unvalidated on a real macOS host.
   For validated macOS support use the [vfkit backend](macos.md).
2. **vfkit snapshots.** `Backend.Snapshot()` returns `nil` — Apple's
   Virtualization.framework (via vfkit) has no native snapshot support.
3. **Monitoring transport.** libvirt carries Tetragon events over a virtio-serial
   channel; the vmware backend carries them over a serial pipe (`/dev/ttyS0`).
   Tetragon itself relies on eBPF, so events are produced only by a Linux guest.
4. **vfkit monitoring.** `Backend.MonitorTransport()` returns `nil` — no monitor
   transport is provided, so no Tetragon events are streamed.
5. **vmware egress enforcer.** iptables on Linux and, as of the pf wiring,
   `pfctl` on macOS (the same enforcer the vfkit backend uses). Windows would
   need a WFP enforcer, which is not implemented.
6. **`mount` / `unmount`** use host-side SSHFS/FUSE, so they work wherever the
   host provides sshfs. On macOS we recommend the kext-less fuse-t + fuse-t-sshfs
   (optional; see [macOS Support](macos.md#file-transfer)); unmount uses
   `umount`/`diskutil` rather than `fusermount`. The vmware backend inherits the
   host OS's tools.
7. **Privilege helper.** The privileged operations (firewall rules, etc.) run
   through abox's privilege helper. On Linux it is a setuid `abox-helper`; on
   macOS there is no setuid helper — the helper is launched via `sudo`. The gRPC
   protocol and security boundary are identical on both. See
   [Privilege Helper](privilege-helper.md).

## Keeping this current

The ✅/❌ values above are derived from the backend capability seams in
`internal/backend/backend.go` (`Snapshot`, `MonitorTransport`,
`EgressController`) and the per-backend implementations
(`internal/backend/{libvirt,vfkit,vmware}/`). When a backend gains or loses a
capability, update this table alongside the code.

## See Also

- [System Requirements](requirements.md) — dependencies and supported OSes
- [macOS Support](macos.md) — the vfkit backend
- [VMware Backend](vmware.md) — the experimental vmware backend
- [Security Design](security.md) — the defense-in-depth egress model
- [Filtering](filtering.md) — DNS/HTTP filtering architecture
