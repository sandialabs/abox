# VMware backend (experimental)

abox can drive **VMware Workstation Pro / Fusion** VMs as an alternative to the
default libvirt/QEMU backend, while preserving abox's core guarantee: **network
egress is filtered and enforced outside the guest**, so a compromised guest
cannot bypass it.

> **Status:** the Linux implementation is complete and unit-tested, but has
> **not yet been validated on a real VMware host**. Code paths that depend on
> exact `vmrun`/`vnetlib` behavior or live iptables semantics are marked
> `TODO(real-host)` (see [Real-host validation](#real-host-validation)).
>
> This is about the VMware backend specifically — **abox has first-class,
> non-experimental macOS support via the built-in vfkit backend** (Apple's
> Virtualization.framework + `pfctl`), which is auto-detected on macOS. See
> [macOS Support](macos.md). On macOS the vmware/Fusion backend now shares that
> same `pfctl` egress enforcer, but its host-only **network lifecycle** is still
> `TODO(real-host)` (it drives `vnetlib`, a Workstation tool; Fusion differs), so
> the Fusion backend remains experimental and unvalidated on a real macOS host.
> Windows is likewise not yet usable — see [Platform support](#platform-support).

## Selecting the backend

The VMware backend is **experimental** and is therefore **never chosen by
auto-detection** — not even when it is the only backend available. You must
select it explicitly with the `ABOX_BACKEND` environment variable:

```bash
ABOX_BACKEND=vmware abox create myvm
```

The selected backend is recorded in the instance config at create time, so
subsequent commands for that instance use it without needing the variable again.
Selecting it logs a one-line warning that the backend is unvalidated on real
hardware. When `ABOX_BACKEND` is unset, libvirt is the auto-detected default on
Linux.

## Requirements

| Tool | Needed for | Notes |
|------|-----------|-------|
| `vmrun` | all VMware VM lifecycle | ships with VMware Workstation Pro / Fusion |
| `qemu-img` | base image conversion (qcow2 → vmdk) | already an abox dependency |

`abox doctor` / `checkdeps` reports `vmrun` as an **optional** dependency (it is
not needed for the libvirt backend).

## How it maps to abox's model

### Disk
- Base cloud images (qcow2) are converted **once** to a `monolithicSparse`
  VMDK per base, cached in the backend image store.
- Each instance disk is a **full copy** of the base VMDK. VMware has no
  disk-level copy-on-write clone without VDDK/VM-level cloning, so abox copies
  the base; on reflink-capable filesystems (btrfs/xfs) this is near-instant and
  space-efficient for free. (`vmrun clone --linked` is a possible future
  optimization.)
- **Import safety:** imported disks are validated by content (not file
  extension). A qcow2 carrying a backing file, or a VMDK descriptor carrying a
  `parentFileNameHint`/`parentCID` or an absolute/`..`-escaping extent path, is
  **rejected** — so a hostile image can't point the VM at arbitrary host files.

### VM
- Defined by a generated `.vmx` (host-only NIC, the instance VMDK, cloud-init
  ISO as an IDE CDROM, a VMware-format `uuid.bios`). Hardened defaults: shared
  folders / drag-and-drop / copy-paste / 3D disabled.
- **Firmware defaults to BIOS** (most cloud images are MBR-bootable); set
  `backend_config.firmware: efi` to opt into EFI.
- Lifecycle via `vmrun` (start/stop/hard-stop/delete, guest IP); snapshots via
  `vmrun snapshot`/`revertToSnapshot`.

### Network — host-only per instance
- Each instance gets its **own host-only vmnet** from the pool `vmnet2`…`vmnet19`
  excluding `vmnet8` (the pool starts at 2, so `vmnet0`/`vmnet1` are below the
  floor; `vmnet8` is VMware's default NAT network) — **17 allocatable numbers**.
  Host-only means **no uplink and no NAT** — the guest has no network path to the
  internet at all; its only reachable neighbor is the host.
- A per-instance vmnet also gives lateral isolation between instances.
- **Concurrency cap:** the host-only vmnet pool bounds abox to ~17 concurrent
  VMware instances. Exhaustion produces a clear error, not a silent failure.
- **The host-only setup mechanism is per-platform** — VMware ships no single
  cross-platform network CLI. abox selects the right one at runtime
  (`internal/vmrun/netcfg.go`), with the exact verbs and sources documented there:
  - **Linux:** edit `/etc/vmware/networking` (`answer VNET_N_*` directives) and
    apply with `vmware-networks --stop`/`--start`.
  - **macOS (Fusion):** edit `/Library/Preferences/VMware Fusion/networking` and
    apply with the Fusion.app `vmnet-cli --configure`/`--stop`/`--start`.
  - **Windows:** the `vnetlib.exe` CLI (`add`/`set`/`update adapter`).
  All paths route through a single choke point that refuses any NAT/bridge/uplink
  directive, and edits touch only the instance's own `VNET_N` lines.

### Security / egress model
This is the important part — how the VMware backend matches libvirt's guarantee
without libvirt's nwfilter:

1. **Topology (guest-unbypassable):** host-only mode gives the guest no uplink,
   so there is no direct internet path to bypass — enforced by the vmnet in the
   host kernel, outside the guest's control.
2. **Host firewall default-deny:** abox installs a dedicated iptables chain
   entered from the **top** of the host `INPUT` chain for the instance's vmnet.
   The chain permits only the DNS-filter and HTTP-proxy ports (plus gateway ICMP
   and established/related return traffic) and **drops everything else** — so the
   guest can reach the host *only* through the filtering proxies, and cannot use
   the host as a pivot. (This default-deny chain also hardens the host under the
   libvirt backend as defense-in-depth.)

> **Single enforcement layer — verified fail-closed at boot.** Unlike libvirt
> (which pairs the host firewall with a per-VM `nwfilter` bound to the tap), the
> VMware backend has **one** host-side enforcement layer: the per-vmnet iptables
> chain. Because each instance gets a *dedicated* vmnet, that interface-scoped
> chain is effectively per-VM, so a second layer is unnecessary. To keep the
> single layer trustworthy, `Define` (invoked by `abox start`) now **verifies the
> rules are actually in force after installing them and refuses to boot an
> unfiltered guest** if they are not — so a host where enforcement silently did
> not take fails closed rather than running open.
>
> Two hardening items remain and require a real VMware host to validate: (1) a
> runtime probe that the vmnet is actually *up and host-only* (today the topology
> is trusted from `vnetlib`/answer-file success, with the FORWARD default-deny as
> the compensating control — see `internal/vmrun/network.go`), and (2) refusing to
> reuse a vmnet number whose stale rules from a failed teardown still exist. Until
> then, run `abox doctor`, which performs the privileged `VerifyEnforced` check.

**Host→guest SSH** (`abox ssh`) is admitted by the shared egress enforcer, so it
needs no VMware-specific rule: on **Linux** the per-vmnet host `INPUT` chain leads
with a conntrack `ESTABLISHED,RELATED` accept, so the guest's SSH reply to a
host-initiated connection passes; on **macOS** the pf anchor (built by
`firewall.BuildInstanceRules`, shared with vfkit) contains an explicit inbound
`pass … port 22`.

The guest reaches the outside world **only** through abox's host-run DNS filter
and HTTP proxy, which are wired into the guest by cloud-init.

> **Explicit proxy is required for functionality (fail-closed).** abox configures
> the guest's DNS and `http_proxy`/`https_proxy` via cloud-init. A guest that
> *ignores* that configuration does not get unfiltered internet — it gets **no
> connectivity** (host-only has no uplink; the host firewall drops non-filter
> traffic). This is safe by default. abox does **not** transparently intercept
> `:80/:443` (the HTTP filter is an explicit proxy).

## Platform support

| Platform | VM lifecycle / disk | Network lifecycle | Egress enforcement |
|----------|---------------------|-------------------|--------------------|
| **Linux** (Workstation Pro) | ✅ implemented | ✅ implemented | ✅ host iptables (reuses abox's privileged helper) |
| **macOS** (Fusion) | ✅ code is portable | ⚠️ implemented (Fusion `vmnet-cli` + answer-file); verbs `TODO(real-host)` | ✅ `pfctl` (shares the vfkit enforcer) |
| **Windows** (Workstation Pro) | ✅ code is portable | ✅ code is portable | ❌ needs a WFP enforcer (not implemented) |

On **macOS**, egress enforcement is wired: the Fusion backend reuses the same
`pfctl` enforcer as abox's native vfkit backend (via the privilege helper, which
uses `sudo` on macOS). The host-only network lifecycle uses Fusion's own mechanism
(edit `/Library/Preferences/VMware Fusion/networking` + `vmnet-cli`), not the
Workstation `vnetlib` — but the exact verbs are `TODO(real-host)`, so the Fusion
backend remains experimental and unvalidated on a real macOS host. For validated macOS support, use the default
[vfkit backend](macos.md).

On **Windows**, egress enforcement still requires a WFP implementation of the
privileged enforcer plus a platform equivalent of the Linux privilege helper.
Until then, only the **Linux** VMware backend provides the full security
guarantee end-to-end.

## Real-host validation

The implementation is unit-tested but not yet validated on a real VMware host.
The following depend on exact `vmrun`/`vnetlib` behavior or live firewall
semantics and are marked `TODO(real-host)` in the code:

- **Disk `ddb.adapterType` (`internal/vmrun/disk.go`):** the `qemu-img`-written
  VMDK descriptor's adapter type must agree with `scsi0.virtualDev=lsilogic`; a
  mismatch could fail boot.
- **Linux answer-file reload (`internal/vmrun/netcfg.go`):** whether
  `vmware-networks --stop`/`--start` re-reads the edited `/etc/vmware/networking`,
  or whether a `--migrate-network-settings <file>` step is required to pick up the
  edit.
- **Windows `vnetlib` setter object token (`internal/vmrun/netcfg.go`):** abox
  uses `set adapter … addr/mask`; `VNETLIB.md` documents `set vnet … addr/mask`.
  The Windows leg is not usable yet (no WFP enforcer), so the discrepancy is
  recorded in-code pending a real Windows host.
- **Privileged answer-file write (`internal/vmrun/netcfg.go`):** the root-owned
  file edit + vendor restart requires abox to run with root/sudo; routing it
  through the privilege helper is a separate workstream (`TODO` in
  `writeNetworkingFile`).
- **Egress (`internal/privilege/egress_linux.go`):** that the position-1 jump
  precedes pre-existing broad `INPUT` accepts, the in-chain ESTABLISHED accept
  preserves host→guest SSH under load, and `-N`/`-X` interaction with concurrent
  operators. (`internal/privilege/helper.go` is now only the gRPC server shell;
  the iptables FORWARD/INPUT logic lives in `egress_linux.go`.)
- **Monitoring (`internal/vmrun/vmx.go`, `internal/backend/vmware/vm.go`):** that
  the `serial0` pipe makes VMware create the Unix socket at `monitor.sock` on
  power-on, that the user-run daemon can connect (socket ownership/permissions),
  and that a base image setting `console=ttyS0` does not corrupt the event stream
  (if it does, move the pipe to `serial1`/`/dev/ttyS1` and update
  `monitorGuestDevice`).

## Differences from the libvirt backend

| Aspect | libvirt | VMware |
|--------|---------|--------|
| Networking | host-only bridge (isolated, no NAT/uplink), static guest IP | host-only vmnet, no NAT/uplink, static guest IP |
| Egress default-deny | nwfilter at the VM tap (per-NIC) **and** a host iptables FORWARD chain on the bridge | host iptables chain on the vmnet |
| Disk CoW | qcow2 backing file | full VMDK copy (reflink where available) |
| Disk format | qcow2 | vmdk (converted from qcow2) |
| Guest monitoring | virtio-serial (Tetragon) | serial pipe bound to the monitor socket (`serial0`, guest `/dev/ttyS0`) |
| Concurrency | limited by host resources | additionally capped at ~17 host-only vmnets |

## See Also

- [Support Matrix](support-matrix.md) — OS × backend × capability table
- [macOS Support](macos.md) — the default (non-experimental) macOS backend, vfkit
- [System Requirements](requirements.md) — dependency details
- [Security Design](security.md) — the defense-in-depth egress model
- [Filtering](filtering.md) — DNS/HTTP filtering architecture
