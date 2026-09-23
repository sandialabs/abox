// Package backend provides a pluggable interface for VM management backends.
//
// Currently available backends:
//   - libvirt (Linux): QEMU/KVM via libvirt
//   - vfkit (macOS): Apple Virtualization.framework via vfkit
//   - vmware (experimental): VMware Workstation/Fusion via vmrun
//
// Additional backends (e.g. proxmox) are planned for future releases.
//
// Backend selection is automatic at runtime based on platform and availability.
// The detected backend is recorded in instance config at create time.
package backend

import (
	"context"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/config"
)

// Backend is the main interface for VM management backends.
// Each backend implements platform-specific operations for VMs, networks, and disks.
type Backend interface {
	// Name returns the backend identifier (e.g., "libvirt", "proxmox", "macos").
	Name() string

	// IsAvailable checks if this backend can be used on the current system.
	// Returns nil if available, or an error describing why not.
	IsAvailable() error

	// VM returns the VM manager for this backend.
	VM() VMManager

	// Network returns the network manager for this backend.
	Network() NetworkManager

	// Disk returns the disk manager for this backend.
	Disk() DiskManager

	// Snapshot returns the snapshot manager, or nil if not supported.
	Snapshot() SnapshotManager

	// EgressController returns the egress controller, or nil if not supported.
	// The egress controller confines an instance's network egress to an
	// EgressPolicy (default-deny; only the DNS/HTTP filter endpoints permitted).
	EgressController() EgressController

	// MonitorTransport returns the monitor transport for this backend, or nil
	// if the backend cannot carry Tetragon monitoring events. It abstracts the
	// per-backend device the guest agent writes events to (e.g. libvirt's
	// virtio-serial port vs. VMware's serial tty) so the monitor daemon and
	// cloud-init generation stay backend-neutral.
	MonitorTransport() MonitorTransport

	// DryRun outputs the backend-specific configuration that would be created
	// for an instance, without actually creating any resources.
	DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts VMCreateOptions) error

	// ResourceNames returns the standardized resource names for an instance.
	// Names are backend-specific (e.g., libvirt uses "abox-<name>" prefix).
	ResourceNames(instanceName string) ResourceNames

	// GenerateMAC returns a new random MAC address for VMs.
	// The format depends on the backend (e.g., libvirt uses 52:54:00:xx:xx:xx).
	GenerateMAC() string

	// StorageDir returns the root directory for backend-managed disk images.
	// This is where base images and instance disks are stored. It is a
	// user-owned location (disk operations run unprivileged); the VM host grants
	// the hypervisor runtime access via dynamic ownership.
	StorageDir() string
}

// NetworkDefaulter lets a backend supply its own subnet/gateway allocation
// (e.g. macOS vmnet host-mode pool) instead of the default config.AllocateSubnet.
// It returns an error when it cannot allocate (e.g. the pool is exhausted) so the
// create flow fails cleanly rather than proceeding with a colliding subnet.
type NetworkDefaulter interface {
	NetworkDefaults() (subnet, gateway string, err error)
}

// ResolveNetwork resolves the subnet/gateway/third-octet for an instance,
// reproducing config.AllocateSubnet's behavior with a per-backend hook.
//
//   - When requested is non-empty, it is validated (a /24 with a .0 host part)
//     and returned verbatim.
//   - Otherwise, if the backend implements NetworkDefaulter it supplies the
//     subnet/gateway (e.g. macOS vmnet's host-mode /24 pool); the third octet
//     is derived from the subnet, and a backend that returns a malformed subnet
//     (not a /24 with a .0 host) is rejected with an error.
//   - Otherwise the default pool allocator (config.AllocateSubnet) is used.
func ResolveNetwork(be Backend, requested string) (subnet, gateway string, thirdOctet int, err error) {
	if requested != "" {
		gateway, third, err := config.ValidateSubnet(requested)
		return requested, gateway, third, err
	}
	if nd, ok := be.(NetworkDefaulter); ok {
		subnet, gateway, derr := nd.NetworkDefaults()
		if derr != nil {
			return "", "", 0, derr
		}
		// Hold the backend-supplied subnet to the same /24-with-.0-host invariant as
		// the requested path, so a buggy defaulter fails cleanly at create time
		// rather than persisting an unusable subnet/gateway into the instance config.
		derivedGateway, third, verr := config.ValidateSubnet(subnet)
		if verr != nil {
			return "", "", 0, fmt.Errorf("backend %q returned an invalid subnet %q: %w", be.Name(), subnet, verr)
		}
		if gateway == "" {
			gateway = derivedGateway
		}
		return subnet, gateway, third, nil
	}
	return config.AllocateSubnet("")
}

// Tool is a host binary a backend needs. Hint is package-install guidance
// (empty falls back to a generic message in check-deps).
type Tool struct {
	Name   string
	UsedBy string
	Hint   string
}

// ToolRequirer is an optional interface implemented by backends that need
// external host binaries beyond abox's common toolset (ssh/qemu-img/iptables/…).
// check-deps checks the selected backend's tools as required and other
// registered backends' tools as optional. It is a separate interface (not part
// of Backend) so mocks and non-tool backends need not implement it.
type ToolRequirer interface {
	RequiredTools() []Tool
}

// VMManager handles VM lifecycle operations.
type VMManager interface {
	// Create defines a new VM from the given spec.
	// The VM is not started automatically.
	Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts VMCreateOptions) error

	// Start starts a defined VM.
	Start(ctx context.Context, name string) error

	// Stop gracefully stops a running VM.
	Stop(ctx context.Context, name string) error

	// ForceStop forcefully stops a running VM.
	ForceStop(ctx context.Context, name string) error

	// Remove removes a VM definition and optionally its storage.
	Remove(ctx context.Context, name string) error

	// Exists checks if a VM is defined.
	Exists(name string) bool

	// IsRunning checks if a VM is currently running.
	IsRunning(name string) bool

	// State returns the current VM state as a string.
	State(name string) VMState

	// GetIP returns the IP address of a running VM.
	GetIP(name string) (string, error)

	// GetUUID returns the UUID of a defined VM, or empty string if not found.
	GetUUID(name string) string

	// Redefine updates an existing VM definition (e.g., to add CDROM).
	// The uuid parameter should be passed to preserve the VM identity.
	Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts VMCreateOptions) error
}

// VMCreateOptions holds options for VM creation.
type VMCreateOptions struct {
	// AssumeCloudInitExists forces inclusion of the cloud-init CDROM device
	// even if the ISO file doesn't exist yet (useful for dry-run).
	AssumeCloudInitExists bool

	// MonitorEnabled includes a virtio-serial channel for Tetragon monitoring.
	MonitorEnabled bool

	// UUID is the existing VM UUID to preserve when redefining.
	// Pass empty string for new VMs.
	UUID string

	// CustomTemplate overrides the default domain XML template.
	// When non-empty, this template string is used instead of the built-in template.
	CustomTemplate string
}

// VMState represents the state of a VM.
type VMState string

const (
	VMStateRunning  VMState = "running"
	VMStateStopped  VMState = "stopped"
	VMStatePaused   VMState = "paused"
	VMStateUnknown  VMState = "unknown"
	VMStateCrashed  VMState = "crashed"
	VMStateShutdown VMState = "shutdown"
)

// NetworkManager handles network lifecycle operations.
type NetworkManager interface {
	// Create defines and optionally starts a new network.
	Create(ctx context.Context, inst *config.Instance) error

	// Start starts a defined network.
	Start(ctx context.Context, name string) error

	// Stop stops a running network.
	Stop(ctx context.Context, name string) error

	// Delete removes a network definition.
	Delete(ctx context.Context, name string) error

	// Exists checks if a network is defined.
	Exists(name string) bool

	// IsActive checks if a network is currently active.
	IsActive(name string) bool
}

// DiskManager handles disk operations.
//
// Disk operations run unprivileged, as the calling user: storage lives in a
// user-writable location and the VM host (e.g. libvirtd dynamic ownership)
// grants the hypervisor runtime access. No privilege helper is involved.
type DiskManager interface {
	// Create creates a new disk image from a base image.
	// Uses copy-on-write where supported by the backend.
	Create(ctx context.Context, inst *config.Instance, paths *config.Paths) error

	// Delete removes a disk image.
	Delete(ctx context.Context, paths *config.Paths) error

	// EnsureBaseImage ensures the base image exists in the backend's image store.
	// May involve copying from user cache to backend-accessible location.
	EnsureBaseImage(ctx context.Context, inst *config.Instance, paths *config.Paths) error

	// EnsureAccess re-asserts the runtime VM process's access to an existing
	// instance's disk, base image, and cloud-init ISO (idempotent). Called before
	// boot so access lost since create/import (e.g. an ACL stripped by a remount
	// or restore) is repaired rather than failing the VM at start.
	EnsureAccess(ctx context.Context, inst *config.Instance, paths *config.Paths) error

	// Import imports an existing disk image into backend-managed storage.
	// Creates storage directories, copies the disk, and for snapshot imports,
	// rebases to the local base image.
	Import(ctx context.Context, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error

	// Export exports a disk image to a local destination path.
	// If snapshot is true, copies the raw CoW layer. Otherwise, flattens
	// the disk by merging it with its backing file for full portability.
	Export(ctx context.Context, dst string, paths *config.Paths, snapshot bool) error
}

// SnapshotManager handles VM snapshot operations.
// This interface is optional - backends may return nil from Backend.Snapshot().
type SnapshotManager interface {
	// Create creates a new snapshot.
	Create(ctx context.Context, vmName, snapshotName, description string) error

	// List returns all snapshots for a VM.
	List(ctx context.Context, vmName string) ([]SnapshotInfo, error)

	// Revert reverts a VM to a snapshot.
	Revert(ctx context.Context, vmName, snapshotName string) error

	// Delete removes a snapshot.
	Delete(ctx context.Context, vmName, snapshotName string) error

	// Exists checks if a snapshot exists.
	Exists(vmName, snapshotName string) bool

	// GetInfo returns detailed information about a snapshot.
	GetInfo(vmName, snapshotName string) (SnapshotInfo, error)
}

// SnapshotInfo holds information about a VM snapshot.
type SnapshotInfo struct {
	Name         string
	CreationTime string
	State        string
	Parent       string
	Current      bool
}

// EgressPolicy is the complete, platform-neutral description of the egress an
// instance's guest is permitted. Anything not described here MUST be denied by
// the enforcing backend (default-deny). It carries no mechanism vocabulary
// (no nwfilter/iptables/MAC/UUID): each backend enforces it however it can.
//
// It is the single source of truth for "what egress is allowed": both the
// privileged host-side enforcer (iptables) and the per-instance filter
// definition (libvirt nwfilter) are driven from this struct, so the two halves
// cannot drift from independently hardcoded constants.
//
// ICMP to the gateway is always permitted (a useful diagnostic); it is not a
// policy knob today, so the enforcers add it unconditionally. There is no DHCP
// allowance: guests are statically addressed via cloud-init (no DHCP handshake).
type EgressPolicy struct {
	DNSPort      int    // dnsfilter listen port (guest DNS is redirected here)
	HTTPPort     int    // httpfilter proxy port
	GuestDNSPort int    // guest-facing DNS port that is redirected to DNSPort (normally 53)
	Gateway      string // bridge gateway IPv4; host-side accepts are pinned to this dest
}

// standardDNSPort is the guest-facing DNS port (what the guest sends to) that is
// transparently redirected to the dnsfilter's actual listen port.
const standardDNSPort = 53

// BuildEgressPolicy derives the egress policy for an instance from its config.
// This is the one place the permitted egress is defined.
func BuildEgressPolicy(inst *config.Instance) EgressPolicy {
	return EgressPolicy{
		DNSPort:      inst.DNS.Port,
		HTTPPort:     inst.HTTP.Port,
		GuestDNSPort: standardDNSPort,
		Gateway:      inst.Gateway,
	}
}

// EgressController confines an instance's network egress to an EgressPolicy.
// Implementations enforce default-deny by whatever mechanism the platform
// offers (libvirt nwfilter + iptables REDIRECT, nftables, pf, WFP, or SLIRP
// restrict=on). The contract is the policy; the mechanism is the implementation.
// This interface is optional - backends may return nil from Backend.EgressController().
type EgressController interface {
	// Define materializes and activates the pre-boot, host-side portion of
	// enforcement for an instance (idempotent). It may run before the VM is
	// running and SHOULD do everything that must be in force before the guest
	// boots — e.g. install host firewall rules (DNS redirect + the accepts the
	// guest needs for DNS/HTTP at first packet) and materialize any
	// per-instance filter definition. It does NOT perform steps that require a
	// running VM (see Apply). Backends with nothing to pre-stage may no-op.
	Define(ctx context.Context, inst *config.Instance, p EgressPolicy) error

	// Apply activates the instance-bound portion of enforcement on the running
	// instance (e.g. binding a packet filter to the live VM interface).
	Apply(ctx context.Context, inst *config.Instance) error

	// Remove tears down enforcement and any materialized policy (idempotent).
	Remove(ctx context.Context, inst *config.Instance) error

	// Verify reports whether the pre-boot/unprivileged portion of enforcement is
	// in force (e.g. the per-instance filter definition exists). It MUST be
	// unprivileged so read-only callers (status/doctor) never trigger privilege
	// escalation. It does NOT confirm the privileged host-side rules (see
	// VerifyEnforced) — the two halves can drift independently.
	Verify(ctx context.Context, inst *config.Instance) (bool, error)

	// VerifyEnforced reports whether the privileged host-side rules (e.g. the DNS
	// REDIRECT + INPUT accepts) are currently in force. Unlike Verify it MAY
	// require privilege, so only explicitly-diagnostic callers (doctor) should use
	// it. Backends with no privileged half may report the same as Verify.
	VerifyEnforced(ctx context.Context, inst *config.Instance) (bool, error)
}

// EnforcementAuthority is an optional capability an EgressController may implement
// to declare whether its VerifyEnforced reflects live kernel/firewall state or
// only a best-effort applied-marker. Controllers that query the kernel (the
// libvirt/vmware iptables path) need not implement it — a controller that does not
// implement this interface is treated as authoritative. The macOS pf backends
// implement it returning false, since their VerifyEnforced is marker-based (a
// read-only pfctl anchor query would need a new privileged RPC). Diagnostic
// callers (doctor) use it to avoid reporting a marker as verified kernel truth.
type EnforcementAuthority interface {
	// EnforcementIsAuthoritative reports whether VerifyEnforced queries live
	// kernel/firewall state (true) or only a best-effort applied-marker (false).
	EnforcementIsAuthoritative() bool
}

// MonitorTransport abstracts how Tetragon events travel from the guest to the
// host monitor daemon. Backends differ only in the device the in-guest agent
// writes events to; the host daemon always reads them from the instance's
// monitor socket. This interface is optional - backends may return nil from
// Backend.MonitorTransport() to signal that they cannot carry monitoring.
type MonitorTransport interface {
	// GuestDevice is the path, inside the guest, that the monitor agent writes
	// Tetragon events to (e.g. "/dev/virtio-ports/abox.monitor.0" for libvirt's
	// virtio-serial port, or "/dev/ttyS0" for a VMware serial pipe).
	GuestDevice() string
}

// EgressEnforcer is the privileged, host-side half of egress enforcement,
// expressed in transport-neutral terms (no rpc/gRPC vocabulary) so the backend
// package stays free of the privilege transport. The concrete implementation
// (see internal/firewall) adapts a privileged helper client to this interface;
// a backend's EgressController obtains one via an injected EgressEnforcerProvider.
type EgressEnforcer interface {
	// Apply installs the host-side egress rules for a bridge as described by the
	// policy: redirect guest DNS to the dnsfilter port and accept the filter
	// traffic (and gateway ICMP). Idempotent.
	Apply(ctx context.Context, bridge string, p EgressPolicy) error
	// Remove flushes the host-side egress rules for a bridge (idempotent). The
	// policy's ports scope the flush to abox's own rules so unrelated rules on
	// the same bridge are not deleted.
	Remove(ctx context.Context, bridge string, p EgressPolicy) error
	// Verify reports whether the complete rule set described by the policy is
	// currently in force on the bridge.
	Verify(ctx context.Context, bridge string, p EgressPolicy) (bool, error)
}

// EgressEnforcerProvider lazily yields an EgressEnforcer. It is called only when
// privileged enforcement is actually needed (Define/Remove), so read-only paths
// (status/doctor Verify) never trigger privilege escalation.
type EgressEnforcerProvider func() (EgressEnforcer, error)

// EgressProviderSetter is the optional hook the factory uses to inject the
// privileged enforcer provider into a backend after construction (the registry
// constructs backends with a no-arg factory). Backends that enforce egress via a
// privileged helper implement it; others can ignore it.
type EgressProviderSetter interface {
	SetEgressProvider(EgressEnforcerProvider)
}

// PfEnforcer is the privileged pfctl surface used by the macOS egress controller.
// It mirrors EgressEnforcer's role (the privileged host-side half, in
// transport-neutral terms) for the pf mechanism: rather than per-bridge iptables
// rules it manages a per-instance pf anchor keyed on the instance's /24 subnet.
type PfEnforcer interface {
	Enable(ctx context.Context) error
	LoadAnchor(ctx context.Context, instance, subnet, rules string) error
	FlushAnchor(ctx context.Context, instance string) error
	TeardownConfig(ctx context.Context) error
}

// PfEnforcerProvider lazily yields a PfEnforcer. Like EgressEnforcerProvider it
// is called only when privileged enforcement is actually needed (Define/Apply/
// Remove), so read-only paths never trigger privilege escalation.
type PfEnforcerProvider func() (PfEnforcer, error)

// PfProviderSetter is the optional hook the factory uses to inject the pfctl
// provider into a backend after construction (parallel to EgressProviderSetter).
// A backend implements at most one of the two setters.
type PfProviderSetter interface{ SetPfProvider(PfEnforcerProvider) }

// StorageEnforcer is the privileged, host-side half of disk-storage setup,
// expressed in transport-neutral terms (no rpc/gRPC vocabulary) so the backend
// package stays free of the privilege transport. The concrete implementation
// (see internal/firewall) adapts a privileged helper client to this interface.
// It is the ONE privileged step disk handling needs: creating the caller's
// per-user storage root, owned by the caller and setgid to the QEMU runtime
// group. All per-instance disk operations then run unprivileged.
type StorageEnforcer interface {
	// EnsureStorageRoot idempotently provisions the caller's per-user disk
	// storage root at path (under /var/lib/libvirt/images/abox), so images
	// created there are reachable and readable by the VM process via group
	// membership. Idempotent.
	//
	// When regroup is true, the helper ALSO walks the caller's own subtree and
	// restores the QEMU group + modes on every entry — used by `abox migrate`
	// after relocating files chowned them to the caller's primary group (losing
	// the QEMU group). The regroup walk is always confined to the caller's own
	// per-uid subtree (derived from the socket peer credentials, never from
	// path). Per-instance create/import pass regroup=false.
	EnsureStorageRoot(ctx context.Context, path string, regroup bool) error
}

// StorageEnforcerProvider lazily yields a StorageEnforcer. Like the egress
// provider it is invoked only when a privileged storage step is actually needed
// (instance create/import), so read-only paths never trigger escalation.
type StorageEnforcerProvider func() (StorageEnforcer, error)

// StorageProviderSetter is the optional hook the factory uses to inject the
// storage enforcer provider into a backend after construction (parallel to
// EgressProviderSetter). Backends whose disks live in a location that needs a
// one-time privileged setup implement it; others can ignore it.
type StorageProviderSetter interface {
	SetStorageProvider(StorageEnforcerProvider)
}

// TemplateValidator is an optional interface for backends that support custom templates.
// Check support via type assertion: tv, ok := be.(TemplateValidator)
type TemplateValidator interface {
	// ValidateCustomTemplate validates template content for this backend.
	ValidateCustomTemplate(content string) error

	// HasCustomTemplate reports whether a custom template is stored for this instance.
	HasCustomTemplate(inst *config.Instance) bool

	// SetCustomTemplate marks the instance config as having (or not having) a custom template.
	SetCustomTemplate(inst *config.Instance, has bool)

	// LoadCustomTemplate reads the stored custom template for this instance.
	// Returns the template content or an error if the template is missing/unreadable.
	LoadCustomTemplate(paths *config.Paths) (string, error)

	// StoreCustomTemplate writes a custom template to the instance's data directory.
	StoreCustomTemplate(paths *config.Paths, content string) error
}

// ResourceNames holds standardized resource names for an instance.
// These names are backend-specific (e.g., libvirt uses "abox-<name>" prefix).
type ResourceNames struct {
	Instance string // The instance name (e.g., "myvm")
	VM       string // The VM/domain name (e.g., "abox-myvm")
	Network  string // The network/bridge name (e.g., "abox-myvm")
}
