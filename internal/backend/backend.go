// Package backend provides a pluggable interface for VM management backends.
//
// Currently available backends:
//   - libvirt (Linux): QEMU/KVM via libvirt
//
// Additional backends (proxmox, macos) are planned for future releases.
//
// Backend selection is automatic at runtime based on platform and availability.
// The detected backend is recorded in instance config at create time.
package backend

import (
	"context"
	"io"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/rpc"
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

	// TrafficInterceptor returns the traffic interceptor, or nil if not supported.
	// Traffic interception is used to redirect DNS/HTTP through filtering proxies.
	TrafficInterceptor() TrafficInterceptor

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
	// This is where base images and instance disks are stored (e.g.,
	// "/var/lib/libvirt/images/abox" for libvirt). The directory typically
	// requires elevated privileges to access.
	StorageDir() string
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
type DiskManager interface {
	// Create creates a new disk image from a base image.
	// Uses copy-on-write where supported by the backend.
	Create(ctx context.Context, client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error

	// Delete removes a disk image.
	Delete(ctx context.Context, client rpc.PrivilegeClient, paths *config.Paths) error

	// EnsureBaseImage ensures the base image exists in the backend's image store.
	// May involve copying from user cache to backend-accessible location.
	EnsureBaseImage(ctx context.Context, client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error

	// Import imports an existing disk image into backend-managed storage.
	// Creates storage directories, copies the disk, and for snapshot imports,
	// rebases to the local base image.
	Import(ctx context.Context, client rpc.PrivilegeClient, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error

	// Export exports a disk image to a local destination path.
	// If snapshot is true, copies the raw CoW layer. Otherwise, flattens
	// the disk by merging it with its backing file for full portability.
	Export(ctx context.Context, client rpc.PrivilegeClient, dst string, paths *config.Paths, snapshot bool) error
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

// TrafficInterceptor handles network traffic interception for filtering.
// This is used to redirect DNS queries and enforce HTTP proxy usage.
// This interface is optional - backends may return nil from Backend.TrafficInterceptor().
type TrafficInterceptor interface {
	// DefineFilter defines a network filter for traffic control.
	DefineFilter(ctx context.Context, inst *config.Instance) error

	// ApplyFilter applies a filter to a running VM's network interface.
	// The cpus parameter ensures the update-device XML matches the running VM's driver config.
	ApplyFilter(ctx context.Context, vmName, networkName, filterName, macAddress string, cpus int) error

	// RemoveFilter removes a filter from a running VM's network interface.
	// The cpus parameter ensures the update-device XML matches the running VM's driver config.
	RemoveFilter(ctx context.Context, vmName, networkName, macAddress string, cpus int) error

	// DeleteFilter removes a filter definition.
	DeleteFilter(ctx context.Context, filterName string) error

	// FilterExists checks if a filter is defined.
	FilterExists(filterName string) bool

	// GetFilterUUID returns the UUID of a filter, or empty string if not found.
	GetFilterUUID(filterName string) string
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
	Filter   string // The traffic filter name (e.g., "abox-myvm-traffic")
}
