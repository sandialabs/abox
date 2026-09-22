//go:build darwin

// Package vfkit implements the backend interface for macOS using vfkit
// and Apple's Virtualization.framework.
//
// Test coverage note: VM-lifecycle and disk pure/error logic is covered by
// vm_test.go and disk_test.go. The shared conformance suite
// (internal/backend/conformance) is contract-only by design (no
// Create/Start/Import, no network or privilege) and deliberately does NOT cover
// lifecycle/disk behavior — do not mistake a green conformance run for that.
package vfkit

import (
	"fmt"
	"io"
	"math/rand"
	"os/exec"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vfkit"
)

const (
	// Name is the identifier for this backend.
	Name = "vfkit"

	// Priority determines auto-detection order. Lower is tried first. vfkit is
	// non-experimental, so it becomes the darwin auto-detect default.
	Priority = 10
)

func init() {
	backend.Register(Name, Priority, New)
}

// Compile-time interface assertions: localize any signature drift to this file
// rather than surfacing it at a distant call site.
var (
	_ backend.Backend          = (*Backend)(nil)
	_ backend.NetworkDefaulter = (*Backend)(nil)
	_ backend.ToolRequirer     = (*Backend)(nil)
	_ backend.PfProviderSetter = (*Backend)(nil)
	_ backend.EgressController = (*EgressController)(nil)
	_ backend.VMManager        = (*VMManager)(nil)
	_ backend.NetworkManager   = (*NetworkManager)(nil)
	_ backend.DiskManager      = (*DiskManager)(nil)
)

// Backend implements the backend.Backend interface for macOS via vfkit.
type Backend struct {
	vm      *VMManager
	network *NetworkManager
	disk    *DiskManager
	egress  *EgressController
}

// New creates a new vfkit backend.
func New() backend.Backend {
	return &Backend{
		vm:      &VMManager{},
		network: &NetworkManager{},
		disk:    &DiskManager{},
		egress:  &EgressController{},
	}
}

// Name returns the backend identifier.
func (b *Backend) Name() string {
	return Name
}

// IsAvailable checks if vfkit is available on this system.
func (b *Backend) IsAvailable() error {
	if _, err := exec.LookPath("vfkit"); err != nil {
		return fmt.Errorf("vfkit not found: install with 'brew install vfkit': %w", err)
	}
	return nil
}

// RequiredTools declares the host binaries only the vfkit backend needs.
// Implements backend.ToolRequirer. qemu-img and xorriso are cross-platform and
// already covered by the common check-deps table, so they are not repeated here
// (mirrors the libvirt backend, which only declares its unique tool).
func (b *Backend) RequiredTools() []backend.Tool {
	return []backend.Tool{
		{Name: "vfkit", UsedBy: "macOS VM backend: launches the guest via Apple's Virtualization.framework",
			Hint: "brew install vfkit"},
		{Name: "vmnet-helper", UsedBy: "macOS VM backend: provides the guest's host-mode vmnet network (DHCP/gateway)",
			Hint: "brew tap nirs/vmnet-helper && brew trust nirs/vmnet-helper && brew install vmnet-helper (brew trust needed on Homebrew 6.0.0+); see https://github.com/nirs/vmnet-helper"},
	}
}

// VM returns the VM manager.
func (b *Backend) VM() backend.VMManager {
	return b.vm
}

// Network returns the network manager.
func (b *Backend) Network() backend.NetworkManager {
	return b.network
}

// Disk returns the disk manager.
func (b *Backend) Disk() backend.DiskManager {
	return b.disk
}

// Snapshot returns nil — vfkit does not support snapshots.
func (b *Backend) Snapshot() backend.SnapshotManager {
	return nil
}

// EgressController returns the pfctl-backed egress controller. Its privileged pf
// surface is injected by the factory via SetPfProvider (see PfProviderSetter), so
// read-only paths never spawn the helper.
func (b *Backend) EgressController() backend.EgressController {
	return b.egress
}

// SetPfProvider injects the privileged pf enforcer provider used by the egress
// controller. Implements backend.PfProviderSetter (the pf analogue of
// EgressProviderSetter); the factory calls this after construction.
func (b *Backend) SetPfProvider(p backend.PfEnforcerProvider) {
	b.egress.Provider = p
}

// MonitorTransport returns nil — Tetragon monitoring transport for vfkit is
// out of scope for this batch.
func (b *Backend) MonitorTransport() backend.MonitorTransport {
	return nil
}

// DryRun outputs the vfkit command that would be used for an instance without
// creating any resources.
func (b *Backend) DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error {
	cfg := buildVMConfig(inst, paths)
	args := vfkit.BuildArgs(cfg)

	fmt.Fprintln(w, "=== vfkit Command ===")
	fmt.Fprintf(w, "vfkit \\\n  %s\n", strings.Join(args, " \\\n  "))
	return nil
}

// ResourceNames returns the standardized resource names for an instance.
func (b *Backend) ResourceNames(instanceName string) backend.ResourceNames {
	return backend.ResourceNames{
		Instance: instanceName,
		VM:       "abox-" + instanceName,
		Network:  "abox-" + instanceName,
	}
}

// GenerateMAC returns a new random MAC address in the locally-administered
// unicast range (02:xx:...), which net.ParseMAC accepts as a valid unicast
// EUI-48.
func (b *Backend) GenerateMAC() string {
	return fmt.Sprintf("02:ab:00:%02x:%02x:%02x",
		rand.Intn(256), rand.Intn(256), rand.Intn(256)) //nolint:gosec // MAC address doesn't need crypto randomness
}

// StorageDir returns the root directory for backend-managed disk images.
func (b *Backend) StorageDir() string {
	return config.UserStorageDir()
}

// NetworkDefaults allocates a deterministic per-instance /24 from the host-mode
// vmnet pool (192.168.128.0/24, .129.0/24, …). Implements
// backend.NetworkDefaulter so the create flow uses these values instead of the
// shared abox subnet pool. The gateway (.1) is baked into cloud-init at create
// time; VMManager.Start later pins vmnet-helper to exactly this subnet.
//
// Returns (subnet, gateway) to match backend.ResolveNetwork / config.AllocateSubnet;
// the internal allocateHostSubnet still yields (gateway, subnet), swapped here.
func (b *Backend) NetworkDefaults() (subnet, gateway string, err error) {
	gateway, subnet, err = allocateHostSubnet()
	return subnet, gateway, err
}
