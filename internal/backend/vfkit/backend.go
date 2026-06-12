//go:build darwin

// Package vfkit implements the backend interface for macOS using vfkit
// and Apple's Virtualization.framework.
package vfkit

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vfkit"
)

const (
	// Name is the identifier for this backend.
	Name = "vfkit"

	// Priority determines auto-detection order. Lower is tried first.
	Priority = 10
)

func init() {
	backend.Register(Name, Priority, New)
}

// storageDir returns the macOS-appropriate directory for VM disk images.
func storageDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".abox", "images")
	}
	return filepath.Join(home, "Library", "Application Support", "abox", "images")
}

// Backend implements the backend.Backend interface for macOS.
type Backend struct {
	vm      *VMManager
	network *NetworkManager
	disk    *DiskManager
	traffic *TrafficInterceptor
}

// New creates a new macOS backend.
func New() backend.Backend {
	b := &Backend{}
	b.vm = &VMManager{}
	b.network = &NetworkManager{}
	b.disk = &DiskManager{}
	b.traffic = &TrafficInterceptor{}
	return b
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

// TrafficInterceptor returns the pfctl-backed traffic interceptor.
func (b *Backend) TrafficInterceptor() backend.TrafficInterceptor {
	return b.traffic
}

// DryRun outputs the vfkit configuration that would be used for an instance.
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
		Filter:   "abox-" + instanceName + "-traffic",
	}
}

// GenerateMAC returns a new random MAC address.
// Uses the locally-administered unicast range (x2:xx:xx:xx:xx:xx).
func (b *Backend) GenerateMAC() string {
	return fmt.Sprintf("02:ab:00:%02x:%02x:%02x",
		rand.Intn(256), rand.Intn(256), rand.Intn(256)) //nolint:gosec // MAC address doesn't need crypto randomness
}

// StorageDir returns the root directory for disk images on macOS.
func (b *Backend) StorageDir() string {
	return storageDir()
}

// DiskFormat returns "raw" — vfkit (Apple Virtualization.framework) only supports raw disk images.
func (b *Backend) DiskFormat() string {
	return "raw"
}

// NetworkDefaults allocates a deterministic per-instance /24 from the host-mode
// vmnet pool (192.168.128.0/24, .129.0/24, …). This implements
// backend.SubnetProvider so the create flow uses these values instead of the
// shared abox subnet pool. The gateway (.1) is baked into cloud-init at create
// time; VMManager.Start later pins vmnet-helper to exactly this subnet.
func (b *Backend) NetworkDefaults() (gateway, subnet string) {
	return allocateHostSubnet()
}
