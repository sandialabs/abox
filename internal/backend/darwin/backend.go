//go:build darwin

// Package darwin implements the backend interface for macOS using vfkit
// and Apple's Virtualization.framework.
package darwin

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

const (
	// Name is the identifier for this backend.
	Name = "macos"

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
}

// New creates a new macOS backend.
func New() backend.Backend {
	b := &Backend{}
	b.vm = &VMManager{}
	b.network = &NetworkManager{}
	b.disk = &DiskManager{}
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

// TrafficInterceptor returns nil — traffic interception is not yet implemented.
func (b *Backend) TrafficInterceptor() backend.TrafficInterceptor {
	return nil
}

// DryRun outputs the vfkit configuration that would be used for an instance.
func (b *Backend) DryRun(inst *config.Instance, paths *config.Paths, w io.Writer, opts backend.VMCreateOptions) error {
	fmt.Fprintln(w, "=== vfkit Configuration ===")
	fmt.Fprintf(w, "CPUs: %d\n", inst.CPUs)
	fmt.Fprintf(w, "Memory: %d\n", inst.Memory)
	fmt.Fprintf(w, "Disk: %s\n", paths.Disk)
	fmt.Fprintf(w, "Cloud-init ISO: %s\n", paths.CloudInitISO)
	fmt.Fprintf(w, "Network: vmnet shared (NAT)\n")
	fmt.Fprintf(w, "MAC: %s\n", inst.MACAddress)
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
