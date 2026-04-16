//go:build darwin

package darwin

import (
	"context"

	"github.com/sandialabs/abox/internal/config"
)

// NetworkManager implements backend.NetworkManager for macOS.
// On macOS, networking is handled by vmnet shared mode which is configured
// as part of the vfkit VM launch — networks are not independent resources.
type NetworkManager struct{}

// Create is a no-op on macOS — vmnet networking is configured at VM start.
func (m *NetworkManager) Create(ctx context.Context, inst *config.Instance) error {
	return nil
}

// Start is a no-op on macOS — the network starts with the VM.
func (m *NetworkManager) Start(ctx context.Context, name string) error {
	return nil
}

// Stop is a no-op on macOS — the network stops with the VM.
func (m *NetworkManager) Stop(ctx context.Context, name string) error {
	return nil
}

// Delete is a no-op on macOS — no persistent network resource to remove.
func (m *NetworkManager) Delete(ctx context.Context, name string) error {
	return nil
}

// Exists returns true on macOS — vmnet is always available.
func (m *NetworkManager) Exists(name string) bool {
	return true
}

// IsActive returns true on macOS — vmnet is a system service that is always available.
// The network becomes active for a specific VM when that VM starts.
func (m *NetworkManager) IsActive(name string) bool {
	return true
}
