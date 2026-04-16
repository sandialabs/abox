//go:build darwin

package darwin

import (
	"context"
	"errors"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
)

var errNotImplemented = errors.New("macOS backend: not yet implemented")

// VMManager implements backend.VMManager for macOS via vfkit.
type VMManager struct{}

// Create defines a new VM configuration.
func (m *VMManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	return errNotImplemented
}

// Start starts a VM using vfkit.
func (m *VMManager) Start(ctx context.Context, name string) error {
	return errNotImplemented
}

// Stop gracefully stops a running VM.
func (m *VMManager) Stop(ctx context.Context, name string) error {
	return errNotImplemented
}

// ForceStop forcefully stops a running VM.
func (m *VMManager) ForceStop(ctx context.Context, name string) error {
	return errNotImplemented
}

// Remove removes a VM definition.
func (m *VMManager) Remove(ctx context.Context, name string) error {
	return errNotImplemented
}

// Exists checks if a VM is defined.
func (m *VMManager) Exists(name string) bool {
	return false
}

// IsRunning checks if a VM is currently running.
func (m *VMManager) IsRunning(name string) bool {
	return false
}

// State returns the current VM state.
func (m *VMManager) State(name string) backend.VMState {
	return backend.VMStateUnknown
}

// GetIP returns the IP address of a running VM.
func (m *VMManager) GetIP(name string) (string, error) {
	return "", errNotImplemented
}

// GetUUID returns the UUID of a defined VM.
func (m *VMManager) GetUUID(name string) string {
	return ""
}

// Redefine updates an existing VM definition.
func (m *VMManager) Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	return errNotImplemented
}
