//go:build darwin

package darwin

import (
	"context"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/rpc"
)

// DiskManager implements backend.DiskManager for macOS.
type DiskManager struct{}

// Create creates a new disk image from a base image using copy-on-write.
func (m *DiskManager) Create(ctx context.Context, client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error {
	return errNotImplemented
}

// Delete removes a disk image.
func (m *DiskManager) Delete(ctx context.Context, client rpc.PrivilegeClient, paths *config.Paths) error {
	return errNotImplemented
}

// EnsureBaseImage ensures the base image exists in the backend's image store.
func (m *DiskManager) EnsureBaseImage(ctx context.Context, client rpc.PrivilegeClient, inst *config.Instance, paths *config.Paths) error {
	return errNotImplemented
}

// Import imports an existing disk image into backend-managed storage.
func (m *DiskManager) Import(ctx context.Context, client rpc.PrivilegeClient, src string, inst *config.Instance, paths *config.Paths, snapshot bool) error {
	return errNotImplemented
}

// Export exports a disk image to a local destination path.
func (m *DiskManager) Export(ctx context.Context, client rpc.PrivilegeClient, dst string, paths *config.Paths, snapshot bool) error {
	return errNotImplemented
}
