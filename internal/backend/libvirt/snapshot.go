//go:build linux

package libvirt

import (
	"context"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/libvirt"
)

// SnapshotManager implements backend.SnapshotManager for libvirt.
type SnapshotManager struct{}

// Create creates a new snapshot.
func (m *SnapshotManager) Create(ctx context.Context, vmName, snapshotName, description string) error {
	return libvirt.CreateSnapshot(domainName(vmName), snapshotName, description)
}

// List returns all snapshots for a VM.
func (m *SnapshotManager) List(ctx context.Context, vmName string) ([]backend.SnapshotInfo, error) {
	snapshots, err := libvirt.ListSnapshots(domainName(vmName))
	if err != nil {
		return nil, err
	}

	result := make([]backend.SnapshotInfo, len(snapshots))
	for i, s := range snapshots {
		result[i] = backend.SnapshotInfo{
			Name:         s.Name,
			CreationTime: s.CreationTime,
			State:        s.State,
			Parent:       s.Parent,
			Current:      s.Current,
		}
	}
	return result, nil
}

// Revert reverts a VM to a snapshot.
func (m *SnapshotManager) Revert(ctx context.Context, vmName, snapshotName string) error {
	return libvirt.RevertSnapshot(domainName(vmName), snapshotName)
}

// Delete removes a snapshot.
func (m *SnapshotManager) Delete(ctx context.Context, vmName, snapshotName string) error {
	return libvirt.DeleteSnapshot(domainName(vmName), snapshotName)
}

// Exists checks if a snapshot exists.
func (m *SnapshotManager) Exists(vmName, snapshotName string) bool {
	return libvirt.SnapshotExists(domainName(vmName), snapshotName)
}

// GetInfo returns detailed information about a snapshot.
func (m *SnapshotManager) GetInfo(vmName, snapshotName string) (backend.SnapshotInfo, error) {
	info, err := libvirt.GetSnapshotInfo(domainName(vmName), snapshotName)
	if err != nil {
		return backend.SnapshotInfo{}, err
	}
	return backend.SnapshotInfo{
		Name:         info.Name,
		CreationTime: info.CreationTime,
		State:        info.State,
		Parent:       info.Parent,
		Current:      info.Current,
	}, nil
}
