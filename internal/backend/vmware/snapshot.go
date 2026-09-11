package vmware

import (
	"context"
	"fmt"
	"strings"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/timeout"
	"github.com/sandialabs/abox/internal/vmrun"
)

// SnapshotManager implements backend.SnapshotManager for VMware via vmrun's
// snapshot subcommands. Snapshots are addressed by the instance name (resolved to
// its .vmx path) plus a snapshot name.
type SnapshotManager struct{}

// Create takes a snapshot. vmrun's snapshot command takes no description, so the
// description argument is accepted for interface parity but ignored (documented).
func (s *SnapshotManager) Create(ctx context.Context, vmName, snapshotName, description string) error {
	_ = description // vmrun snapshot has no description field.
	vmx, err := vmxPathFor(vmName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	return vmrun.CreateSnapshot(ctx, vmx, snapshotName)
}

// List returns all snapshots for a VM. vmrun listSnapshots emits a header
// ("Total snapshots: N") followed by one name per line.
func (s *SnapshotManager) List(ctx context.Context, vmName string) ([]backend.SnapshotInfo, error) {
	vmx, err := vmxPathFor(vmName)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	names, err := vmrun.ListSnapshots(ctx, vmx)
	if err != nil {
		return nil, err
	}
	infos := make([]backend.SnapshotInfo, 0, len(names))
	for _, n := range names {
		infos = append(infos, backend.SnapshotInfo{Name: n})
	}
	return infos, nil
}

// Revert reverts the VM to a snapshot.
func (s *SnapshotManager) Revert(ctx context.Context, vmName, snapshotName string) error {
	vmx, err := vmxPathFor(vmName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	return vmrun.RevertToSnapshot(ctx, vmx, snapshotName)
}

// Delete removes a snapshot.
func (s *SnapshotManager) Delete(ctx context.Context, vmName, snapshotName string) error {
	vmx, err := vmxPathFor(vmName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()
	return vmrun.DeleteSnapshot(ctx, vmx, snapshotName)
}

// Exists reports whether a named snapshot exists (by scanning List). Defensive:
// any error listing snapshots is treated as "does not exist".
func (s *SnapshotManager) Exists(vmName, snapshotName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout.Default)
	defer cancel()
	infos, err := s.List(ctx, vmName)
	if err != nil {
		return false
	}
	for _, i := range infos {
		if i.Name == snapshotName {
			return true
		}
	}
	return false
}

// GetInfo returns information about a snapshot. vmrun exposes only the snapshot
// name (no creation time / parent / state), so only Name and Current are
// populated; Current is false because vmrun offers no "current snapshot" query.
// The snapshot's existence is verified first (via Exists) so a missing snapshot
// returns an error instead of a fabricated success.
func (s *SnapshotManager) GetInfo(vmName, snapshotName string) (backend.SnapshotInfo, error) {
	name := strings.TrimSpace(snapshotName)
	if !s.Exists(vmName, name) {
		return backend.SnapshotInfo{}, fmt.Errorf("snapshot %q not found for VM %q", name, vmName)
	}
	return backend.SnapshotInfo{Name: name}, nil
}
