package firewall

import (
	"context"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/rpc"
	"github.com/sandialabs/abox/internal/timeout"
)

// storageEnforcer adapts an rpc.EgressClient to backend.StorageEnforcer. The
// privileged storage-root setup shares the Egress service (the single privileged
// helper), so it reuses the same client.
type storageEnforcer struct {
	priv rpc.EgressClient
}

// NewStorageEnforcer wraps a privileged client as a backend.StorageEnforcer.
func NewStorageEnforcer(priv rpc.EgressClient) backend.StorageEnforcer {
	return &storageEnforcer{priv: priv}
}

// EnsureStorageRoot provisions the caller's per-user disk storage root
// (idempotent). When regroup is set, the helper also restores the QEMU group +
// modes across the caller's own subtree (used by `abox migrate`).
func (e *storageEnforcer) EnsureStorageRoot(ctx context.Context, path string, regroup bool) error {
	logging.Debug("ensuring storage root", "path", path, "regroup", regroup)

	cctx, cancel := context.WithTimeout(ctx, timeout.Default)
	defer cancel()

	if _, err := e.priv.EnsureStorageRoot(cctx, &rpc.EnsureStorageRootReq{Path: path, Regroup: regroup}); err != nil {
		return err
	}

	logging.Audit("storage root ensured", "path", path, "regroup", regroup)
	return nil
}
