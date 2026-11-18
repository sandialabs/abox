//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/virsh"
)

// NetworkManager implements backend.NetworkManager for libvirt.
type NetworkManager struct{}

// Create defines a new network in libvirt.
//
// After defining, it re-probes the subnets of every OTHER network defined on the
// shared libvirtd and backs out with backend.ErrSubnetConflict if one overlaps:
// subnet allocation and net-define are not atomic, so two users' concurrent
// creates can both probe a /24 as free and both define it (the per-user data-dir
// lock cannot serialize across users). Define-then-verify shrinks that race to
// the span between the two defines; callers retry allocation on the sentinel.
// The probe is fail-open (an empty result verifies clean), matching allocation.
func (m *NetworkManager) Create(ctx context.Context, inst *config.Instance) error {
	xml, err := virsh.NetworkXML(inst)
	if err != nil {
		return fmt.Errorf("failed to generate network XML: %w", err)
	}

	if err := virsh.DefineNetwork(xml); err != nil {
		return fmt.Errorf("failed to define network: %w", err)
	}

	if config.SubnetOverlapsDefined(inst.Subnet, virsh.ListNetworkSubnetsExcluding(inst.Bridge)) {
		if derr := virsh.DeleteNetwork(inst.Bridge); derr != nil {
			logging.Warn("failed to remove just-defined network after subnet conflict",
				"network", inst.Bridge, "error", derr)
		}
		return fmt.Errorf("subnet %s for network %s: %w", inst.Subnet, inst.Bridge, backend.ErrSubnetConflict)
	}

	return nil
}

// Start starts a defined network.
func (m *NetworkManager) Start(ctx context.Context, name string) error {
	return virsh.StartNetwork(name)
}

// Stop stops a running network.
func (m *NetworkManager) Stop(ctx context.Context, name string) error {
	return virsh.StopNetwork(name)
}

// Delete removes a network definition.
func (m *NetworkManager) Delete(ctx context.Context, name string) error {
	return virsh.DeleteNetwork(name)
}

// Exists checks if a network is defined.
func (m *NetworkManager) Exists(name string) bool {
	return virsh.NetworkExists(name)
}

// IsActive checks if a network is currently active.
func (m *NetworkManager) IsActive(name string) bool {
	return virsh.NetworkIsActive(name)
}
