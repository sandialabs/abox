//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

// NetworkManager implements backend.NetworkManager for libvirt.
type NetworkManager struct{}

// Create defines a new network in libvirt.
func (m *NetworkManager) Create(ctx context.Context, inst *config.Instance) error {
	xml, err := virsh.NetworkXML(inst)
	if err != nil {
		return fmt.Errorf("failed to generate network XML: %w", err)
	}

	if err := virsh.DefineNetwork(xml); err != nil {
		return fmt.Errorf("failed to define network: %w", err)
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
