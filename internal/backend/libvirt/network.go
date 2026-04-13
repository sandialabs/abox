//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/libvirt"
)

// NetworkManager implements backend.NetworkManager for libvirt.
type NetworkManager struct{}

// Create defines a new network in libvirt.
func (m *NetworkManager) Create(ctx context.Context, inst *config.Instance) error {
	xml, err := libvirt.NetworkXML(inst)
	if err != nil {
		return fmt.Errorf("failed to generate network XML: %w", err)
	}

	if err := libvirt.DefineNetwork(xml); err != nil {
		return fmt.Errorf("failed to define network: %w", err)
	}

	return nil
}

// Start starts a defined network.
func (m *NetworkManager) Start(ctx context.Context, name string) error {
	return libvirt.StartNetwork(name)
}

// Stop stops a running network.
func (m *NetworkManager) Stop(ctx context.Context, name string) error {
	return libvirt.StopNetwork(name)
}

// Delete removes a network definition.
func (m *NetworkManager) Delete(ctx context.Context, name string) error {
	return libvirt.DeleteNetwork(name)
}

// Exists checks if a network is defined.
func (m *NetworkManager) Exists(name string) bool {
	return libvirt.NetworkExists(name)
}

// IsActive checks if a network is currently active.
func (m *NetworkManager) IsActive(name string) bool {
	return libvirt.NetworkIsActive(name)
}
