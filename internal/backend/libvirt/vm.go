//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/libvirt"
)

// VMManager implements backend.VMManager for libvirt.
type VMManager struct{}

// domainName returns the libvirt domain name for an instance.
func domainName(instanceName string) string {
	return "abox-" + instanceName
}

// Create defines a new VM in libvirt.
func (m *VMManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	libvirtOpts := libvirt.DomainXMLOptions{
		AssumeCloudInitExists: opts.AssumeCloudInitExists,
		MonitorEnabled:        opts.MonitorEnabled,
		UUID:                  opts.UUID,
		CustomTemplate:        opts.CustomTemplate,
	}

	xml, err := libvirt.DomainXMLWithOptions(inst, paths, libvirtOpts)
	if err != nil {
		return fmt.Errorf("failed to generate domain XML: %w", err)
	}

	if err := libvirt.DefineDomain(xml); err != nil {
		return fmt.Errorf("failed to define domain: %w", err)
	}

	return nil
}

// Start starts a defined VM.
func (m *VMManager) Start(ctx context.Context, name string) error {
	return libvirt.StartDomain(domainName(name))
}

// Stop gracefully stops a running VM.
func (m *VMManager) Stop(ctx context.Context, name string) error {
	return libvirt.StopDomain(domainName(name))
}

// ForceStop forcefully stops a running VM.
func (m *VMManager) ForceStop(ctx context.Context, name string) error {
	return libvirt.ForceStopDomain(domainName(name))
}

// Remove removes a VM definition and its storage.
func (m *VMManager) Remove(ctx context.Context, name string) error {
	return libvirt.DeleteDomain(domainName(name))
}

// Exists checks if a VM is defined.
func (m *VMManager) Exists(name string) bool {
	return libvirt.DomainExists(domainName(name))
}

// IsRunning checks if a VM is currently running.
func (m *VMManager) IsRunning(name string) bool {
	return libvirt.DomainIsRunning(domainName(name))
}

// State returns the current VM state.
func (m *VMManager) State(name string) backend.VMState {
	state := libvirt.DomainState(domainName(name))
	switch state {
	case "running":
		return backend.VMStateRunning
	case "shut off":
		return backend.VMStateStopped
	case "paused":
		return backend.VMStatePaused
	case "crashed":
		return backend.VMStateCrashed
	case "shutdown":
		return backend.VMStateShutdown
	default:
		return backend.VMStateUnknown
	}
}

// GetIP returns the IP address of a running VM.
func (m *VMManager) GetIP(name string) (string, error) {
	return libvirt.GetDomainIP(domainName(name))
}

// GetUUID returns the UUID of a defined VM.
func (m *VMManager) GetUUID(name string) string {
	return libvirt.GetDomainUUID(domainName(name))
}

// Redefine updates an existing VM definition.
func (m *VMManager) Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	// Get existing UUID if not provided
	if opts.UUID == "" {
		opts.UUID = m.GetUUID(inst.Name)
	}
	return m.Create(ctx, inst, paths, opts)
}
