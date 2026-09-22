//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

// VMManager implements backend.VMManager for libvirt.
type VMManager struct{}

// domainName returns the libvirt domain name for an instance.
func domainName(instanceName string) string {
	return "abox-" + instanceName
}

// Create defines a new VM in libvirt.
func (m *VMManager) Create(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	libvirtOpts := virsh.DomainXMLOptions{
		AssumeCloudInitExists: opts.AssumeCloudInitExists,
		MonitorEnabled:        opts.MonitorEnabled,
		UUID:                  opts.UUID,
		CustomTemplate:        opts.CustomTemplate,
	}

	xml, err := virsh.DomainXMLWithOptions(inst, paths, libvirtOpts)
	if err != nil {
		return fmt.Errorf("failed to generate domain XML: %w", err)
	}

	if err := virsh.DefineDomain(xml); err != nil {
		return fmt.Errorf("failed to define domain: %w", err)
	}

	return nil
}

// Start starts a defined VM.
func (m *VMManager) Start(ctx context.Context, name string) error {
	return virsh.StartDomain(domainName(name))
}

// Stop gracefully stops a running VM.
func (m *VMManager) Stop(ctx context.Context, name string) error {
	return virsh.StopDomain(domainName(name))
}

// ForceStop forcefully stops a running VM.
func (m *VMManager) ForceStop(ctx context.Context, name string) error {
	return virsh.ForceStopDomain(domainName(name))
}

// Remove removes a VM definition and its storage.
func (m *VMManager) Remove(ctx context.Context, name string) error {
	return virsh.DeleteDomain(domainName(name))
}

// Exists checks if a VM is defined.
func (m *VMManager) Exists(name string) bool {
	return virsh.DomainExists(domainName(name))
}

// IsRunning checks if a VM is currently running.
func (m *VMManager) IsRunning(name string) bool {
	return virsh.DomainIsRunning(domainName(name))
}

// State returns the current VM state.
func (m *VMManager) State(name string) backend.VMState {
	state := virsh.DomainState(domainName(name))
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

// GetIP returns the guest's static IP address. abox assigns every guest a static
// address at create (config.IPAddress, baked into cloud-init), so there is no DHCP
// lease to query — the configured address is authoritative (config-truth, not
// observed-truth). Note this reads config from disk on every call, so avoid it in
// hot loops where the caller already holds the Instance.
func (m *VMManager) GetIP(name string) (string, error) {
	inst, _, err := config.Load(name)
	if err != nil {
		return "", err
	}
	return inst.IPAddress, nil
}

// GetUUID returns the UUID of a defined VM.
func (m *VMManager) GetUUID(name string) string {
	return virsh.GetDomainUUID(domainName(name))
}

// Redefine updates an existing VM definition.
func (m *VMManager) Redefine(ctx context.Context, inst *config.Instance, paths *config.Paths, opts backend.VMCreateOptions) error {
	// Get existing UUID if not provided
	if opts.UUID == "" {
		opts.UUID = m.GetUUID(inst.Name)
	}
	return m.Create(ctx, inst, paths, opts)
}
