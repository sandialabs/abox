//go:build linux

package libvirt

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/virsh"
)

// VMManager implements backend.VMManager for libvirt.
// Methods that receive only a bare instance name resolve the libvirt domain name
// through domainName in names.go, which re-reads the instance config on every
// call (no caching — the YAML read is noise next to the virsh exec it precedes).
type VMManager struct{}

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
//
// Legacy (pre-multi-user) names are shared across users, so before destroying a
// domain found under one — with --remove-all-storage, which makes a wrong match
// unrecoverable — verify one of its disks is this instance's disk, the same
// ownership gate UpgradeResourceNames applies. Fail closed on a probe error; a
// confirmed-foreign domain is left alone (nothing of ours lives under it) and
// the caller's instance-data removal proceeds. The name resolution and the gate
// deliberately come from ONE config load (not domainName plus a second load):
// two loads could disagree under a concurrent save, resolving the shared legacy
// name while skipping the gate that protects it.
func (m *VMManager) Remove(ctx context.Context, name string) error {
	inst, paths, err := config.Load(name)
	if err != nil {
		// Same fallback discipline as domainName: without a config that proves
		// the legacy scheme, never target the shared legacy name — the per-user
		// derivation is ours or absent.
		domain := config.DomainNameFor(os.Getuid(), name)
		logging.Warn("could not load instance config to resolve domain name for removal; assuming per-user scheme",
			"instance", name, "domain", domain, "error", err)
		return virsh.DeleteDomain(domain)
	}
	domain := inst.ResolvedVMName()
	if !inst.UsesCurrentNames() {
		// Fail closed through BOTH probes: a transient listing error must not
		// read as "absent" and skip the ownership gate — the fall-through below
		// destroys storage.
		exists, derr := virsh.DomainDefined(domain)
		if derr != nil {
			return fmt.Errorf("cannot verify legacy-named domain %s exists before removal: %w", domain, derr)
		}
		if exists {
			disks, derr := virsh.DomainDiskPaths(domain)
			if derr != nil {
				return fmt.Errorf("cannot verify ownership of legacy-named domain %s before removal: %w", domain, derr)
			}
			if !slices.Contains(disks, paths.Disk) {
				logging.Warn("legacy-named domain does not use this instance's disk (likely another user's same-named instance); leaving it alone",
					"instance", name, "domain", domain, "disk", paths.Disk)
				return nil
			}
		}
	}
	return virsh.DeleteDomain(domain)
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
