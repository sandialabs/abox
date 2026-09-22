//go:build linux

package libvirt

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/virsh"
)

// filterName returns the nwfilter name for an instance.
func filterName(instanceName string) string {
	return "abox-" + instanceName + "-traffic"
}

// EgressController implements backend.EgressController for libvirt.
// It enforces the egress policy with two mechanisms:
//   - an nwfilter (default-deny with holes for the DNS/HTTP filter endpoints)
//     bound to the VM's network interface, and
//   - host-side iptables rules (DNS REDIRECT to dnsfilter + INPUT accepts),
//     installed via the injected privileged enforcer.
//
// The nwfilter half needs no privilege (libvirtd applies it); the iptables half
// is the privileged part and is obtained lazily via enforcer so read-only paths
// (Verify) never trigger escalation.
type EgressController struct {
	egress.IptablesBase
}

// Define materializes and activates the pre-boot host-side enforcement
// (idempotent): it defines/updates the nwfilter and installs the host iptables
// rules (DNS REDIRECT + host accepts for the dnsfilter/httpfilter ports and
// ICMP). These must be in force before the guest boots so the guest's first
// DNS packets are handled. The nwfilter is bound to the live interface
// later, by Apply (which needs a running VM).
func (e *EgressController) Define(ctx context.Context, inst *config.Instance, p backend.EgressPolicy) error {
	// Get existing filter UUID if present, so we can update in-place.
	existingUUID := virsh.GetNWFilterUUID(filterName(inst.Name))

	// The nwfilter is generated from the same policy that drives the host
	// iptables rules below, so the two halves cannot drift.
	xml, err := virsh.NWFilterXML(inst, existingUUID, p.GuestDNSPort)
	if err != nil {
		return fmt.Errorf("failed to generate nwfilter XML: %w", err)
	}

	newlyDefined := existingUUID == ""
	if err := virsh.DefineNWFilter(xml); err != nil {
		return fmt.Errorf("failed to define nwfilter: %w", err)
	}

	// Install the privileged host-side rules (DNS REDIRECT + INPUT accepts).
	// If this fails, undefine the nwfilter we just created so we don't leave a
	// "defined but unenforced" state that Verify would report as in force.
	enf, err := e.Enforcer()
	if err != nil {
		if newlyDefined {
			_ = virsh.DeleteNWFilter(filterName(inst.Name))
		}
		return err
	}
	if err := enf.Apply(ctx, inst.Bridge, p); err != nil {
		if newlyDefined {
			_ = virsh.DeleteNWFilter(filterName(inst.Name))
		}
		return fmt.Errorf("failed to install host egress rules: %w", err)
	}

	return nil
}

// Apply binds the nwfilter to the running VM's network interface, activating
// L2 enforcement. The driver queue count must match the running VM's config.
func (e *EgressController) Apply(ctx context.Context, inst *config.Instance) error {
	return virsh.ApplyNWFilter(domainName(inst.Name), inst.Bridge, filterName(inst.Name), inst.MACAddress, inst.CPUs)
}

// Remove tears down enforcement (idempotent): it flushes the host-side iptables
// rules first, then deletes the nwfilter definition. The VM being destroyed
// implicitly unbinds the filter from its interface.
//
// If the privileged host-rule flush fails (e.g. no privilege available), the
// failure is surfaced loudly with the bridge name and manual-cleanup guidance —
// orphaned host rules outlive the nwfilter and the network, so a silent warning
// would hide a security-relevant leak. The nwfilter delete is still attempted so
// teardown makes as much progress as possible.
func (e *EgressController) Remove(ctx context.Context, inst *config.Instance) error {
	// Flush host-side rules first so they never outlive the nwfilter.
	manualCleanup := "remove leftover rules for " + inst.Bridge + " with: iptables -t nat -S | grep " + inst.Bridge
	if enf, err := e.Enforcer(); err != nil {
		backend.WarnEgressLeak("could not acquire egress enforcer to flush host rules; host iptables rules for the bridge may remain",
			inst.Name, "bridge", inst.Bridge, manualCleanup, err)
	} else if err := enf.Remove(ctx, inst.Bridge, backend.BuildEgressPolicy(inst)); err != nil {
		backend.WarnEgressLeak("failed to flush host egress rules; host iptables rules for the bridge may remain",
			inst.Name, "bridge", inst.Bridge, manualCleanup, err)
	}

	name := filterName(inst.Name)
	if !virsh.NWFilterExists(name) {
		return nil
	}
	return virsh.DeleteNWFilter(name)
}

// Verify reports whether the nwfilter is defined for the instance. This is
// intentionally unprivileged (nwfilter-only) so status/doctor never spawn the
// privileged helper. It does NOT confirm the host iptables rules — see
// VerifyEnforced for that.
func (e *EgressController) Verify(ctx context.Context, inst *config.Instance) (bool, error) {
	return virsh.NWFilterExists(filterName(inst.Name)), nil
}

// VerifyEnforced reports whether the privileged host-side rules (DNS REDIRECT +
// INPUT accepts) are currently in force for the instance's bridge. It uses the
// privileged enforcer, so it MAY trigger privilege escalation — only diagnostic
// callers (doctor) should use it.
func (e *EgressController) VerifyEnforced(ctx context.Context, inst *config.Instance) (bool, error) {
	enf, err := e.Enforcer()
	if err != nil {
		return false, err
	}
	return enf.Verify(ctx, inst.Bridge, backend.BuildEgressPolicy(inst))
}
