//go:build darwin

package vmware

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
)

// Compile-time assertions for the darwin (pf) egress controller. On macOS the
// vmware/Fusion backend enforces egress via pfctl (iptables is absent), so it
// implements PfProviderSetter rather than EgressProviderSetter.
var (
	_ backend.EgressController = (*EgressController)(nil)
	_ backend.PfProviderSetter = (*Backend)(nil)
)

// EgressController implements backend.EgressController for the macOS/VMware
// (Fusion) backend using pfctl — the pf analogue of the iptables controller in
// egress_default.go. It confines the guest with a per-instance pf anchor
// (abox/<instance>) whose rules key on the instance's deterministic /24 subnet
// (see firewall.BuildInstanceRules): a DNS rdr to the local dnsfilter, an IPv6
// block on the VM's vmnet interface, explicit allows for the HTTP-proxy/ICMP,
// and a terminal default-deny.
//
// The shared pf machinery (marker-file Verify, anchor-flush Remove, the lazy
// enforcer accessor) lives in the embedded egress.PfBase; this type adds only
// the vmware-specific Define/Apply.
//
// Unlike vfkit — which learns its bridge (bridge100) only after the VM starts and
// therefore defers LoadAnchor to Apply — VMware allocates and records its vmnet
// interface (e.g. "vmnet2") in inst.BackendConfig["vnet"] BEFORE boot (see
// internal/vmrun/network.go). So this controller can both enable pf and load the
// per-instance anchor in Define, and Apply is a deliberate no-op (matching the
// non-darwin vmware controller). The enforcer "bridge" passed to pf is that vmnet
// interface (via vnetFor), NOT the logical inst.Bridge ("abox-<name>").
//
// EXPERIMENTAL: this wires pf enforcement, but the VMware/Fusion host-only
// network lifecycle is still TODO(real-host) (see internal/vmrun), so the backend
// remains unvalidated end-to-end on macOS.
type EgressController struct {
	egress.PfBase
}

// vnetFor (the pf enforcement interface, e.g. "vmnet2") is shared with the
// non-darwin controller in helpers.go.

// Define enables pf, wires the abox/* anchor references into /etc/pf.conf, and
// loads the per-instance anchor (idempotent). Unlike vfkit it does the full load
// here — the vmnet interface is known pre-boot (inst.BackendConfig["vnet"]), so
// there is no reason to defer to Apply. The rules key on the instance's /24
// subnet (not the DHCP IP), so they are complete before the guest has a lease.
// On success it writes an unprivileged marker so Verify can answer without
// privilege.
func (e *EgressController) Define(ctx context.Context, inst *config.Instance, p backend.EgressPolicy) error {
	vnet, err := vnetFor(inst)
	if err != nil {
		return err
	}
	enf, err := e.Enforcer()
	if err != nil {
		return err
	}
	if err := enf.Enable(ctx); err != nil {
		return fmt.Errorf("failed to enable pf for instance %q: %w", inst.Name, err)
	}
	// LoadInstanceAnchor is itself the fail-closed gate: pfctl returns an error if
	// the kernel rejects the ruleset, so a failed load surfaces here and the guest
	// never boots unfiltered. This is why there is no separate post-load Verify like
	// the non-darwin iptables path (egress_default.go) — a successful pfctl load
	// means the rules are in force.
	return e.LoadInstanceAnchor(ctx, inst, vnet, p)
}

// Apply is a no-op for the VMware backend: the vmnet interface is known pre-boot,
// so Define already loaded the per-instance anchor. Documented as a deliberate
// no-op so the lifecycle's post-boot Apply call is a harmless success (matching
// the non-darwin vmware controller). vfkit does its LoadAnchor here only because
// it learns its bridge post-boot.
func (e *EgressController) Apply(ctx context.Context, inst *config.Instance) error {
	return nil
}

// SetPfProvider injects the privileged pf enforcer provider used by the egress
// controller. Implements backend.PfProviderSetter (the pf analogue of
// EgressProviderSetter); the factory calls this after construction. It exists
// only on darwin: on non-darwin the backend implements EgressProviderSetter
// instead (see egress_default.go).
func (b *Backend) SetPfProvider(p backend.PfEnforcerProvider) {
	b.egress.Provider = p
}
