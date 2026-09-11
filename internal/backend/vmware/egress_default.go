//go:build !darwin

package vmware

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/vmrun"
)

// Compile-time assertions for the non-darwin (iptables) egress controller. On
// Linux/Windows the vmware backend enforces egress via the shared iptables
// enforcer, so it implements EgressProviderSetter. Blank-identifier vars may be
// declared repeatedly, so these coexist with the test-file assertions.
var (
	_ backend.EgressController     = (*EgressController)(nil)
	_ backend.EgressProviderSetter = (*Backend)(nil)
)

// SetEgressProvider injects the privileged iptables enforcer provider used by the
// egress controller to install host-side rules (DNS REDIRECT + INPUT accepts +
// per-bridge default-deny) on the instance's vmnet. Called by the factory after
// construction; satisfies backend.EgressProviderSetter. It exists only on
// non-darwin: on darwin the backend implements PfProviderSetter instead (see
// egress_darwin.go).
func (b *Backend) SetEgressProvider(p backend.EgressEnforcerProvider) {
	b.egress.Provider = p
}

// EgressController implements backend.EgressController for VMware.
//
// Enforcement model vs. libvirt: libvirt confines the guest with an nwfilter
// bound at the VM tap (default-deny for guest->internet AND guest->host) PLUS
// host iptables rules (DNS REDIRECT + accepts). VMware has NO nwfilter.
//
// guest->HOST is closed by the shared privileged enforcer's per-bridge INPUT
// default-deny (conntrack ESTABLISHED accept + a final DROP scoped to the
// interface), installed by Define.
//
// guest->internet is now defense-in-depth: (1) the host-only vmnet topology has
// no uplink/NAT, AND (2) for a vmnet interface the same enforcer installs a
// host-side FORWARD default-deny (conntrack ESTABLISHED accept + final DROP,
// jumped from FORWARD position 1 for `-i <vmnet>`). So even on a host with
// ip_forward=1 and a broad MASQUERADE covering the vmnet subnet (common with
// Docker/libvirt on a dev laptop), forwarded guest traffic is dropped rather than
// resting SOLELY on the (vnetlib-enforced but not yet host-verified) host-only
// assumption. See internal/vmrun/network.go for the host-only vnetlib caveat.
//
// The single most important consequence: for VMware there is NO per-VM packet
// filter to bind to the live interface, so Apply is a no-op — the host rules from
// Define ARE the enforcement. And there is no unprivileged enforcement half
// (no nwfilter definition), so Verify reports the pre-boot signal from the
// unprivileged vmnet allocation registry, while the real host-rule check lives in
// VerifyEnforced (privileged).
//
// The enforcer "bridge" is the instance's actual host interface — the allocated
// vmnet (e.g. "vmnet2"), NOT the logical inst.Bridge ("abox-<name>"). iptables
// rules must match the real interface packets arrive on.
type EgressController struct {
	egress.IptablesBase
}

// vnetFor (the iptables enforcement interface, e.g. "vmnet2") is shared with the
// darwin controller in helpers.go.

// Define installs the pre-boot host-side enforcement on the instance's vmnet
// (idempotent): the DNS REDIRECT to the dnsfilter port, the INPUT accepts for the
// dnsfilter/httpfilter/DHCP/ICMP traffic, the per-bridge INPUT default-deny
// (conntrack ESTABLISHED accept + final DROP), and — because the vmnet is a
// vmnet interface — a FORWARD default-deny so guest->internet is blocked at the
// host even if ip_forward + a broad MASQUERADE would otherwise route it. These
// must be in force before the guest boots so its first DHCP/DNS packets are
// handled and nothing else reaches the host or the internet. There is no nwfilter
// to materialize (VMware has none).
func (e *EgressController) Define(ctx context.Context, inst *config.Instance, p backend.EgressPolicy) error {
	vnet, err := vnetFor(inst)
	if err != nil {
		return err
	}
	enf, err := e.Enforcer()
	if err != nil {
		return err
	}
	if err := enf.Apply(ctx, vnet, p); err != nil {
		return fmt.Errorf("failed to install host egress rules for %s: %w", vnet, err)
	}
	// Fail closed: VMware has no unprivileged enforcement half to fall back on
	// (no nwfilter), so confirm the rules are actually in force before the guest
	// is allowed to boot. Without this, an Apply that reported success but did not
	// take — drift, a concurrent flush, or a host where the rules silently didn't
	// land — would leave the guest unfiltered while the unprivileged Verify (which
	// only checks the vmnet allocation registry) still reported the instance as
	// enforced. `abox start` calls Define, so a non-enforcing host now errors here
	// instead of booting an open guest.
	ok, err := enf.Verify(ctx, vnet, p)
	if err != nil {
		return fmt.Errorf("failed to verify host egress rules for %s: %w", vnet, err)
	}
	if !ok {
		return fmt.Errorf("host egress rules for %s are not in force after install; refusing to boot an unfiltered guest", vnet)
	}
	return nil
}

// Apply is a no-op for VMware. Unlike libvirt (which binds its nwfilter to the
// running VM's interface here), VMware has no per-VM packet filter to activate:
// the host iptables rules installed by Define ARE the enforcement, and they are
// already in force regardless of the VM's run state. Documented as a deliberate
// no-op so the lifecycle's post-boot Apply call is a harmless success.
func (e *EgressController) Apply(ctx context.Context, inst *config.Instance) error {
	return nil
}

// Remove flushes the host-side egress rules for the instance's vmnet (idempotent).
//
// If the enforcer cannot be acquired the failure is surfaced loudly with the vmnet
// name and manual-cleanup guidance: orphaned host rules would outlive the vmnet
// (and, once the vmnet number is later reused by another instance, could even
// mis-scope), so a silent warning would hide a security-relevant leak. Mirrors the
// libvirt Remove.
func (e *EgressController) Remove(ctx context.Context, inst *config.Instance) error {
	vnet, err := vnetFor(inst)
	if err != nil {
		// No vmnet recorded: nothing was ever installed, so there is nothing to
		// flush. Idempotent success.
		return nil //nolint:nilerr // absent vmnet means nothing to remove, not a failure
	}

	manualCleanup := "remove leftover rules for " + vnet + " with: iptables -S | grep " + vnet
	enf, err := e.Enforcer()
	if err != nil {
		backend.WarnEgressLeak("could not acquire egress enforcer to flush host rules; host iptables rules for the vmnet may remain",
			inst.Name, "vmnet", vnet, manualCleanup, err)
		return nil
	}
	if err := enf.Remove(ctx, vnet, backend.BuildEgressPolicy(inst)); err != nil {
		backend.WarnEgressLeak("failed to flush host egress rules; host iptables rules for the vmnet may remain",
			inst.Name, "vmnet", vnet, manualCleanup, err)
	}
	return nil
}

// Verify reports whether the pre-boot portion of enforcement exists. It is
// intentionally UNPRIVILEGED (status/doctor must never trigger escalation) and,
// because VMware has no unprivileged enforcement half (no nwfilter to inspect),
// it reports the closest unprivileged signal: whether abox has allocated and
// recorded a vmnet for the instance (the pre-boot resource the host rules are
// installed against). The real host-rule check is VerifyEnforced.
func (e *EgressController) Verify(ctx context.Context, inst *config.Instance) (bool, error) {
	paths, err := config.GetPathsWithStorage(inst.Name, inst.StorageDir)
	if err != nil {
		return false, fmt.Errorf("resolve paths: %w", err)
	}
	_, ok := vmrun.Lookup(registryPath(paths.Base), inst.Name)
	return ok, nil
}

// VerifyEnforced reports whether the privileged host-side rules (DNS REDIRECT +
// INPUT accepts + default-deny) are in force on the instance's vmnet. It uses the
// privileged enforcer, so it MAY trigger escalation — only diagnostic callers
// (doctor) should use it.
func (e *EgressController) VerifyEnforced(ctx context.Context, inst *config.Instance) (bool, error) {
	vnet, err := vnetFor(inst)
	if err != nil {
		return false, err
	}
	enf, err := e.Enforcer()
	if err != nil {
		return false, err
	}
	return enf.Verify(ctx, vnet, backend.BuildEgressPolicy(inst))
}
