//go:build darwin

package vfkit

import (
	"context"
	"fmt"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/egress"
	"github.com/sandialabs/abox/internal/config"
)

// EgressController implements backend.EgressController for the macOS/vfkit
// backend using pfctl. It confines the guest with a per-instance pf anchor
// (abox/<instance>) whose rules key on the instance's deterministic /24 subnet
// (see firewall.BuildInstanceRules): a DNS rdr to the local dnsfilter, an IPv6
// block on the VM's bridge, explicit allows for the HTTP-proxy/ICMP, and a
// terminal default-deny.
//
// The shared pf machinery (marker-file Verify, anchor-flush Remove, the lazy
// enforcer accessor) lives in the embedded egress.PfBase; this type adds only
// the vfkit-specific Define/Apply. Enforcement is split across the generic
// egress lifecycle:
//   - Define (pre-boot): enable pf + wire /etc/pf.conf anchor refs. IP/bridge
//     independent, so it runs before the VM (and thus before the bridge) exists.
//   - Apply (post-boot): the vmnet bridge is now known (persisted by VM().Start
//     into inst.BackendConfig["bridge"]); build and load the per-instance anchor.
//
// Because rules key on the subnet (not a per-guest IP), Apply does NOT need to
// wait for the guest and can run before it is reachable.
type EgressController struct {
	egress.PfBase
}

// bridgeFor resolves the instance's vmnet bridge interface (e.g. "bridge100"),
// which VM().Start persists into inst.BackendConfig["bridge"] once the VM is up.
// If the in-memory instance predates that write, it reloads from disk before
// giving up, so a stale caller does not spuriously fail post-boot Apply.
func bridgeFor(inst *config.Instance) (string, error) {
	if b := bridgeFromConfig(inst); b != "" {
		return b, nil
	}
	// In-memory value may be stale (Apply is handed the pre-boot instance in some
	// flows); reload the persisted config, which VM().Start updated.
	if reloaded, _, err := config.Load(inst.Name); err == nil {
		if b := bridgeFromConfig(reloaded); b != "" {
			return b, nil
		}
	}
	return "", fmt.Errorf("no bridge recorded for instance %q (VM not started?); cannot load pf rules", inst.Name)
}

// bridgeFromConfig extracts the "bridge" string from an instance's BackendConfig.
func bridgeFromConfig(inst *config.Instance) string {
	s, _ := inst.BackendString(config.BackendKeyBridge)
	return s
}

// Define enables pf, wires the abox/* anchor references into /etc/pf.conf
// (idempotent, IP/bridge-independent), and loads the pre-boot ruleset into the
// per-instance anchor: the inbound HTTP-proxy confinement plus the IPv4 terminal
// default-deny. Loading these pre-boot closes the window in which the guest has a
// network but the anchor is empty (governed only by the base pf.conf, which
// passes traffic) AND the window in which the wildcard-bound proxy is reachable
// from off-host: the guest is fail-closed for IPv4 egress from its first packet.
// The pre-boot denies are IPv4-only; the interface-scoped IPv6 kill needs the
// vmnet bridge and so is added by the full ruleset that Apply loads once the VM
// has started (the pre-boot denies key on the subnet/port, known pre-boot).
func (e *EgressController) Define(ctx context.Context, inst *config.Instance, _ backend.EgressPolicy) error {
	enf, err := e.Enforcer()
	if err != nil {
		return err
	}
	if err := enf.Enable(ctx); err != nil {
		return fmt.Errorf("failed to enable pf for instance %q: %w", inst.Name, err)
	}
	// Always load the pre-boot deny, regardless of the persisted "applied" marker.
	// The marker records only that abox once loaded the full ruleset; it is NOT
	// kernel truth. It lives in $TMPDIR, which macOS preserves across reboots, so it
	// survives a host reboot (or an external `pfctl -F`) that wipes the actual pf
	// state — gating the deny on it would skip loading while the anchor is empty,
	// leaving the guest with unfiltered egress from its first packet until Apply
	// reloads the full rules post-boot. Loading the deny unconditionally keeps the
	// guest fail-closed from its first packet. The only cost is a brief deny-all on
	// a re-assert of an already-running guest (instance.ApplyFiltered calls
	// Define+Apply on every start) before Apply — invoked immediately after —
	// restores the full ruleset: an availability blip, never a fail-open.
	//
	// Fail-closed: if the pre-boot deny cannot be loaded, do not start the guest
	// unprotected — the caller (start) aborts on a Define error.
	return e.LoadPreBootDeny(ctx, inst)
}

// Apply loads the per-instance pf anchor. It runs AFTER VM start, so the vmnet
// bridge is known: it resolves the bridge (reloading the instance from disk if
// the in-memory copy is stale), builds the subnet-keyed ruleset, and loads it
// into abox/<instance>. On success it writes an unprivileged marker so Verify can
// answer without privilege.
func (e *EgressController) Apply(ctx context.Context, inst *config.Instance) error {
	bridge, err := bridgeFor(inst)
	if err != nil {
		return err
	}
	return e.LoadInstanceAnchor(ctx, inst, bridge, backend.BuildEgressPolicy(inst))
}
