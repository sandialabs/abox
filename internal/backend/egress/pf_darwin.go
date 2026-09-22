//go:build darwin

package egress

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/firewall"
	"github.com/sandialabs/abox/internal/logging"
)

// PfBase is the shared, embeddable state + behavior of a pf egress controller. A
// backend's EgressController embeds it (as a value field) and adds only its own
// Define/Apply; the promoted Remove/Verify/VerifyEnforced methods then satisfy
// the rest of backend.EgressController.
//
// The privileged pf surface is obtained lazily via the injected Provider so
// read-only paths (Verify) never spawn the helper. The factory injects Provider
// after construction via each backend's SetPfProvider (backend.PfProviderSetter).
type PfBase struct {
	Provider backend.PfEnforcerProvider
}

// Enforcer resolves the injected privileged pf enforcer, or the shared
// fail-closed error when no provider was injected. It is exported because each
// backend's Define/Apply (in the vfkit/vmware packages) calls it across the
// package boundary.
func (b *PfBase) Enforcer() (backend.PfEnforcer, error) {
	if b.Provider == nil {
		return nil, errors.New("pf enforcer not configured (no privileged provider injected)")
	}
	return b.Provider()
}

// LoadInstanceAnchor builds the subnet-keyed ruleset for an instance and loads it
// into the per-instance pf anchor (abox/<instance>), then writes the unprivileged
// "applied" marker. It is the shared tail of each darwin backend's rule-loading
// path; the only per-backend difference is where iface comes from (vfkit resolves
// its vmnet bridge post-boot, vmware its vmnet interface pre-boot), so callers
// resolve iface and pass it in.
//
// The rules are built via the validated firewall.InstanceRules entry point, which
// rejects a malformed subnet/gateway/iface/port client-side before they reach the
// helper (which independently re-validates as the trust boundary). A marker-write
// failure is non-fatal: the anchor is already loaded (enforcement is in force), so
// a missing marker only weakens the unprivileged Verify signal.
func (b *PfBase) LoadInstanceAnchor(ctx context.Context, inst *config.Instance, iface string, policy backend.EgressPolicy) error {
	rules, err := firewall.InstanceRules(inst.Name, inst.Subnet, inst.Gateway, iface, policy.DNSPort, policy.HTTPPort)
	if err != nil {
		return fmt.Errorf("failed to build pf rules for instance %q: %w", inst.Name, err)
	}

	enf, err := b.Enforcer()
	if err != nil {
		return err
	}
	if err := enf.LoadAnchor(ctx, inst.Name, inst.Subnet, rules); err != nil {
		return fmt.Errorf("failed to load pf anchor for instance %q: %w", inst.Name, err)
	}

	if err := WriteMarker(inst.Name); err != nil {
		// The anchor is loaded (enforcement is in force); a missing marker only
		// weakens the unprivileged Verify signal, so warn rather than fail.
		logging.Warn("failed to write pf-applied marker; Verify may report unapplied despite rules being in force",
			"instance", inst.Name, "error", err)
	}
	return nil
}

// LoadPreBootDeny loads a minimal default-deny into the per-instance pf anchor
// before the VM boots, so the guest is fail-closed from its very first packet
// rather than governed only by the base pf.conf until Apply runs post-boot. It
// keys on the instance subnet (known pre-boot; no bridge or DHCP lease needed).
// Apply later replaces the anchor wholesale with the full ruleset. No "applied"
// marker is written here — the marker signals the full ruleset is in force
// (Verify), which the deny alone is not.
func (b *PfBase) LoadPreBootDeny(ctx context.Context, inst *config.Instance) error {
	// The pre-boot ruleset confines the wildcard-bound HTTP proxy to the guest
	// subnet, so it needs the resolved HTTP port (the same source Apply uses).
	policy := backend.BuildEgressPolicy(inst)
	rules, err := firewall.PreBootDenyRules(inst.Name, inst.Subnet, policy.HTTPPort)
	if err != nil {
		return fmt.Errorf("failed to build pre-boot deny rules for instance %q: %w", inst.Name, err)
	}
	enf, err := b.Enforcer()
	if err != nil {
		return err
	}
	if err := enf.LoadAnchor(ctx, inst.Name, inst.Subnet, rules); err != nil {
		return fmt.Errorf("failed to load pre-boot pf anchor for instance %q: %w", inst.Name, err)
	}
	return nil
}

// Remove flushes the per-instance pf anchor and removes the marker (idempotent).
// It does NOT call TeardownConfig: removing the global /etc/pf.conf anchor
// references is the job of `abox teardown-pf`, not per-instance teardown. A
// failure to acquire/flush is surfaced loudly (WarnEgressLeak) since orphaned pf
// rules would outlive the instance.
func (b *PfBase) Remove(ctx context.Context, inst *config.Instance) error {
	manualCleanup := fmt.Sprintf("flush the anchor with: sudo pfctl -a abox/%s -F all", inst.Name)
	if enf, err := b.Enforcer(); err != nil {
		backend.WarnEgressLeak("could not acquire pf enforcer to flush the instance anchor; pf rules may remain",
			inst.Name, "anchor", "abox/"+inst.Name, manualCleanup, err)
	} else if err := enf.FlushAnchor(ctx, inst.Name); err != nil {
		backend.WarnEgressLeak("failed to flush the instance pf anchor; pf rules may remain",
			inst.Name, "anchor", "abox/"+inst.Name, manualCleanup, err)
	}

	if err := os.Remove(MarkerPath(inst.Name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove pf marker for instance %q: %w", inst.Name, err)
	}
	return nil
}

// Verify reports whether the per-instance pf anchor has been applied. It is
// intentionally UNPRIVILEGED (status/doctor must never trigger escalation): it
// checks the marker file written when the anchor was loaded. A read-only pfctl
// anchor query would strengthen this later; it is deferred to avoid a new RPC.
func (b *PfBase) Verify(_ context.Context, inst *config.Instance) (bool, error) {
	return MarkerExists(inst.Name), nil
}

// VerifyEnforced reports whether the per-instance pf anchor was loaded, based on
// the unprivileged "applied" marker — the SAME signal as Verify. It is NOT a
// kernel-truth check: unlike the libvirt/vmware backends (which query the
// privileged host rules), this cannot detect an anchor flushed out from under a
// running guest by an external `pfctl -F`, because a read-only pfctl anchor query
// (`pfctl -a abox/<name> -sr`) needs root and would require a new privileged RPC.
// That is deliberately not claimed here: the method is honest that it reflects
// "abox loaded the anchor", not "the rules are currently in the kernel".
//
// This is a reporting-accuracy limitation only, not an enforcement gap: the
// per-instance rules are (re)asserted on every `abox start` (recoverDaemons →
// ApplyFiltered), independent of this signal.
func (b *PfBase) VerifyEnforced(_ context.Context, inst *config.Instance) (bool, error) {
	return MarkerExists(inst.Name), nil
}

// EnforcementIsAuthoritative reports false: VerifyEnforced here is the unprivileged
// applied-marker, not a live pfctl query (see VerifyEnforced above). It satisfies
// backend.EnforcementAuthority so diagnostic callers (doctor) label the macOS
// result honestly ("loaded") rather than as verified kernel truth ("active").
func (b *PfBase) EnforcementIsAuthoritative() bool { return false }

// MarkerPath returns the unprivileged marker file that records "the per-instance
// pf anchor has been loaded for this instance". It lives in the user runtime dir
// (falling back to the temp dir), so status/doctor Verify can answer without any
// privilege or pfctl query.
func MarkerPath(name string) string {
	return filepath.Join(config.RuntimeDirOr(os.TempDir()), fmt.Sprintf("abox-%s-pf.applied", name))
}

// WriteMarker writes the unprivileged "pf applied" marker file.
func WriteMarker(name string) error {
	return os.WriteFile(MarkerPath(name), []byte("applied\n"), 0o600)
}

// MarkerExists reports whether the pf-applied marker file is present.
func MarkerExists(name string) bool {
	_, err := os.Stat(MarkerPath(name))
	return err == nil
}
