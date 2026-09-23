//go:build linux

package privilege

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sandialabs/abox/internal/logging"
)

// IPv6 default-deny.
//
// The IPv4 egress path (egress_linux.go) is blind to IPv6: `<all/>` nwfilter
// rules and every iptables rule match IPv4 only, so a guest that self-assigns a
// link-local fe80:: address on the host-only bridge could reach host services
// over IPv6. This file mirrors the IPv4 dedicated-chain default-deny using
// ip6tables. abox has no IPv6 use case (guests are statically IPv4-addressed via
// cloud-init, no uplink/RA), so the IPv6 chains are a pure default-deny: an
// ESTABLISHED,RELATED accept (so any return traffic survives) followed by a
// terminal DROP, jumped from the top of INPUT and FORWARD — no port accepts.
//
// The pure arg-builders (chainSpec.name / jumpArgs / insertJumpArgs /
// establishedArgs / dropArgs) are family-agnostic and reused here; only the
// command execution seams differ (ip6tablesRun/Check/List). ip6tables has its
// own rule namespace, so reusing the same chain names as the IPv4 path is safe.

// ipv6Enabled reports whether the host kernel has an active IPv6 stack, by
// checking /proc/net/if_inet6 (present and non-empty when IPv6 is enabled).
// Used to decide whether a missing ip6tables binary is fatal: if IPv6 is live
// but ip6tables is absent, abox cannot enforce the IPv6 deny and must fail
// closed rather than silently leave IPv6 unfiltered. It is a package var so
// tests can force the enabled/disabled decision.
var ipv6Enabled = func() bool {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		// No /proc/net/if_inet6 => IPv6 disabled/absent in the kernel.
		return false
	}
	return len(strings.TrimSpace(string(data))) > 0
}

// ensureIPv6Denied installs the IPv6 default-deny chains for a bridge. It is the
// IPv6 counterpart of buildChain+buildFwdChain, called from Apply after the IPv4
// rules are in place.
//
// Fail-closed contract: if ip6tables is unavailable we only proceed to skip when
// the kernel has no IPv6 stack at all; if IPv6 is enabled and ip6tables is
// missing we return an error so Apply aborts (and rolls back) rather than
// leaving IPv6 unfiltered under a running guest.
func (s *EgressServer) ensureIPv6Denied(r *ruleParams) error {
	if ip6tablesPath() == "" {
		if ipv6Enabled() {
			return errors.New("ip6tables not found but the host has an active IPv6 stack; " +
				"install ip6tables (or disable IPv6) so abox can enforce the IPv6 default-deny")
		}
		logging.Audit("privilege-helper.egress", "warning",
			"ip6tables not found and IPv6 disabled on host; skipping IPv6 default-deny", "bridge", r.bridge)
		return nil
	}

	if err := s.buildV6Chain(inputChain, r.bridge); err != nil {
		return err
	}
	return s.buildV6Chain(forwardChain, r.bridge)
}

// buildV6Chain (re)creates the dedicated per-bridge IPv6 chain for a family
// (INPUT or FORWARD), populates it in order (ESTABLISHED accept, final DROP), and
// ensures a single jump to it at the top of the parent chain. Idempotent, exactly
// like the IPv4 buildChain/buildFwdChain, but with no port accepts and via the
// ip6tables seams.
func (s *EgressServer) buildV6Chain(c chainSpec, bridge string) error {
	chain := c.name(bridge)

	// Ensure the chain exists (treat "already exists" as success), then flush it.
	if _, err := ip6tablesRun("-w", "-N", chain); err != nil {
		if _, lerr := ip6tablesList("-w", "-S", chain); lerr != nil {
			return fmt.Errorf("ip6tables create %s chain failed: %w", c.parent, err)
		}
	}
	if _, err := ip6tablesRun("-w", "-F", chain); err != nil {
		return fmt.Errorf("ip6tables flush %s chain failed: %w", c.parent, err)
	}

	// ESTABLISHED,RELATED accept first (return traffic survives), DROP last.
	if out, err := ip6tablesRun(establishedArgs("-A", chain)...); err != nil {
		return fmt.Errorf("ip6tables append established to %s failed: %s: %w", c.parent, string(out), err)
	}
	if out, err := ip6tablesRun(dropArgs("-A", chain)...); err != nil {
		return fmt.Errorf("ip6tables append drop to %s failed: %s: %w", c.parent, string(out), err)
	}

	// Ensure exactly one jump at the top of the parent chain.
	if ip6tablesCheck(c.jumpArgs("-C", bridge)...) {
		return nil
	}
	if out, err := ip6tablesRun(c.insertJumpArgs(bridge)...); err != nil {
		return fmt.Errorf("ip6tables insert %s jump failed: %s: %w", c.parent, string(out), err)
	}
	return nil
}

// flushV6Chains tears down the IPv6 default-deny for a bridge (both families):
// remove every parent->chain jump, then flush+delete the chain. Idempotent; a
// missing chain/jump is treated as done. Mirrors flushChainRules for the IPv6
// seams.
//
// When ip6tables is unavailable at teardown we cannot flush. If ip6tables was
// also absent at Apply, nothing was installed and this is genuinely a no-op — but
// if ip6tables was present at Apply and later removed from the host, the bridge's
// IPv6 chains are now orphaned and we cannot clean them up. We audit a warning in
// that case rather than silently reporting success, so the residual rules are at
// least discoverable. (We can't distinguish the two cases here, so warn whenever
// the host still shows a live IPv6 stack, where orphaned rules would matter.)
func (s *EgressServer) flushV6Chains(r *ruleParams) error {
	if ip6tablesPath() == "" {
		if ipv6Enabled() {
			logging.Audit("privilege-helper.egress", "warning",
				"ip6tables unavailable at teardown; any IPv6 default-deny chains previously installed for the bridge could not be removed and may be orphaned",
				"bridge", r.bridge)
		}
		return nil
	}
	return errors.Join(s.flushV6Chain(inputChain, r.bridge), s.flushV6Chain(forwardChain, r.bridge))
}

func (s *EgressServer) flushV6Chain(c chainSpec, bridge string) error {
	// Remove all jumps (bounded loop, matches removeAllJumps).
	for range maxFlushRules {
		if !ip6tablesCheck(c.jumpArgs("-C", bridge)...) {
			break
		}
		if _, err := ip6tablesRun(c.jumpArgs("-D", bridge)...); err != nil {
			return fmt.Errorf("deleting ip6tables %s jump for bridge %s: %w", c.parent, bridge, err)
		}
	}

	chain := c.name(bridge)
	// If the chain does not exist, nothing to delete.
	if _, err := ip6tablesList("-w", "-S", chain); err != nil {
		return nil //nolint:nilerr // a missing chain is success (nothing to delete)
	}
	if _, err := ip6tablesRun("-w", "-F", chain); err != nil {
		return fmt.Errorf("flushing ip6tables chain %s: %w", chain, err)
	}
	if _, err := ip6tablesRun("-w", "-X", chain); err != nil {
		return fmt.Errorf("deleting ip6tables chain %s: %w", chain, err)
	}
	return nil
}

// ipv6Applied reports whether the IPv6 default-deny (jump + chain ESTABLISHED
// accept + DROP) is present for both families. When ip6tables is unavailable it
// returns true iff IPv6 is also disabled on the host (i.e. the fail-closed skip
// in ensureIPv6Denied was legitimately taken), so Verify/alreadyApplied stay
// consistent with what Apply installed.
func (s *EgressServer) ipv6Applied(r *ruleParams) bool {
	if ip6tablesPath() == "" {
		return !ipv6Enabled()
	}
	for _, c := range []chainSpec{inputChain, forwardChain} {
		if !ip6tablesCheck(c.jumpArgs("-C", r.bridge)...) ||
			!ip6tablesCheck(establishedArgs("-C", c.name(r.bridge))...) ||
			!ip6tablesCheck(dropArgs("-C", c.name(r.bridge))...) {
			return false
		}
	}
	return true
}
