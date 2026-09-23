//go:build linux

package privilege

import (
	"context"
	"strings"
	"testing"
)

// TestApplyBuildsIPv6Chains asserts Apply installs the IPv6 default-deny for both
// families via ip6tables: chain created, ESTABLISHED accept + DROP appended, and
// a jump inserted at the top of INPUT and FORWARD.
func TestApplyBuildsIPv6Chains(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}

	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	v6ran := func(want ...string) bool {
		target := strings.Join(want, " ")
		for _, c := range f.v6RunCalls {
			if strings.Join(c, " ") == target {
				return true
			}
		}
		return false
	}

	for _, c := range []chainSpec{inputChain, forwardChain} {
		chain := c.name(testBridge)
		if !v6ran("-w", "-N", chain) {
			t.Errorf("Apply did not create ip6tables %s chain %s", c.parent, chain)
		}
		if !v6ran(establishedArgs("-A", chain)...) {
			t.Errorf("Apply did not append ip6tables ESTABLISHED accept to %s", chain)
		}
		if !v6ran(dropArgs("-A", chain)...) {
			t.Errorf("Apply did not append ip6tables DROP to %s", chain)
		}
		if !v6ran(c.insertJumpArgs(testBridge)...) {
			t.Errorf("Apply did not insert ip6tables %s jump", c.parent)
		}
	}
}

// TestApplyFailsClosedWhenIPv6LiveButIp6tablesMissing verifies the
// fail-closed contract: if the host has a live IPv6 stack but ip6tables is
// unavailable, Apply must fail (and roll back) rather than leave IPv6 unfiltered.
func TestApplyFailsClosedWhenIPv6LiveButIp6tablesMissing(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}

	// Simulate ip6tables absent but IPv6 enabled.
	iptablesMu.Lock()
	ip6tablesAbs = ""
	iptablesMu.Unlock()
	origEnabled := ipv6Enabled
	ipv6Enabled = func() bool { return true }
	t.Cleanup(func() { ipv6Enabled = origEnabled })

	if _, err := s.Apply(context.Background(), testEgressReq()); err == nil {
		t.Fatal("Apply must fail closed when IPv6 is live but ip6tables is missing")
	}
	// Rollback should have flushed the IPv4 rules it installed (best-effort);
	// at minimum no v6 rules were issued.
	if len(f.v6RunCalls) != 0 {
		t.Errorf("no ip6tables calls expected when ip6tables is unavailable, got: %v", f.v6RunCalls)
	}
}

// TestApplySkipsIPv6WhenDisabledAndIp6tablesMissing verifies the legitimate skip:
// ip6tables absent AND IPv6 disabled kernel-wide => Apply succeeds without v6
// rules, and alreadyApplied stays consistent (ipv6Applied returns true).
func TestApplySkipsIPv6WhenDisabledAndIp6tablesMissing(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}

	iptablesMu.Lock()
	ip6tablesAbs = ""
	iptablesMu.Unlock()
	origEnabled := ipv6Enabled
	ipv6Enabled = func() bool { return false }
	t.Cleanup(func() { ipv6Enabled = origEnabled })

	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Apply should succeed when IPv6 is disabled and ip6tables is missing: %v", err)
	}
	if len(f.v6RunCalls) != 0 {
		t.Errorf("no ip6tables calls expected, got: %v", f.v6RunCalls)
	}
	if !s.ipv6Applied(&ruleParams{bridge: testBridge}) {
		t.Error("ipv6Applied must be true when the legitimate skip was taken")
	}
}

// TestApplyReconcilesIPv6WhenAppliedLate verifies the reconciliation path:
// after a skip (ip6tables absent), a later Apply with ip6tables present must
// install the IPv6 rules rather than treat the instance as already-applied.
func TestApplyReconcilesIPv6WhenAppliedLate(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}

	// First Apply: IPv4 fully installed; ip6tables present (installFakeIptables
	// set it), so v6 is installed too.
	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if len(f.v6RunCalls) == 0 {
		t.Fatal("expected ip6tables rules on first Apply")
	}

	// Simulate the v6 rules having been wiped (e.g. ip6tables was absent at first
	// apply, installed later): clear v6 state, then a re-Apply must reinstall.
	f.v6Present = map[string]bool{}
	f.v6Chains = map[string]bool{}
	f.v6RunCalls = nil

	if s.alreadyApplied(&ruleParams{
		bridge: testBridge, guestDNS: testGuestDNS, dnsPort: testDNSPort, httpPort: testHTTPPort, gateway: testGateway,
	}) {
		t.Fatal("alreadyApplied must be false when IPv6 rules are missing")
	}
	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("reconciling Apply: %v", err)
	}
	if len(f.v6RunCalls) == 0 {
		t.Error("reconciling Apply must reinstall the IPv6 rules")
	}
}
