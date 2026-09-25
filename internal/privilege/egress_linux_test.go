//go:build linux

package privilege

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/rpc"
)

// fakeIptables installs test doubles for the iptablesRun/iptablesCheck/iptablesList
// seams and restores the originals on cleanup. It models enough iptables state for
// the dedicated-chain design: a set of "present" rules (answered by -C checks and
// mutated by add/delete), and a set of existing chains (created by -N, removed by
// -X; a -S <chain> on a missing chain errors, as real iptables does). It records
// every mutating arg vector so tests can assert the exact commands issued.
type fakeIptables struct {
	runCalls [][]string      // recorded mutating invocations (adds/deletes/chain ops)
	present  map[string]bool // set of "-C ..." joined args that report as present
	chains   map[string]bool // existing chain names

	// IPv6 family state (separate namespace, as real ip6tables is).
	v6RunCalls [][]string
	v6Present  map[string]bool
	v6Chains   map[string]bool
}

// installFakeIptables swaps the seams for the duration of the test. It fakes both
// the IPv4 (iptables) and IPv6 (ip6tables) families; the v6 path is given a
// resolved binary path so ip6tablesPath() is non-empty and ensureIPv6Denied
// exercises the install path rather than the fail-closed skip.
func installFakeIptables(t *testing.T) *fakeIptables {
	t.Helper()
	f := &fakeIptables{
		present: map[string]bool{}, chains: map[string]bool{},
		v6Present: map[string]bool{}, v6Chains: map[string]bool{},
	}

	origRun, origCheck, origList := iptablesRun, iptablesCheck, iptablesList
	orig6Run, orig6Check, orig6List := ip6tablesRun, ip6tablesCheck, ip6tablesList
	iptablesMu.Lock()
	origAbs, orig6Abs := iptablesAbs, ip6tablesAbs
	ip6tablesAbs = "/usr/sbin/ip6tables" // make ip6tablesPath() non-empty
	iptablesMu.Unlock()
	t.Cleanup(func() {
		iptablesRun, iptablesCheck, iptablesList = origRun, origCheck, origList
		ip6tablesRun, ip6tablesCheck, ip6tablesList = orig6Run, orig6Check, orig6List
		iptablesMu.Lock()
		iptablesAbs, ip6tablesAbs = origAbs, orig6Abs
		iptablesMu.Unlock()
	})

	iptablesRun = func(args ...string) ([]byte, error) {
		f.runCalls = append(f.runCalls, append([]string(nil), args...))
		applyMutation(f.present, f.chains, args)
		return nil, nil
	}
	iptablesCheck = func(args ...string) bool {
		return f.present[strings.Join(args, " ")]
	}
	iptablesList = func(args ...string) ([]byte, error) {
		return listChain(f.chains, args)
	}

	ip6tablesRun = func(args ...string) ([]byte, error) {
		f.v6RunCalls = append(f.v6RunCalls, append([]string(nil), args...))
		applyMutation(f.v6Present, f.v6Chains, args)
		return nil, nil
	}
	ip6tablesCheck = func(args ...string) bool {
		return f.v6Present[strings.Join(args, " ")]
	}
	ip6tablesList = func(args ...string) ([]byte, error) {
		return listChain(f.v6Chains, args)
	}
	return f
}

// listChain models `iptables -S <chain>`: built-ins always list; a dedicated
// chain lists only if it exists.
func listChain(chains map[string]bool, args []string) ([]byte, error) {
	chain := args[len(args)-1]
	if chain == "INPUT" || chain == "PREROUTING" || chain == "FORWARD" {
		return nil, nil
	}
	if !chains[chain] {
		return nil, errors.New("no such chain")
	}
	return nil, nil
}

// markV6Present marks the IPv6 default-deny rule set (both families) present, so
// alreadyApplied's ipv6Applied() check passes.
func (f *fakeIptables) markV6Present(bridge string) {
	for _, c := range []chainSpec{inputChain, forwardChain} {
		f.v6Chains[c.name(bridge)] = true
		f.v6Present[strings.Join(c.jumpArgs("-C", bridge), " ")] = true
		f.v6Present[strings.Join(establishedArgs("-C", c.name(bridge)), " ")] = true
		f.v6Present[strings.Join(dropArgs("-C", c.name(bridge)), " ")] = true
	}
}

// applyMutation updates the modeled state to mirror real iptables: -N creates a
// chain, -X removes it, -F is a no-op on state; an add (-A/-I) makes the
// corresponding -C check succeed and a delete (-D) makes it fail. This lets
// addNATRedirect's post-add verification and the jump idempotency (-C) work.
// present/chains are the family-specific state maps (IPv4 or IPv6).
func applyMutation(present, chains map[string]bool, args []string) {
	// Chain lifecycle verbs: "-w -N <chain>" / "-w -X <chain>".
	for i, a := range args {
		if a == "-N" && i+1 < len(args) {
			chains[args[i+1]] = true
			return
		}
		if a == "-X" && i+1 < len(args) {
			delete(chains, args[i+1])
			return
		}
		if a == "-F" {
			return // flush: no per-rule state modeled inside chains
		}
	}
	// Rule add/delete verbs: translate to the -C form and flip presence. Skip a
	// leading position argument (e.g. "-I INPUT 1 ...") so the -C form matches the
	// builder's check vector (which carries no position).
	check := append([]string(nil), args...)
	for i, a := range check {
		switch a {
		case "-A", "-I":
			check[i] = "-C"
			present[strings.Join(stripInsertPos(check), " ")] = true
			return
		case "-D":
			check[i] = "-C"
			delete(present, strings.Join(check, " "))
			return
		}
	}
}

// stripInsertPos removes a bare numeric position token that follows a built-in
// chain name in an insert form (e.g. "-C INPUT 1 -i ..." -> "-C INPUT -i ...", and
// likewise for FORWARD), so the modeled -C key matches the check builder which
// never includes a position.
func stripInsertPos(args []string) []string {
	out := make([]string, 0, len(args))
	for i, a := range args {
		if i > 0 && a == "1" && (args[i-1] == "INPUT" || args[i-1] == "FORWARD") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// ranWith reports whether any recorded iptablesRun call exactly matches want.
func (f *fakeIptables) ranWith(want ...string) bool {
	target := strings.Join(want, " ")
	for _, c := range f.runCalls {
		if strings.Join(c, " ") == target {
			return true
		}
	}
	return false
}

// countRan returns how many recorded iptablesRun calls exactly match want.
func (f *fakeIptables) countRan(want ...string) int {
	target := strings.Join(want, " ")
	n := 0
	for _, c := range f.runCalls {
		if strings.Join(c, " ") == target {
			n++
		}
	}
	return n
}

// markPresent records an arg vector (as passed to a -C check) as existing.
func (f *fakeIptables) markPresent(args ...string) {
	f.present[strings.Join(args, " ")] = true
}

// inputNATRuleSet marks every rule in the INPUT+NAT desired set as present (and the
// INPUT chain as existing), mirroring the INPUT/NAT portion of alreadyApplied's
// check set. It deliberately does NOT mark the FORWARD default-deny (see
// markFwdPresent / completeRuleSet), so tests can drive the "FORWARD required"
// path. The ports are the shared test constants.
func (f *fakeIptables) inputNATRuleSet(bridge string) {
	f.chains[inputChain.name(bridge)] = true
	f.markPresent(natRedirectArgs("-C", bridge, protoUDP, testGuestDNS, testDNSPort)...)
	f.markPresent(natRedirectArgs("-C", bridge, protoTCP, testGuestDNS, testDNSPort)...)
	f.markPresent(inputChain.jumpArgs("-C", bridge)...)
	f.markPresent(establishedArgs("-C", inputChain.name(bridge))...)
	f.markPresent(chainAcceptArgs("-C", bridge, protoUDP, testDNSPort, "")...)
	f.markPresent(chainAcceptArgs("-C", bridge, protoTCP, testDNSPort, "")...)
	f.markPresent(chainAcceptArgs("-C", bridge, protoTCP, testHTTPPort, testGateway)...)
	f.markPresent(chainICMPAcceptArgs("-C", bridge, testGateway)...)
	f.markPresent(dropArgs("-C", inputChain.name(bridge))...)
}

// completeRuleSet marks the FULL desired egress rule set present for a bridge: the
// INPUT+NAT set AND the FORWARD default-deny (jump + chain ESTABLISHED accept +
// DROP), so alreadyApplied returns true. The FORWARD chain is now built for EVERY
// abox-managed bridge (libvirt and vmnet alike), so it is part of the complete set
// for all bridges. Mirrors alreadyApplied's check set.
func (f *fakeIptables) completeRuleSet(bridge string) {
	f.inputNATRuleSet(bridge)
	f.markFwdPresent(bridge)
	f.markV6Present(bridge)
}

// markFwdPresent marks the FORWARD default-deny rule set (jump + chain ESTABLISHED
// accept + DROP) present for a bridge, mirroring fwdApplied's check set.
func (f *fakeIptables) markFwdPresent(bridge string) {
	f.chains[forwardChain.name(bridge)] = true
	f.markPresent(forwardChain.jumpArgs("-C", bridge)...)
	f.markPresent(establishedArgs("-C", forwardChain.name(bridge))...)
	f.markPresent(dropArgs("-C", forwardChain.name(bridge))...)
}

const (
	testBridge   = "abox-dev"
	testGuestDNS = "53"
	testDNSPort  = "34711"
	testHTTPPort = "45123"
	testGateway  = "10.20.30.1"
)

func testEgressReq() *rpc.EgressReq {
	return &rpc.EgressReq{Bridge: testBridge, DnsPort: 34711, HttpPort: 45123, GuestDnsPort: 53, Gateway: testGateway}
}

// TestChainNameLimit guards the iptables 29-char chain-name limit and determinism.
func TestChainNameLimit(t *testing.T) {
	for _, bridge := range []string{"abox-dev", "abox-a-very-long-instance-name-that-exceeds-things", "ab-0123456789abcdef"} {
		name := inputChain.name(bridge)
		if len(name) > 29 {
			t.Errorf("chainName(%q) = %q is %d chars, exceeds iptables 29-char limit", bridge, name, len(name))
		}
		if !strings.HasPrefix(name, chainPrefix) {
			t.Errorf("chainName(%q) = %q missing prefix %q", bridge, name, chainPrefix)
		}
		if name != inputChain.name(bridge) {
			t.Errorf("chainName(%q) not deterministic", bridge)
		}
	}
	// Distinct bridges get distinct chains.
	if inputChain.name("abox-a") == inputChain.name("abox-b") {
		t.Error("distinct bridges must map to distinct chains")
	}
}

// TestApplyBuildsChainInOrder asserts Apply creates+flushes the dedicated chain,
// populates it IN ORDER (ESTABLISHED accept, DNS/HTTP/ICMP accepts, final DROP)
// with `-A <chain>`, and installs a single jump at the top of INPUT.
func TestApplyBuildsChainInOrder(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	chain := inputChain.name(testBridge)

	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Chain created and flushed.
	if !f.ranWith("-w", "-N", chain) {
		t.Errorf("Apply did not create chain %s\nissued: %v", chain, f.runCalls)
	}
	if !f.ranWith("-w", "-F", chain) {
		t.Errorf("Apply did not flush chain %s", chain)
	}

	// Expected chain contents, in append order.
	wantOrder := [][]string{
		establishedArgs("-A", inputChain.name(testBridge)),
		chainAcceptArgs("-A", testBridge, protoUDP, testDNSPort, ""),
		chainAcceptArgs("-A", testBridge, protoTCP, testDNSPort, ""),
		chainAcceptArgs("-A", testBridge, protoTCP, testHTTPPort, testGateway),
		chainICMPAcceptArgs("-A", testBridge, testGateway),
		dropArgs("-A", inputChain.name(testBridge)),
	}
	// Find the index of each in runCalls and assert strictly increasing (order).
	idx := func(want []string) int {
		target := strings.Join(want, " ")
		for i, c := range f.runCalls {
			if strings.Join(c, " ") == target {
				return i
			}
		}
		return -1
	}
	prev := -1
	for _, w := range wantOrder {
		at := idx(w)
		if at < 0 {
			t.Fatalf("chain rule not issued: %v\nissued: %v", w, f.runCalls)
		}
		if at <= prev {
			t.Errorf("chain rule out of order: %v at %d, prev %d", w, at, prev)
		}
		prev = at
	}

	// ESTABLISHED must be first and DROP last in the chain.
	if idx(establishedArgs("-A", inputChain.name(testBridge))) != idx(wantOrder[0]) {
		t.Error("ESTABLISHED accept must be the first chain rule")
	}
	if idx(dropArgs("-A", inputChain.name(testBridge))) != prev {
		t.Error("DROP must be the last chain rule")
	}

	// Single jump at the TOP of INPUT (position 1).
	wantJump := inputChain.insertJumpArgs(testBridge)
	if !f.ranWith(wantJump...) {
		t.Errorf("Apply did not install top-of-INPUT jump %v\nissued: %v", wantJump, f.runCalls)
	}
	if got := strings.Join(wantJump[:5], " "); got != "-w -I INPUT 1 -i" {
		t.Errorf("jump not inserted at position 1: %q", got)
	}
}

// TestApplyIdempotentNoDuplicateJump confirms a second Apply on an already-complete
// state is a no-op (no mutating commands at all, so no stacked jump).
func TestApplyIdempotentNoDuplicateJump(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	f.completeRuleSet(testBridge)

	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(f.runCalls) != 0 {
		t.Errorf("second Apply should be a no-op, but issued: %v", f.runCalls)
	}
}

// TestApplyRebuildEndsWithSingleJump confirms that when a rebuild runs (chain
// rules absent) while a jump already exists, Apply ends with EXACTLY ONE jump: the
// pre-flush removes the stale jump and ensureJump re-inserts a single one — it
// never stacks a duplicate. We assert the net inserts (1) minus deletes (1) leaves
// one jump, and that ensureJump only inserts when the jump is absent.
func TestApplyRebuildEndsWithSingleJump(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	// Pre-existing jump, but the chain rules are absent so alreadyApplied is false
	// and a rebuild runs.
	f.markPresent(inputChain.jumpArgs("-C", testBridge)...)

	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// A rebuild removes the stale jump (pre-flush) then re-inserts one: at most a
	// single insert, and the final state has the jump present (reachable, single).
	if n := f.countRan(inputChain.insertJumpArgs(testBridge)...); n != 1 {
		t.Errorf("jump inserted %d times during rebuild, want exactly 1 (no stacking)", n)
	}
	if !f.present[strings.Join(inputChain.jumpArgs("-C", testBridge), " ")] {
		t.Error("after rebuild the INPUT jump must be present")
	}
}

// TestEnsureJumpSkipsWhenPresent isolates the anti-stack guard: ensureJump must
// NOT insert when the jump already exists.
func TestEnsureJumpSkipsWhenPresent(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	f.markPresent(inputChain.jumpArgs("-C", testBridge)...)

	if err := s.ensureJump(inputChain, testBridge); err != nil {
		t.Fatalf("ensureJump: %v", err)
	}
	if f.countRan(inputChain.insertJumpArgs(testBridge)...) != 0 {
		t.Errorf("ensureJump inserted a jump despite one already existing: %v", f.runCalls)
	}
}

// TestAlreadyAppliedRequiresChainAndJump confirms alreadyApplied (and thus Verify
// and the Apply no-op) requires the jump AND every chain rule.
func TestAlreadyAppliedRequiresChainAndJump(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	r := &ruleParams{bridge: testBridge, guestDNS: testGuestDNS, dnsPort: testDNSPort, httpPort: testHTTPPort, gateway: testGateway}

	// NAT + all chain rules present but NO jump -> not applied (deny unreachable).
	f.markPresent(natRedirectArgs("-C", testBridge, protoUDP, testGuestDNS, testDNSPort)...)
	f.markPresent(natRedirectArgs("-C", testBridge, protoTCP, testGuestDNS, testDNSPort)...)
	f.markPresent(establishedArgs("-C", inputChain.name(testBridge))...)
	f.markPresent(chainAcceptArgs("-C", testBridge, protoUDP, testDNSPort, "")...)
	f.markPresent(chainAcceptArgs("-C", testBridge, protoTCP, testDNSPort, "")...)
	f.markPresent(chainAcceptArgs("-C", testBridge, protoTCP, testHTTPPort, testGateway)...)
	f.markPresent(chainICMPAcceptArgs("-C", testBridge, testGateway)...)
	f.markPresent(dropArgs("-C", inputChain.name(testBridge))...)
	f.markFwdPresent(testBridge)
	f.markV6Present(testBridge)
	if s.alreadyApplied(r) {
		t.Fatal("alreadyApplied must be false without the INPUT jump")
	}

	// Add the jump -> complete (INPUT chain + jump + FORWARD default-deny + IPv6).
	f.markPresent(inputChain.jumpArgs("-C", testBridge)...)
	if !s.alreadyApplied(r) {
		t.Fatal("alreadyApplied must be true with jump + full chain + FORWARD + IPv6")
	}

	// Remove the DROP -> incomplete again.
	delete(f.present, strings.Join(dropArgs("-C", inputChain.name(testBridge)), " "))
	if s.alreadyApplied(r) {
		t.Fatal("alreadyApplied must be false without the chain DROP")
	}
}

// TestVerifyRequiresChainAndJump drives Verify through the RPC surface.
func TestVerifyRequiresChainAndJump(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}

	resp, err := s.Verify(context.Background(), testEgressReq())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if resp.GetOk() {
		t.Fatal("Verify should be false when nothing is present")
	}

	f.completeRuleSet(testBridge)
	resp, err = s.Verify(context.Background(), testEgressReq())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !resp.GetOk() {
		t.Fatal("Verify should be true with jump + full chain")
	}
}

// TestRemoveDeletesJumpAndChain confirms Remove deletes the INPUT jump, then
// flushes and deletes the dedicated chain, plus flushes the NAT REDIRECT.
func TestRemoveDeletesJumpAndChain(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	chain := inputChain.name(testBridge)

	// Model an installed state: chain exists and the jump is present.
	f.chains[chain] = true
	f.markPresent(inputChain.jumpArgs("-C", testBridge)...)

	if _, err := s.Remove(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if !f.ranWith(inputChain.jumpArgs("-D", testBridge)...) {
		t.Errorf("Remove did not delete INPUT jump\nissued: %v", f.runCalls)
	}
	if !f.ranWith("-w", "-F", chain) {
		t.Errorf("Remove did not flush chain %s", chain)
	}
	if !f.ranWith("-w", "-X", chain) {
		t.Errorf("Remove did not delete chain %s", chain)
	}
}

// TestRemoveLeavesOperatorRulesUntouched is a regression guard: because all
// abox INPUT rules live in the dedicated chain and teardown is a whole-chain
// delete, an operator's own `-i <bridge> ... -j DROP` (or any other) INPUT rule is
// NEVER pattern-matched or deleted. We assert the ONLY INPUT-level delete Remove
// issues is the jump (never a bare INPUT rule delete).
func TestRemoveLeavesOperatorRulesUntouched(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	f.chains[inputChain.name(testBridge)] = true
	f.markPresent(inputChain.jumpArgs("-C", testBridge)...)

	if _, err := s.Remove(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// An operator DROP/ACCEPT directly in INPUT would be deleted via a
	// "-w -D INPUT -i abox-dev -j DROP" style command. Remove must issue exactly
	// one INPUT delete: the jump. Any INPUT -D that is not the jump is a bug.
	jump := strings.Join(inputChain.jumpArgs("-D", testBridge), " ")
	for _, c := range f.runCalls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "-D INPUT") && joined != jump {
			t.Errorf("Remove issued a non-jump INPUT delete (could hit operator rules): %q", joined)
		}
	}
}

// TestRemoveIdempotentNoJumpNoChain confirms Remove is a clean success when there
// is nothing to remove (no jump, no chain): it must not error or delete anything.
func TestRemoveIdempotentNoJumpNoChain(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}

	if _, err := s.Remove(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Remove (nothing installed) should succeed: %v", err)
	}
	if f.ranWith(inputChain.jumpArgs("-D", testBridge)...) {
		t.Error("Remove should not attempt a jump delete when no jump exists")
	}
	if f.ranWith("-w", "-X", inputChain.name(testBridge)) {
		t.Error("Remove should not attempt a chain delete when no chain exists")
	}
}

const testVMNet = "vmnet7"

func testVMNetReq() *rpc.EgressReq {
	return &rpc.EgressReq{Bridge: testVMNet, DnsPort: 34711, HttpPort: 45123, GuestDnsPort: 53, Gateway: testGateway}
}

// TestFwdChainNameDistinctAndBounded confirms the FORWARD chain name is distinct
// from the INPUT chain name for the same bridge and stays within the 29-char limit.
func TestFwdChainNameDistinctAndBounded(t *testing.T) {
	for _, bridge := range []string{"vmnet2", "vmnet19", "abox-dev"} {
		in := inputChain.name(bridge)
		fwd := forwardChain.name(bridge)
		if in == fwd {
			t.Errorf("fwdChainName(%q) == chainName(%q) = %q; must be distinct", bridge, bridge, in)
		}
		if len(fwd) > 29 {
			t.Errorf("fwdChainName(%q) = %q is %d chars, exceeds 29-char limit", bridge, fwd, len(fwd))
		}
		if !strings.HasPrefix(fwd, fwdChainPrefix) {
			t.Errorf("fwdChainName(%q) = %q missing prefix %q", bridge, fwd, fwdChainPrefix)
		}
	}
}

// TestApplyBuildsForwardChainForVMNet asserts that for a vmnet bridge Apply builds
// the FORWARD default-deny chain (ESTABLISHED accept before DROP) and installs the
// FORWARD jump at position 1, in addition to the INPUT chain.
func TestApplyBuildsForwardChainForVMNet(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	fwdChain := forwardChain.name(testVMNet)

	if _, err := s.Apply(context.Background(), testVMNetReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// FORWARD chain created and flushed.
	if !f.ranWith("-w", "-N", fwdChain) {
		t.Errorf("Apply did not create FORWARD chain %s\nissued: %v", fwdChain, f.runCalls)
	}
	if !f.ranWith("-w", "-F", fwdChain) {
		t.Errorf("Apply did not flush FORWARD chain %s", fwdChain)
	}

	// ESTABLISHED accept and DROP present, established BEFORE drop.
	idx := func(want []string) int {
		target := strings.Join(want, " ")
		for i, c := range f.runCalls {
			if strings.Join(c, " ") == target {
				return i
			}
		}
		return -1
	}
	est := idx(establishedArgs("-A", forwardChain.name(testVMNet)))
	drop := idx(dropArgs("-A", forwardChain.name(testVMNet)))
	if est < 0 {
		t.Fatalf("FORWARD ESTABLISHED accept not issued\nissued: %v", f.runCalls)
	}
	if drop < 0 {
		t.Fatalf("FORWARD DROP not issued\nissued: %v", f.runCalls)
	}
	if est >= drop {
		t.Errorf("FORWARD ESTABLISHED (at %d) must precede DROP (at %d)", est, drop)
	}

	// FORWARD jump at position 1.
	wantJump := forwardChain.insertJumpArgs(testVMNet)
	if !f.ranWith(wantJump...) {
		t.Errorf("Apply did not install top-of-FORWARD jump %v\nissued: %v", wantJump, f.runCalls)
	}
	if got := strings.Join(wantJump[:5], " "); got != "-w -I FORWARD 1 -i" {
		t.Errorf("FORWARD jump not inserted at position 1: %q", got)
	}
}

// TestApplyBuildsForwardForLibvirtBridge is the host-only migration guard: after
// the migration an "abox-*" (libvirt) bridge ALSO gets the FORWARD default-deny
// chain (ESTABLISHED accept before DROP) plus the top-of-FORWARD jump, exactly like
// a vmnet bridge (defense-in-depth on top of the host-only topology).
func TestApplyBuildsForwardForLibvirtBridge(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	fwdChain := forwardChain.name(testBridge)

	if _, err := s.Apply(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// FORWARD chain created and flushed for the libvirt bridge.
	if !f.ranWith("-w", "-N", fwdChain) {
		t.Errorf("Apply did not create FORWARD chain %s for libvirt bridge\nissued: %v", fwdChain, f.runCalls)
	}
	if !f.ranWith("-w", "-F", fwdChain) {
		t.Errorf("Apply did not flush FORWARD chain %s", fwdChain)
	}

	// ESTABLISHED accept before DROP.
	idx := func(want []string) int {
		target := strings.Join(want, " ")
		for i, c := range f.runCalls {
			if strings.Join(c, " ") == target {
				return i
			}
		}
		return -1
	}
	est := idx(establishedArgs("-A", forwardChain.name(testBridge)))
	drop := idx(dropArgs("-A", forwardChain.name(testBridge)))
	if est < 0 {
		t.Fatalf("FORWARD ESTABLISHED accept not issued for libvirt bridge\nissued: %v", f.runCalls)
	}
	if drop < 0 {
		t.Fatalf("FORWARD DROP not issued for libvirt bridge\nissued: %v", f.runCalls)
	}
	if est >= drop {
		t.Errorf("FORWARD ESTABLISHED (at %d) must precede DROP (at %d)", est, drop)
	}

	// FORWARD jump at position 1.
	wantJump := forwardChain.insertJumpArgs(testBridge)
	if !f.ranWith(wantJump...) {
		t.Errorf("Apply did not install top-of-FORWARD jump %v for libvirt bridge\nissued: %v", wantJump, f.runCalls)
	}
	if got := strings.Join(wantJump[:5], " "); got != "-w -I FORWARD 1 -i" {
		t.Errorf("FORWARD jump not inserted at position 1: %q", got)
	}
}

// TestAlreadyAppliedRequiresForward confirms that after the host-only migration
// alreadyApplied (and thus Verify and the Apply no-op) requires the FORWARD
// default-deny in addition to the INPUT+NAT set, for BOTH a libvirt (abox-*) and a
// vmnet bridge — the vmnet-vs-libvirt distinction is gone. It flips to false when
// the FORWARD DROP is missing.
func TestAlreadyAppliedRequiresForward(t *testing.T) {
	for _, bridge := range []string{testBridge, testVMNet} {
		t.Run(bridge, func(t *testing.T) {
			f := installFakeIptables(t)
			s := &EgressServer{}
			r := &ruleParams{bridge: bridge, guestDNS: testGuestDNS, dnsPort: testDNSPort, httpPort: testHTTPPort, gateway: testGateway}

			// Full INPUT+NAT set (and IPv6) but NO FORWARD rules -> not applied.
			f.inputNATRuleSet(bridge)
			f.markV6Present(bridge)
			if s.alreadyApplied(r) {
				t.Fatalf("%s alreadyApplied must be false without the FORWARD default-deny", bridge)
			}

			// Add the FORWARD rules -> complete.
			f.markFwdPresent(bridge)
			if !s.alreadyApplied(r) {
				t.Fatalf("%s alreadyApplied must be true with INPUT+NAT+FORWARD+IPv6 present", bridge)
			}

			// Remove the FORWARD DROP -> incomplete again.
			delete(f.present, strings.Join(dropArgs("-C", forwardChain.name(bridge)), " "))
			if s.alreadyApplied(r) {
				t.Fatalf("%s alreadyApplied must be false without the FORWARD DROP", bridge)
			}
		})
	}
}

// TestApplyIdempotentVMNetNoRebuild confirms a second Apply for a vmnet whose full
// set (INPUT+NAT+FORWARD) is already present is a complete no-op.
func TestApplyIdempotentVMNetNoRebuild(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	f.completeRuleSet(testVMNet)

	if _, err := s.Apply(context.Background(), testVMNetReq()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(f.runCalls) != 0 {
		t.Errorf("second vmnet Apply should be a no-op, but issued: %v", f.runCalls)
	}
}

// TestRemoveDeletesForwardChainForVMNet confirms Remove deletes the FORWARD jump,
// then flushes and deletes the dedicated FORWARD chain for a vmnet.
func TestRemoveDeletesForwardChainForVMNet(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	fwdChain := forwardChain.name(testVMNet)

	// Model installed state: both chains exist and both jumps present.
	f.chains[inputChain.name(testVMNet)] = true
	f.chains[fwdChain] = true
	f.markPresent(inputChain.jumpArgs("-C", testVMNet)...)
	f.markPresent(forwardChain.jumpArgs("-C", testVMNet)...)

	if _, err := s.Remove(context.Background(), testVMNetReq()); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if !f.ranWith(forwardChain.jumpArgs("-D", testVMNet)...) {
		t.Errorf("Remove did not delete FORWARD jump\nissued: %v", f.runCalls)
	}
	if !f.ranWith("-w", "-F", fwdChain) {
		t.Errorf("Remove did not flush FORWARD chain %s", fwdChain)
	}
	if !f.ranWith("-w", "-X", fwdChain) {
		t.Errorf("Remove did not delete FORWARD chain %s", fwdChain)
	}
}

// TestRemoveDeletesForwardChainForLibvirtBridge confirms Remove now tears down the
// FORWARD default-deny (jump + chain) for an "abox-*" bridge too, since after the
// host-only migration the FORWARD chain is built for every abox-managed bridge.
func TestRemoveDeletesForwardChainForLibvirtBridge(t *testing.T) {
	f := installFakeIptables(t)
	s := &EgressServer{}
	fwdChain := forwardChain.name(testBridge)

	// Model installed state: both chains exist and both jumps present.
	f.chains[inputChain.name(testBridge)] = true
	f.chains[fwdChain] = true
	f.markPresent(inputChain.jumpArgs("-C", testBridge)...)
	f.markPresent(forwardChain.jumpArgs("-C", testBridge)...)

	if _, err := s.Remove(context.Background(), testEgressReq()); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if !f.ranWith(forwardChain.jumpArgs("-D", testBridge)...) {
		t.Errorf("Remove did not delete FORWARD jump for libvirt bridge\nissued: %v", f.runCalls)
	}
	if !f.ranWith("-w", "-F", fwdChain) {
		t.Errorf("Remove did not flush FORWARD chain %s", fwdChain)
	}
	if !f.ranWith("-w", "-X", fwdChain) {
		t.Errorf("Remove did not delete FORWARD chain %s", fwdChain)
	}
}

func TestRuleTargetsBridge(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		bridge string
		want   bool
	}{
		{
			"exact match",
			"-A PREROUTING -i abox-dev -p udp -m udp --dport 53 -j REDIRECT --to-ports 34711",
			"abox-dev",
			true,
		},
		{
			// Regression: a boundary-less substring match would wrongly match
			// abox-dev2's rules when flushing abox-dev, deleting another running
			// instance's rules.
			"prefix bridge must NOT match longer bridge",
			"-A PREROUTING -i abox-dev2 -p udp -m udp --dport 53 -j REDIRECT --to-ports 40000",
			"abox-dev",
			false,
		},
		{
			"longer bridge does not match prefix request",
			"-A INPUT -i abox-dev -p tcp --dport 34711 -j ACCEPT",
			"abox-dev2",
			false,
		},
		{
			"different bridge",
			"-A INPUT -i abox-other -p udp --dport 67 -j ACCEPT",
			"abox-dev",
			false,
		},
		{
			"no -i field",
			"-A INPUT -p udp --dport 67 -j ACCEPT",
			"abox-dev",
			false,
		},
		{
			"-i as last field (no value)",
			"-A INPUT -i",
			"abox-dev",
			false,
		},
		{
			"empty line",
			"",
			"abox-dev",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleTargetsBridge(tt.line, tt.bridge)
			if got != tt.want {
				t.Errorf("ruleTargetsBridge(%q, %q) = %v, want %v", tt.line, tt.bridge, got, tt.want)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int32
		wantErr bool
	}{
		{"min boundary", 1024, false},
		{"former 5353 floor still valid", 5353, false},
		{"typical filter port", 34711, false},
		{"max", 65535, false},
		{"well-known port too low", 53, true},
		{"just below min", 1023, true},
		{"above max", 65536, true},
		{"zero", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidateGuestPort(t *testing.T) {
	tests := []struct {
		name    string
		port    int32
		wantErr bool
	}{
		{"standard DNS", 53, false},
		{"min", 1, false},
		{"max", 65535, false},
		{"zero", 0, true},
		{"above max", 65536, true},
		{"negative", -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateGuestPort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGuestPort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestResolveRulesValidation(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		req := &rpc.EgressReq{Bridge: "abox-dev", DnsPort: 34711, HttpPort: 45123, GuestDnsPort: 53, Gateway: testGateway}
		r, err := resolveRules(req, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.gateway != testGateway {
			t.Errorf("gateway = %q, want %q", r.gateway, testGateway)
		}
	})

	t.Run("bogus guest_dns_port rejected", func(t *testing.T) {
		req := &rpc.EgressReq{Bridge: "abox-dev", DnsPort: 34711, HttpPort: 45123, GuestDnsPort: 70000, Gateway: testGateway}
		if _, err := resolveRules(req, false); err == nil {
			t.Fatal("expected error for out-of-range guest_dns_port")
		}
	})

	t.Run("sub-5353 filter port rejected", func(t *testing.T) {
		req := &rpc.EgressReq{Bridge: "abox-dev", DnsPort: 53, HttpPort: 45123, GuestDnsPort: 53, Gateway: testGateway}
		if _, err := resolveRules(req, false); err == nil {
			t.Fatal("expected error for filter port below 5353")
		}
	})

	// The gateway is required on Apply (dest-IP pin): a missing or non-IPv4
	// gateway must fail rather than install an under-scoped accept.
	t.Run("missing gateway rejected on apply", func(t *testing.T) {
		req := &rpc.EgressReq{Bridge: "abox-dev", DnsPort: 34711, HttpPort: 45123, GuestDnsPort: 53}
		if _, err := resolveRules(req, false); err == nil {
			t.Fatal("expected error for missing gateway")
		}
	})

	t.Run("non-ipv4 gateway rejected on apply", func(t *testing.T) {
		req := &rpc.EgressReq{Bridge: "abox-dev", DnsPort: 34711, HttpPort: 45123, GuestDnsPort: 53, Gateway: "not-an-ip"}
		if _, err := resolveRules(req, false); err == nil {
			t.Fatal("expected error for non-IPv4 gateway")
		}
	})

	// Lenient teardown drops out-of-range ports instead of guessing a default, so
	// a never-started instance does not orphan a non-standard guest DNS redirect.
	t.Run("lenient drops out-of-range guest_dns_port to empty", func(t *testing.T) {
		req := &rpc.EgressReq{Bridge: "abox-dev", DnsPort: 0, HttpPort: 0, GuestDnsPort: 0}
		r, err := resolveRules(req, true)
		if err != nil {
			t.Fatalf("lenient resolveRules should not fail: %v", err)
		}
		if r.guestDNS != "" || r.dnsPort != "" || r.httpPort != "" {
			t.Errorf("expected all ports empty, got guestDNS=%q dnsPort=%q httpPort=%q", r.guestDNS, r.dnsPort, r.httpPort)
		}
		if r.gateway != "" {
			t.Errorf("expected empty gateway, got %q", r.gateway)
		}
	})
}

// TestChainAcceptArgsGatewayPin is the gateway-pin regression guard: the DNS accepts
// must carry NO -d (their destination is rewritten to loopback by the NAT
// REDIRECT before INPUT), while the HTTP and ICMP accepts must be pinned to the
// gateway.
func TestChainAcceptArgsGatewayPin(t *testing.T) {
	dnsArgs := chainAcceptArgs("-A", testBridge, protoUDP, testDNSPort, "")
	if slices.Contains(dnsArgs, "-d") {
		t.Errorf("DNS accept must NOT be pinned to a destination, got: %v", dnsArgs)
	}

	httpArgs := strings.Join(chainAcceptArgs("-A", testBridge, protoTCP, testHTTPPort, testGateway), " ")
	if !strings.Contains(httpArgs, "-d "+testGateway) {
		t.Errorf("HTTP accept must be pinned to -d %s, got: %s", testGateway, httpArgs)
	}

	icmpArgs := strings.Join(chainICMPAcceptArgs("-A", testBridge, testGateway), " ")
	if !strings.Contains(icmpArgs, "-d "+testGateway) {
		t.Errorf("ICMP accept must be pinned to -d %s, got: %s", testGateway, icmpArgs)
	}
}

// TestFlushNATRulesEmptyGuestDNS guards the lenient-teardown fix: with no valid
// guest DNS port there is no REDIRECT to flush, so flushNATRules must return nil
// without invoking iptables (which would also require root via safeCommand).
func TestFlushNATRulesEmptyGuestDNS(t *testing.T) {
	s := &EgressServer{}
	if err := s.flushNATRules(&ruleParams{bridge: "abox-dev", guestDNS: ""}); err != nil {
		t.Errorf("flushNATRules with empty guestDNS = %v, want nil", err)
	}
}

// TestNATRuleIsAbox is the regression guard for the NAT-flush anchoring fix: the
// guest DNS dport must be matched as a whole field so "--dport 53" does not also
// match an unrelated REDIRECT with "--dport 5353" on the same bridge.
func TestNATRuleIsAbox(t *testing.T) {
	r := &ruleParams{bridge: "abox-dev", guestDNS: "53", dnsPort: "34711", httpPort: "45123"}
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"abox redirect", "-A PREROUTING -i abox-dev -p udp -m udp --dport 53 -j REDIRECT --to-ports 34711", true},
		{"abox redirect tcp", "-A PREROUTING -i abox-dev -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 34711", true},
		{"stale redirect to defunct port still matches", "-A PREROUTING -i abox-dev -p udp -m udp --dport 53 -j REDIRECT --to-ports 99999", true},
		{"port substring must NOT match", "-A PREROUTING -i abox-dev -p udp -m udp --dport 5353 -j REDIRECT --to-ports 34711", false},
		{"other bridge must NOT match", "-A PREROUTING -i abox-dev2 -p udp -m udp --dport 53 -j REDIRECT --to-ports 34711", false},
		{"non-redirect must NOT match", "-A PREROUTING -i abox-dev -p udp -m udp --dport 53 -j ACCEPT", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := natRuleIsAbox(tt.line, r); got != tt.want {
				t.Errorf("natRuleIsAbox(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}
