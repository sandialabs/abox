//go:build linux

package privilege

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/pfvalidate"
	"github.com/sandialabs/abox/internal/rpc"
)

// Supported iptables protocols for DNS/HTTP redirect rules.
const (
	protoTCP = "tcp"
	protoUDP = "udp"
)

// resolvedIptables holds the absolute path to iptables, resolved once at
// startup and cached for the process lifetime. iptables is the only external
// command the egress helper invokes.
var (
	iptablesMu  sync.RWMutex
	iptablesAbs string
)

// iptablesPath returns the resolved absolute path for iptables, falling back to
// the bare name if ResolveCommands hasn't been called (backwards compatibility).
func iptablesPath() string {
	iptablesMu.RLock()
	defer iptablesMu.RUnlock()

	if iptablesAbs != "" {
		return iptablesAbs
	}
	return "iptables"
}

// iptablesRun and iptablesCheck are the two seams through which every iptables
// invocation flows. iptablesRun runs a mutating rule command (returns combined
// output + error); iptablesCheck runs a rule-existence probe (returns bool).
// They are package-level vars so tests can fake command execution and assert the
// exact argument vectors abox issues, without requiring root or a real iptables.
// Production wires them to safeCommand (explicit root creds + minimal env).
var (
	iptablesRun = func(args ...string) ([]byte, error) {
		cmd, err := safeCommand(iptablesPath(), args...)
		if err != nil {
			return nil, err
		}
		return cmd.CombinedOutput()
	}
	iptablesCheck = func(args ...string) bool {
		cmd, err := safeCommand(iptablesPath(), args...)
		if err != nil {
			return false
		}
		return cmd.Run() == nil
	}
	// iptablesList runs an `iptables -S <chain>` listing and returns stdout. It is
	// the seam the flush routines use to enumerate existing rules for a bridge.
	iptablesList = func(args ...string) ([]byte, error) {
		cmd, err := safeCommand(iptablesPath(), args...)
		if err != nil {
			return nil, err
		}
		return cmd.Output()
	}
)

// ruleExists reports whether the given iptables rule exists. Callers pass the
// full argument list including the `-C` check verb (and `-t <table>` if needed).
func ruleExists(args ...string) bool {
	return iptablesCheck(args...)
}

// ruleTargetsBridge reports whether an `iptables -S` output line targets exactly
// the given bridge as the input interface (`-i <bridge>` as a whole field).
// A substring check would let a prefix bridge (abox-dev) match abox-dev2.
func ruleTargetsBridge(line, bridge string) bool {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "-i" && i+1 < len(fields) {
			return fields[i+1] == bridge
		}
	}
	return false
}

// EgressServer implements the gRPC Egress service.
type EgressServer struct {
	rpc.UnimplementedEgressServer
	allowedUID int
}

// Ping handles the ping operation (health check).
func (s *EgressServer) Ping(ctx context.Context, req *rpc.Empty) (*rpc.StringMsg, error) {
	return pingReply(), nil
}

// Shutdown gracefully terminates the helper process.
// GracefulStop causes server.Serve() to return, which lets deferred cleanup
// (socket removal) in RunHelper execute naturally.
func (s *EgressServer) Shutdown(ctx context.Context, req *rpc.Empty) (*rpc.Empty, error) {
	shutdownServerAsync()
	return &rpc.Empty{}, nil
}

// maxFlushRules is the maximum number of iptables rules to delete in a single
// flush operation. This prevents resource exhaustion if an attacker manages to
// add a large number of rules matching the bridge pattern.
const maxFlushRules = 100

// validatePort validates an egress filter port and returns its string form.
// Ports must be in the abox service range (5353-65535). Filter ports are
// auto-allocated listen ports, never standard low ports, so this floor doubles
// as a sanity bound on the REDIRECT target / INPUT accept ports.
func validatePort(p int32) (string, error) {
	// Use the shared unprivileged-port bound (pfvalidate.ValidatePort, 1024-65535)
	// so the trust-boundary check is identical on every backend. Filter ports are
	// auto-allocated well above 1024 in practice; this is the sanity bound.
	port := int(p)
	if !pfvalidate.ValidatePort(port) {
		return "", fmt.Errorf("port must be between 1024 and 65535, got: %d", port)
	}
	return strconv.Itoa(port), nil
}

// validateGuestPort validates the guest-facing DNS port (the REDIRECT match
// dport, normally 53). It is only ever used as a match dport, never as a bind
// target, so the full 1-65535 range is allowed.
func validateGuestPort(p int32) (string, error) {
	port := int(p)
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("guest DNS port must be between 1 and 65535, got: %d", port)
	}
	return strconv.Itoa(port), nil
}

// ruleParams holds the resolved, validated egress rule parameters for a bridge.
// It is the helper's view of a backend.EgressPolicy: the single description of
// what the helper installs/flushes/verifies for a bridge. Gateway ICMP is always
// part of the managed set (gateway ping is a diagnostic), so it is not
// represented as a flag. Guests are statically addressed via cloud-init, so there
// is no DHCP rule.
type ruleParams struct {
	bridge   string
	guestDNS string // guest-facing DNS port REDIRECTed to dnsPort (e.g. "53")
	dnsPort  string // dnsfilter listen port
	httpPort string // httpfilter listen port
}

// resolveRules validates an EgressReq (a trust boundary: every field is bounded
// even though the policy originates in-process) and returns the rule params.
//
// When lenient is true (teardown), out-of-range ports (including the guest DNS
// port) are dropped from the match set rather than failing the flush: a teardown
// of an instance that never fully started may carry zero/low ports, and we still
// want to flush whatever abox did install.
func resolveRules(req *rpc.EgressReq, lenient bool) (*ruleParams, error) {
	if err := ValidateBridgeName(req.Bridge); err != nil {
		return nil, err
	}
	r := &ruleParams{bridge: req.Bridge}

	if lenient {
		// Drop an out-of-range guest DNS port rather than guessing a default: an
		// instance that never fully started installed no NAT REDIRECT, so an empty
		// guestDNS correctly skips the NAT flush (see flushNATRules). Guessing a
		// fixed port could orphan a real redirect on a non-standard guest DNS port.
		if s, err := validateGuestPort(req.GuestDnsPort); err == nil {
			r.guestDNS = s
		}
		if s, err := validatePort(req.DnsPort); err == nil {
			r.dnsPort = s
		}
		if s, err := validatePort(req.HttpPort); err == nil {
			r.httpPort = s
		}
		return r, nil
	}

	dnsStr, err := validatePort(req.DnsPort)
	if err != nil {
		return nil, fmt.Errorf("invalid dns_port: %w", err)
	}
	httpStr, err := validatePort(req.HttpPort)
	if err != nil {
		return nil, fmt.Errorf("invalid http_port: %w", err)
	}
	guestStr, err := validateGuestPort(req.GuestDnsPort)
	if err != nil {
		return nil, fmt.Errorf("invalid guest_dns_port: %w", err)
	}
	r.guestDNS = guestStr
	r.dnsPort = dnsStr
	r.httpPort = httpStr
	return r, nil
}

// natRedirectArgs builds the iptables args for the NAT PREROUTING REDIRECT rule
// that relocates guest DNS (the guest-facing port) to the dnsfilter port.
// verb is -A/-C/-D.
func natRedirectArgs(verb, bridge, proto, guestPort, toPort string) []string {
	return []string{
		"-w", "-t", "nat", verb, "PREROUTING",
		"-i", bridge, "-p", proto, "--dport", guestPort,
		"-j", "REDIRECT", "--to-port", toPort,
	}
}

// chainPrefix is the fixed prefix of abox's per-bridge dedicated INPUT chains.
const chainPrefix = "ABOX-"

// fwdChainPrefix is the fixed prefix of abox's per-bridge dedicated FORWARD
// chains. It is DISTINCT from chainPrefix so the FORWARD chain never collides
// with (or is confused for) the INPUT chain: the INPUT chain ACCEPTs the filter
// ports, which would be WRONG to apply to forwarded (guest->beyond-host) traffic.
// "ABOXF-" (6) + 16 hex chars (8 bytes) = 22 chars, within the 29-char limit.
const fwdChainPrefix = "ABOXF-"

// iptables built-in chain/target names abox references when building rule args.
const (
	chainINPUT   = "INPUT"
	chainFORWARD = "FORWARD"
	targetACCEPT = "ACCEPT"
	targetDROP   = "DROP"
)

// chainSpec describes one of abox's two dedicated per-bridge chain families: the
// INPUT-side guest->host default-deny and the FORWARD-side guest->beyond-host
// default-deny. The two families differ ONLY by (1) the chain-name prefix and
// (2) the built-in parent chain the jump attaches to; everything else — the
// sha256-of-bridge name derivation, the jump/insert arg vectors, and the
// ensure/remove/flush lifecycle (see the ensureChain/ensureJump/removeAllJumps/
// flushChainRules methods) — is identical, so they share one implementation
// parameterized by a chainSpec.
type chainSpec struct {
	prefix string // dedicated-chain name prefix (chainPrefix / fwdChainPrefix)
	parent string // built-in parent chain the jump attaches to (INPUT / FORWARD)
}

var (
	// inputChain is the INPUT-side family: the guest->host default-deny reached
	// from a top-of-INPUT jump.
	inputChain = chainSpec{prefix: chainPrefix, parent: chainINPUT}
	// forwardChain is the FORWARD-side family: the guest->beyond-host default-deny
	// reached from a top-of-FORWARD jump.
	forwardChain = chainSpec{prefix: fwdChainPrefix, parent: chainFORWARD}
)

// name returns the deterministic name of the dedicated per-bridge chain for this
// family. It is derived from a sha256 of the bridge name — the hash input is the
// bare bridge, IDENTICAL for both families, so chain names never change — and kept
// ≤29 chars (the iptables chain-name limit): prefix + 16 hex chars (8 bytes). A
// hash (rather than the raw bridge name) keeps the name within the limit
// regardless of bridge length and avoids any character-set concerns. The DISTINCT
// prefixes (see chainPrefix / fwdChainPrefix) guarantee the INPUT and FORWARD
// chains for one bridge never collide.
//
// Rationale for a dedicated chain (M1/M2 fix): a bare `-A INPUT ... -j DROP` at
// the bottom of INPUT is unreachable on any host that has an earlier broad accept
// (ufw/firewalld/docker commonly append `-A INPUT ... -j ACCEPT`), silently
// killing the guest->host deny while the rule still "exists" (so a naive Verify
// passes). Putting the whole set in a dedicated chain and jumping to it from the
// parent chain at position 1 guarantees reachability (M1), and lets teardown
// remove the entire chain instead of pattern-matching individual rules that could
// collide with an operator's own rules (M2).
func (c chainSpec) name(bridge string) string {
	sum := sha256.Sum256([]byte(bridge))
	return c.prefix + hex.EncodeToString(sum[:8])
}

// jumpArgs builds the iptables args for the parent->chain jump for a bridge.
// Traffic arriving on the bridge (`-i <bridge>`) is diverted into the dedicated
// chain; verb is "-C" for check or "-D" for delete. insertJumpArgs is the add
// form (needs the explicit "1" position for -I).
func (c chainSpec) jumpArgs(verb, bridge string) []string {
	return []string{"-w", verb, c.parent, "-i", bridge, "-j", c.name(bridge)}
}

// insertJumpArgs builds the add form of the parent->chain jump: inserted at
// position 1 (top of the parent chain) so the dedicated chain is consulted before
// any pre-existing parent rule — guaranteeing the default-deny is reachable ahead
// of an operator/host/libvirt INPUT accept or a host MASQUERADE/ACCEPT in FORWARD.
func (c chainSpec) insertJumpArgs(bridge string) []string {
	return []string{"-w", "-I", c.parent, "1", "-i", bridge, "-j", c.name(bridge)}
}

// chainAcceptArgs builds a `-A <chain>` ACCEPT rule for a proto/port, appended to
// the dedicated INPUT chain (order within the chain is by append order).
func chainAcceptArgs(verb, bridge, proto, port string) []string {
	return []string{"-w", verb, inputChain.name(bridge), "-p", proto, "--dport", port, "-j", targetACCEPT}
}

// chainICMPAcceptArgs builds the ICMP ACCEPT rule inside the dedicated INPUT chain.
func chainICMPAcceptArgs(verb, bridge string) []string {
	return []string{"-w", verb, inputChain.name(bridge), "-p", "icmp", "-j", targetACCEPT}
}

// establishedArgs builds the conntrack ESTABLISHED,RELATED ACCEPT inside a
// dedicated chain (INPUT or FORWARD; callers pass the resolved chain name). It is
// the FIRST rule appended so return traffic survives the chain's final DROP: for
// the INPUT chain that is host-initiated connections into the guest (notably
// host->guest SSH replies); for the FORWARD chain it is an established/inbound
// port-forward (abox `forward` DNATs to the guest).
func establishedArgs(verb, chain string) []string {
	return []string{
		"-w", verb, chain,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", targetACCEPT,
	}
}

// dropArgs builds the final DROP inside a dedicated chain (INPUT or FORWARD;
// callers pass the resolved chain name). Because it is the LAST rule in a chain
// that is only entered for `-i <bridge>` traffic and the ESTABLISHED accept
// precedes it, it is the default-deny — reachable regardless of surrounding rules
// in the parent chain.
func dropArgs(verb, chain string) []string {
	return []string{"-w", verb, chain, "-j", targetDROP}
}

// Apply installs the host-side egress enforcement for a bridge (idempotent):
//  1. NAT PREROUTING REDIRECT of guest DNS (the guest-facing port) to the
//     dnsfilter port (udp+tcp).
//  2. A dedicated per-bridge chain (see chainName) populated, IN ORDER, with:
//     (a) a conntrack ESTABLISHED,RELATED ACCEPT (so host->guest SSH replies and
//     other return traffic survive); (b) ACCEPTs for the dnsfilter port (udp+tcp),
//     the httpfilter port (tcp) and ICMP — the guest->host traffic the guest needs
//     (filter access, gateway ping); and (c) a final DROP. Everything not
//     explicitly accepted is dropped. (Guests are statically addressed via
//     cloud-init, so there is no DHCP rule.)
//  3. A single jump `-I INPUT 1 -i <bridge> -j <chain>` at the TOP of INPUT.
//
// Why a dedicated chain (M1/M2 hardening): all abox networks are host-only (no
// uplink), so the topology already blocks guest->internet, but a guest can still
// reach the HOST on non-filter ports, so the host itself must enforce the
// guest->host deny. A bare DROP appended to the bottom of INPUT is UNREACHABLE on
// any host that has an earlier broad accept (ufw/firewalld/docker commonly add
// `-A INPUT ... -j ACCEPT`), silently killing the deny while the rule still exists.
// Housing the whole set in a dedicated chain reached from INPUT position 1
// guarantees the deny is evaluated before any other INPUT rule (M1), and lets
// teardown drop the entire chain instead of pattern-matching individual rules that
// could collide with an operator's own INPUT rules (M2).
//
// Safety: the chain is entered only for `-i <bridge>` traffic (guest->host) and
// its ESTABLISHED/DNS/HTTP/ICMP accepts precede the DROP, so guest->host
// keeps working. The chain never affects other interfaces or libvirt's dnsmasq.
// guest->internet default-deny is provided by the host-only topology plus the
// FORWARD chain (see Apply's buildFwdChain); for libvirt the nwfilter remains an
// additional independent internet default-deny.
//
// The permitted set is driven entirely by the request (see backend.EgressPolicy),
// so the iptables and nwfilter halves cannot drift.
//
// TODO(real-host): validate dedicated-chain ordering/conntrack on a real host
//
// If the full desired rule set is already present, Apply is a no-op so repeated
// applies (e.g. the start + secure phases of `abox up`) neither churn rules nor
// momentarily drop the live REDIRECT. Otherwise the chain is (re)created and its
// contents rebuilt cleanly; on any failure all rules for the bridge are flushed so
// no partial state is left behind.
func (s *EgressServer) Apply(ctx context.Context, req *rpc.EgressReq) (*rpc.Empty, error) {
	r, err := resolveRules(req, false)
	if err != nil {
		return nil, err
	}

	// Idempotency: if the complete desired rule set is already in force, do
	// nothing (avoids re-flushing and a transient gap on a running guest).
	if s.alreadyApplied(r) {
		return &rpc.Empty{}, nil
	}

	// Clear any stale rules for this bridge first (e.g. a filter restarted on a
	// different port). Best-effort: a stale-clear failure here is not fatal to a
	// fresh apply, so the flush errors are intentionally ignored (unlike Remove).
	_ = s.flushNATRules(r)
	_ = s.flushChainRules(inputChain, r)
	_ = s.flushChainRules(forwardChain, r)

	rollback := func() {
		_ = s.flushNATRules(r)
		_ = s.flushChainRules(inputChain, r)
		_ = s.flushChainRules(forwardChain, r)
	}

	// NAT PREROUTING REDIRECT guestDNS -> dnsfilter port, for udp and tcp.
	for _, proto := range []string{protoUDP, protoTCP} {
		if err := s.addNATRedirect(r, proto); err != nil {
			rollback()
			return nil, err
		}
	}

	// Build the dedicated per-bridge chain and jump to it from the top of INPUT.
	if err := s.buildChain(r); err != nil {
		rollback()
		return nil, err
	}

	// Add the host-side FORWARD default-deny for EVERY abox-managed bridge
	// (defense-in-depth).
	//
	// Invariant: all abox networks are host-only (no uplink); the host originates
	// all egress on the guest's behalf and NOTHING the guest sends is ever
	// forwarded/masqueraded — DNS terminates at the gateway dnsfilter
	// (REDIRECT->INPUT), HTTP/HTTPS at the host proxy (guest->gateway INPUT), abox
	// forward uses SSH tunnels (not DNAT), mount uses sshfs. The FORWARD
	// default-deny is therefore defense-in-depth on top of the host-only topology;
	// for libvirt the nwfilter remains an additional independent guest->internet
	// default-deny.
	if err := s.buildFwdChain(r); err != nil {
		rollback()
		return nil, err
	}

	return &rpc.Empty{}, nil
}

// buildChain (re)creates the dedicated per-bridge chain, populates it in order
// (ESTABLISHED accept, the DNS/HTTP/ICMP accepts, final DROP), and ensures a
// single jump to it exists at the top of INPUT. It is idempotent: the chain is
// flushed before repopulating, and the jump is inserted only if not already
// present, so a re-Apply never stacks a second jump.
func (s *EgressServer) buildChain(r *ruleParams) error {
	// Ensure the chain exists (ignore "already exists"), then flush it so its
	// contents are rebuilt cleanly.
	if err := s.ensureChain(inputChain, r.bridge); err != nil {
		return err
	}
	if _, err := iptablesRun("-w", "-F", inputChain.name(r.bridge)); err != nil {
		return fmt.Errorf("iptables flush chain failed: %w", err)
	}

	// Populate the chain in order. Appends keep the ESTABLISHED accept first and
	// the DROP last.
	if err := s.appendRule(establishedArgs("-A", inputChain.name(r.bridge))); err != nil {
		return err
	}
	for _, proto := range []string{protoUDP, protoTCP} {
		if err := s.appendRule(chainAcceptArgs("-A", r.bridge, proto, r.dnsPort)); err != nil {
			return err
		}
	}
	if err := s.appendRule(chainAcceptArgs("-A", r.bridge, protoTCP, r.httpPort)); err != nil {
		return err
	}
	if err := s.appendRule(chainICMPAcceptArgs("-A", r.bridge)); err != nil {
		return err
	}
	if err := s.appendRule(dropArgs("-A", inputChain.name(r.bridge))); err != nil {
		return err
	}

	// Ensure exactly one jump to the chain at the top of INPUT.
	return s.ensureJump(inputChain, r.bridge)
}

// ensureChain creates the dedicated chain for the given family/bridge, treating
// an "already exists" error as success (iptables -N is not idempotent on its own).
func (s *EgressServer) ensureChain(c chainSpec, bridge string) error {
	chain := c.name(bridge)
	if _, err := iptablesRun("-w", "-N", chain); err != nil {
		// -N fails if the chain exists; a subsequent -F/-L confirms it is usable.
		// Probe with a list to distinguish "already exists" from a real failure.
		if _, lerr := iptablesList("-w", "-S", chain); lerr != nil {
			return fmt.Errorf("iptables create %s chain failed: %w", c.parent, err)
		}
	}
	return nil
}

// appendRule appends a single rule (already including its own -A <chain> verb) and
// surfaces the combined output on failure.
func (s *EgressServer) appendRule(args []string) error {
	if output, err := iptablesRun(args...); err != nil {
		return fmt.Errorf("iptables append to chain failed: %s: %w", string(output), err)
	}
	return nil
}

// ensureJump inserts the parent->chain jump at position 1 if it is not already
// present, so a re-Apply never stacks a duplicate jump. The parent chain name in
// the error text is taken from the chainSpec (INPUT / FORWARD).
func (s *EgressServer) ensureJump(c chainSpec, bridge string) error {
	if ruleExists(c.jumpArgs("-C", bridge)...) {
		return nil
	}
	if output, err := iptablesRun(c.insertJumpArgs(bridge)...); err != nil {
		return fmt.Errorf("iptables insert %s jump failed: %s: %w", c.parent, string(output), err)
	}
	return nil
}

// buildFwdChain (re)creates the dedicated per-bridge FORWARD chain, populates it
// in order (ESTABLISHED accept, final DROP), and ensures a single jump to it at
// the top of FORWARD. It mirrors buildChain: idempotent (flushed before
// repopulating, jump inserted only if absent). Called for every abox-managed
// bridge.
func (s *EgressServer) buildFwdChain(r *ruleParams) error {
	if err := s.ensureChain(forwardChain, r.bridge); err != nil {
		return err
	}
	if _, err := iptablesRun("-w", "-F", forwardChain.name(r.bridge)); err != nil {
		return fmt.Errorf("iptables flush FORWARD chain failed: %w", err)
	}

	// ESTABLISHED,RELATED first so return traffic for an inbound port-forward
	// survives; DROP last as the default-deny.
	if err := s.appendRule(establishedArgs("-A", forwardChain.name(r.bridge))); err != nil {
		return err
	}
	if err := s.appendRule(dropArgs("-A", forwardChain.name(r.bridge))); err != nil {
		return err
	}

	return s.ensureJump(forwardChain, r.bridge)
}

// Verify reports whether the complete egress rule set described by the request
// is currently in force for the bridge (drift detection for doctor).
func (s *EgressServer) Verify(ctx context.Context, req *rpc.EgressReq) (*rpc.BoolMsg, error) {
	r, err := resolveRules(req, false)
	if err != nil {
		return nil, err
	}
	return &rpc.BoolMsg{Ok: s.alreadyApplied(r)}, nil
}

// alreadyApplied reports whether the complete desired egress rule set is present
// for the bridge (used to make Apply an idempotent no-op and to back Verify).
//
// It checks (a) the NAT REDIRECT (udp+tcp), (b) the INPUT->chain jump exists, and
// (c) the dedicated chain contains every expected rule. Because the jump is at
// INPUT position 1 and the chain is self-contained, existence of these rules ==
// enforcement (reachability is guaranteed by construction), so no separate
// reachability check is needed.
//
// It ADDITIONALLY requires the FORWARD default-deny (jump + chain ESTABLISHED
// accept + DROP) for EVERY abox-managed bridge, since the FORWARD chain is now
// built for all bridges (see Apply).
func (s *EgressServer) alreadyApplied(r *ruleParams) bool {
	applied := ruleExists(natRedirectArgs("-C", r.bridge, protoUDP, r.guestDNS, r.dnsPort)...) &&
		ruleExists(natRedirectArgs("-C", r.bridge, protoTCP, r.guestDNS, r.dnsPort)...) &&
		ruleExists(inputChain.jumpArgs("-C", r.bridge)...) &&
		ruleExists(establishedArgs("-C", inputChain.name(r.bridge))...) &&
		ruleExists(chainAcceptArgs("-C", r.bridge, protoUDP, r.dnsPort)...) &&
		ruleExists(chainAcceptArgs("-C", r.bridge, protoTCP, r.dnsPort)...) &&
		ruleExists(chainAcceptArgs("-C", r.bridge, protoTCP, r.httpPort)...) &&
		ruleExists(chainICMPAcceptArgs("-C", r.bridge)...) &&
		ruleExists(dropArgs("-C", inputChain.name(r.bridge))...)
	if !applied {
		return false
	}
	return s.fwdApplied(r)
}

// fwdApplied reports whether the FORWARD default-deny (jump + chain ESTABLISHED
// accept + DROP) is fully present for a bridge. The FORWARD chain is built for
// every abox-managed bridge, so this is part of the "applied" set for all bridges.
func (s *EgressServer) fwdApplied(r *ruleParams) bool {
	return ruleExists(forwardChain.jumpArgs("-C", r.bridge)...) &&
		ruleExists(establishedArgs("-C", forwardChain.name(r.bridge))...) &&
		ruleExists(dropArgs("-C", forwardChain.name(r.bridge))...)
}

// addNATRedirect adds and verifies a NAT PREROUTING REDIRECT rule that relocates
// guest traffic to the guest-facing DNS port onto the dnsfilter port.
func (s *EgressServer) addNATRedirect(r *ruleParams, proto string) error {
	if output, err := iptablesRun(natRedirectArgs("-A", r.bridge, proto, r.guestDNS, r.dnsPort)...); err != nil {
		return fmt.Errorf("iptables NAT failed: %s: %w", string(output), err)
	}
	if !ruleExists(natRedirectArgs("-C", r.bridge, proto, r.guestDNS, r.dnsPort)...) {
		return errors.New("iptables NAT rule verification failed: rule not found after add")
	}
	return nil
}

// Remove flushes the host-side egress rules for a bridge (idempotent). The
// request's ports scope the flush to abox's own rules.
func (s *EgressServer) Remove(ctx context.Context, req *rpc.EgressReq) (*rpc.Empty, error) {
	// Lenient: a teardown of an instance that never fully started may carry
	// zero/low ports; flush whatever abox installed rather than failing.
	r, err := resolveRules(req, true)
	if err != nil {
		return nil, err
	}

	// Surface flush failures so the teardown caller learns that stale host rules
	// may have survived (unlike Apply, where stale-clearing is best-effort).
	if err := errors.Join(s.flushNATRules(r), s.flushChainRules(inputChain, r), s.flushChainRules(forwardChain, r)); err != nil {
		return nil, err
	}

	return &rpc.Empty{}, nil
}

// flushNATRules removes the NAT PREROUTING REDIRECT rules abox installed for a
// bridge (matched by the guest-facing DNS dport + REDIRECT target).
//
// Security note: This function parses iptables -S output using strings.Fields().
// This is safe because:
//  1. The bridge name is validated before reaching this function (alphanumeric + hyphen only)
//  2. iptables -S output format is predictable: "-A CHAIN -i IFACE -p PROTO ..." with
//     space-separated fields. No shell interpretation occurs.
//  3. We match only lines containing our validated bridge name and specific rule patterns.
//  4. The parsed fields are passed directly to exec.Command without shell expansion.
//
// Returns an error if listing fails or any delete fails, so a teardown
// (Remove) can report that stale rules may have survived. Apply ignores this
// (its pre-flush is best-effort stale-clearing).
func (s *EgressServer) flushNATRules(r *ruleParams) error {
	// A teardown that carries no valid guest DNS port (an instance that never
	// fully started) installed no REDIRECT, so there is nothing to flush; bail
	// before matching, since an empty guestDNS would not target a real rule.
	if r.guestDNS == "" {
		return nil
	}

	output, err := iptablesList("-w", "-t", "nat", "-S", "PREROUTING")
	if err != nil {
		return fmt.Errorf("listing NAT PREROUTING rules: %w", err)
	}

	var rulesToDelete []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if natRuleIsAbox(line, r) {
			rulesToDelete = append(rulesToDelete, line)
			if len(rulesToDelete) >= maxFlushRules {
				logging.Audit("privilege-helper.flush", "warning", "excessive NAT rules for bridge, truncating", "bridge", r.bridge, "limit", maxFlushRules)
				break
			}
		}
	}

	var failed int
	for _, rule := range slices.Backward(rulesToDelete) {
		rule = strings.TrimPrefix(rule, "-A ")
		args := []string{"-w", "-t", "nat", "-D"}
		// strings.Fields safely splits on whitespace; iptables -S output contains
		// no quoted strings or special characters that would affect parsing
		args = append(args, strings.Fields(rule)...)
		if _, err := iptablesRun(args...); err != nil {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("failed to delete %d of %d NAT rule(s) for bridge %s", failed, len(rulesToDelete), r.bridge)
	}
	return nil
}

// natRuleIsAbox reports whether an `iptables -t nat -S PREROUTING` line is the
// REDIRECT rule abox installed for the bridge. Matches like:
//
//	-A PREROUTING -i ab-xxx -p udp -m udp --dport 53 -j REDIRECT --to-ports 34711
//
// The bridge is matched as a whole field so a prefix bridge (abox-dev) does not
// also match abox-dev2. The guest DNS dport is matched as a whole field (trailing
// space) so "--dport 53" does not also match "--dport 5353" (mirrors
// inputRuleIsAbox). The dport + REDIRECT scopes the match to abox's own redirect
// rules, while still catching a stale redirect to a now-defunct dnsfilter port.
func natRuleIsAbox(line string, r *ruleParams) bool {
	return ruleTargetsBridge(line, r.bridge) &&
		strings.Contains(line, "--dport "+r.guestDNS+" ") &&
		strings.Contains(line, "-j REDIRECT")
}

// flushChainRules tears down abox's default-deny for a bridge in the given family
// (INPUT or FORWARD) by removing the dedicated chain and the jump to it
// (idempotent). Because ALL of abox's rules for the family live inside the
// dedicated chain — never spliced into the parent chain itself — teardown is a
// whole-object delete: (1) remove every parent->chain jump, (2) flush the chain,
// (3) delete the chain. This is the M2 fix: abox never pattern-matches individual
// parent-chain rules for deletion, so it can NEVER remove an operator's own rule
// (even one that happens to be `-i <bridge> ... -j DROP`).
//
// It is the chain-side counterpart to flushNATRules and, for the FORWARD family,
// handles a bridge that never had a FORWARD chain installed gracefully
// (removeAllJumps / deleteNamedChain treat "absent" as done). See flushNATRules
// for -S parsing safety analysis (only the jump-removal loop parses -S here).
func (s *EgressServer) flushChainRules(c chainSpec, r *ruleParams) error {
	if err := s.removeAllJumps(c, r.bridge); err != nil {
		return err
	}
	return s.deleteNamedChain(c.name(r.bridge))
}

// removeAllJumps deletes every `-i <bridge> -j <chain>` jump from the family's
// parent chain (INPUT or FORWARD). It loops so a (pathological) stacked jump is
// fully cleared, bounded by maxFlushRules. A "does not exist" delete is treated as
// done (nothing left to remove).
func (s *EgressServer) removeAllJumps(c chainSpec, bridge string) error {
	for range maxFlushRules {
		if !ruleExists(c.jumpArgs("-C", bridge)...) {
			return nil
		}
		if _, err := iptablesRun(c.jumpArgs("-D", bridge)...); err != nil {
			return fmt.Errorf("deleting %s jump for bridge %s: %w", c.parent, bridge, err)
		}
	}
	logging.Audit("privilege-helper.flush", "warning", fmt.Sprintf("excessive %s jumps for bridge, truncating", c.parent), "bridge", bridge, "limit", maxFlushRules)
	return nil
}

// deleteNamedChain flushes and deletes a dedicated per-bridge chain by its
// resolved name (idempotent). A chain that does not exist is success (nothing to
// delete); a chain that still has references would fail -X, but the caller's
// jump-removal (removeAllJumps) has already cleared the only reference abox
// creates. It serves both the INPUT and FORWARD chains (see chainSpec.name);
// callers pass the already-resolved name.
func (s *EgressServer) deleteNamedChain(chain string) error {
	// If the chain does not exist, there is nothing to do.
	if _, err := iptablesList("-w", "-S", chain); err != nil {
		return nil //nolint:nilerr // a missing chain is success (nothing to delete)
	}
	if _, err := iptablesRun("-w", "-F", chain); err != nil {
		return fmt.Errorf("flushing chain %s: %w", chain, err)
	}
	if _, err := iptablesRun("-w", "-X", chain); err != nil {
		return fmt.Errorf("deleting chain %s: %w", chain, err)
	}
	return nil
}
