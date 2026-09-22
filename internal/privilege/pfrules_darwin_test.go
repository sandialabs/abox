//go:build darwin

package privilege

import (
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/firewall"
)

const (
	pfSubnet   = "10.20.30.0/24"
	pfGateway  = "10.20.30.1"
	pfBridge   = "bridge100"
	pfDNSPort  = 5300
	pfHTTPPort = 8080
)

// goodRules returns the generator's output for the standard test subnet.
func goodRules() string {
	return firewall.BuildInstanceRules(pfSubnet, pfGateway, pfBridge, pfDNSPort, pfHTTPPort)
}

func TestValidatePFRules_AcceptsGeneratorOutput(t *testing.T) {
	if err := validatePFRules(goodRules(), pfSubnet); err != nil {
		t.Fatalf("validatePFRules rejected the generator's own output: %v", err)
	}
}

func TestValidatePFRules_AcceptsPreBootDeny(t *testing.T) {
	// The pre-boot default-deny loaded by vfkit's Define must pass the helper's
	// trust-boundary validator token-for-token, or fail-closed startup would break.
	rules, err := firewall.PreBootDenyRules("dev", pfSubnet, pfHTTPPort)
	if err != nil {
		t.Fatalf("PreBootDenyRules returned an error for valid inputs: %v", err)
	}
	if err := validatePFRules(rules, pfSubnet); err != nil {
		t.Fatalf("validatePFRules rejected the pre-boot deny ruleset: %v", err)
	}
	// Cross-instance guard still holds: a deny for another subnet is rejected.
	other := firewall.BuildPreBootDenyRules("10.99.99.0/24", pfHTTPPort)
	if err := validatePFRules(other, pfSubnet); err == nil {
		t.Fatal("pre-boot deny for a mismatched subnet should be rejected")
	}
}

func TestValidatePFRules_RoundTrip(t *testing.T) {
	// Same subnet: accepted.
	rules := firewall.BuildInstanceRules(pfSubnet, pfGateway, pfBridge, pfDNSPort, pfHTTPPort)
	if err := validatePFRules(rules, pfSubnet); err != nil {
		t.Fatalf("round-trip with matching subnet should pass: %v", err)
	}

	// Rules generated for a different subnet, validated against pfSubnet:
	// rejected (cross-instance guard).
	otherRules := firewall.BuildInstanceRules("10.99.99.0/24", "10.99.99.1", pfBridge, pfDNSPort, pfHTTPPort)
	if err := validatePFRules(otherRules, pfSubnet); err == nil {
		t.Fatal("round-trip with mismatched subnet should fail (cross-instance injection)")
	}
}

// TestValidatePFRules_AcceptsBridgeNames asserts the widened pfBridgeNameRE
// admits both vfkit's bridgeN interfaces and VMware Fusion's vmnetN interfaces,
// binding the rest of the ruleset to the caller's subnet.
func TestValidatePFRules_AcceptsBridgeNames(t *testing.T) {
	for _, bridge := range []string{"bridge100", "bridge0", "vmnet2", "vmnet19"} {
		t.Run(bridge, func(t *testing.T) {
			rules := firewall.BuildInstanceRules(pfSubnet, pfGateway, bridge, pfDNSPort, pfHTTPPort)
			if err := validatePFRules(rules, pfSubnet); err != nil {
				t.Fatalf("expected bridge %q to be accepted, got: %v", bridge, err)
			}
		})
	}
}

func TestValidatePFRules_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		rules string
	}{
		{
			name: "cross-instance different cidr",
			// Legitimate shape, but <cidr> is a different subnet than the caller's.
			rules: "rdr pass proto udp from 10.99.99.0/24 to any port 53 -> 127.0.0.1 port 5300",
		},
		{
			name:  "wrong gateway",
			rules: "pass quick proto icmp from 10.20.30.0/24 to 10.20.30.254",
		},
		{
			name:  "non-bridge interface",
			rules: "block drop quick on en0 inet6 all",
		},
		{
			name:  "bare bridge no digits",
			rules: "block drop quick on bridge inet6 all",
		},
		{
			name:  "bare vmnet no digits",
			rules: "block drop quick on vmnet inet6 all",
		},
		{
			name:  "vmnet non-digit suffix",
			rules: "block drop quick on vmnetX inet6 all",
		},
		{
			name:  "out-of-range port high",
			rules: "pass quick proto tcp from 10.20.30.0/24 to 10.20.30.1 port 70000",
		},
		{
			name:  "out-of-range port privileged",
			rules: "pass quick proto tcp from 10.20.30.0/24 to 10.20.30.1 port 80",
		},
		{
			name:  "inline comment injection",
			rules: "pass quick proto icmp from 10.20.30.0/24 to 10.20.30.1 # sneaky",
		},
		{
			name:  "foreign rule shape",
			rules: "pass in all",
		},
		{
			name:  "nested anchor directive",
			rules: "anchor evil",
		},
		{
			name:  "table file reference",
			rules: `table <bad> file /etc/passwd`,
		},
		{
			name:  "extra rule appended to good set",
			rules: goodRules() + "\npass in quick all",
		},
		{
			name:  "single VM IP instead of subnet",
			rules: "block drop quick from 10.20.30.42 to any",
		},
		{
			name: "inbound SSH on a non-22 port",
			// Only host->guest :22 is templated; any other port is rejected.
			rules: "pass quick proto tcp from 10.20.30.1 to 10.20.30.0/24 port 2222",
		},
		{
			name: "inbound SSH from a non-gateway source",
			// The source must be the subnet's .1 gateway, not an arbitrary host.
			rules: "pass quick proto tcp from 10.20.30.42 to 10.20.30.0/24 port 22",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePFRules(tc.rules, pfSubnet); err == nil {
				t.Fatalf("expected rejection for %q, got nil", tc.rules)
			}
		})
	}
}

func TestValidatePFRules_RequiresTerminalDeny(t *testing.T) {
	// A ruleset of otherwise-valid allow shapes but WITHOUT the subnet-keyed
	// terminal deny is fail-open (a pf anchor falls through to "pass") and must
	// be refused even though every individual line matches an allowed template.
	allowOnly := strings.Join([]string{
		"rdr pass proto udp from 10.20.30.0/24 to any port 53 -> 127.0.0.1 port 5300",
		"pass quick proto icmp from 10.20.30.0/24 to 10.20.30.1",
	}, "\n")
	err := validatePFRules(allowOnly, pfSubnet)
	if err == nil {
		t.Fatal("allow-only ruleset without a terminal deny must be rejected")
	}
	if !strings.Contains(err.Error(), "terminal default-deny") {
		t.Fatalf("expected a missing-terminal-deny error, got: %v", err)
	}

	// Adding the terminal deny AND the inet6 deny makes the same set valid (an
	// allow-carrying ruleset must close both families — see RequiresIPv6Deny).
	withDeny := allowOnly + "\nblock drop quick on bridge100 inet6 all" +
		"\nblock drop quick from 10.20.30.0/24 to any"
	if err := validatePFRules(withDeny, pfSubnet); err != nil {
		t.Fatalf("ruleset with a terminal deny should be accepted: %v", err)
	}
}

// TestValidatePFRules_RequiresIPv6Deny asserts a ruleset that permits egress but
// omits the interface-scoped IPv6 kill is refused (the IPv4 terminal deny does
// not cover vmnet's NAT66/link-local v6). The pre-boot bare deny is exempt.
func TestValidatePFRules_RequiresIPv6Deny(t *testing.T) {
	// Allow rules + IPv4 terminal deny, but NO inet6 deny: fail-open on IPv6.
	noInet6 := strings.Join([]string{
		"rdr pass proto udp from 10.20.30.0/24 to any port 53 -> 127.0.0.1 port 5300",
		"pass quick proto tcp from 10.20.30.0/24 to 10.20.30.1 port 8080",
		"block drop quick from 10.20.30.0/24 to any",
	}, "\n")
	err := validatePFRules(noInet6, pfSubnet)
	if err == nil {
		t.Fatal("allow-carrying ruleset without the inet6 deny must be rejected")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("expected a missing-IPv6-deny error, got: %v", err)
	}

	// The pre-boot bare terminal deny (no allow rules) stays exempt.
	preBoot := "block drop quick from 10.20.30.0/24 to any"
	if err := validatePFRules(preBoot, pfSubnet); err != nil {
		t.Fatalf("pre-boot bare deny (no allow rules) must remain valid: %v", err)
	}
}

// TestValidatePFRules_AcceptsInboundProxyDeny asserts the "block ... from ! <cidr>
// ... port <httpPort>" inbound-proxy deny is a valid shape, and that its
// negation/port are still bound to the caller's subnet and port class.
func TestValidatePFRules_AcceptsInboundProxyDeny(t *testing.T) {
	// Present in the generator output, so goodRules() already exercises acceptance;
	// assert the standalone shape and a couple of rejections around it.
	good := goodRules()
	if !strings.Contains(good, "block drop quick proto tcp from ! 10.20.30.0/24 to any port 8080") {
		t.Fatal("generator should emit the inbound-proxy deny")
	}
	// A privileged port in the inbound deny is rejected (port class is enforced).
	bad := "block drop quick proto tcp from ! 10.20.30.0/24 to any port 80\n" +
		"block drop quick on bridge100 inet6 all\n" +
		"block drop quick from 10.20.30.0/24 to any"
	if err := validatePFRules(bad, pfSubnet); err == nil {
		t.Fatal("inbound-proxy deny with a privileged port must be rejected")
	}
	// The negated source must still be the caller's subnet (cross-instance guard).
	crossed := "block drop quick proto tcp from ! 10.99.99.0/24 to any port 8080\n" +
		"block drop quick from 10.20.30.0/24 to any"
	if err := validatePFRules(crossed, pfSubnet); err == nil {
		t.Fatal("inbound-proxy deny for a foreign subnet must be rejected")
	}
}

func TestValidatePFRules_SubnetValidation(t *testing.T) {
	rules := goodRules()
	for _, bad := range []string{
		"",              // empty
		"10.20.30.0/16", // not a /24
		"10.20.30.5/24", // not the network address
		"not-a-cidr",    // garbage
		"fd00::/24",     // IPv6
	} {
		if err := validatePFRules(rules, bad); err == nil {
			t.Fatalf("expected rejection for bad subnet %q", bad)
		}
	}
}

func TestValidatePFRules_CommentsAndBlankLinesAllowed(t *testing.T) {
	// The generator emits comment lines; ensure they and blank lines are tolerated.
	rules := goodRules()
	if !strings.Contains(rules, "#") {
		t.Fatal("expected the generator to emit comment lines")
	}
	rules = "\n\n" + rules + "\n\n"
	if err := validatePFRules(rules, pfSubnet); err != nil {
		t.Fatalf("comments/blank lines should be tolerated: %v", err)
	}
}

func TestValidateInstanceName(t *testing.T) {
	good := []string{"dev", "my-box", "abc123", "A-B-9"}
	for _, n := range good {
		if err := validateInstanceName(n); err != nil {
			t.Errorf("expected %q valid: %v", n, err)
		}
	}
	bad := []string{"", "-leading", "has space", "slash/x", "dot.name", "semi;colon", strings.Repeat("a", 64)}
	for _, n := range bad {
		if err := validateInstanceName(n); err == nil {
			t.Errorf("expected %q invalid", n)
		}
	}
}
