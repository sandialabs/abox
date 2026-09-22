package firewall

import (
	"strings"
	"testing"
)

func TestBuildInstanceRules_Shape(t *testing.T) {
	rules := BuildInstanceRules("10.20.30.0/24", "10.20.30.1", "bridge100", 5300, 8080)

	// Exact rule lines the helper's validatePFRules expects, token-for-token.
	want := []string{
		"rdr pass proto udp from 10.20.30.0/24 to any port 53 -> 127.0.0.1 port 5300",
		"rdr pass proto tcp from 10.20.30.0/24 to any port 53 -> 127.0.0.1 port 5300",
		"block drop quick on bridge100 inet6 all",
		"pass quick proto tcp from 10.20.30.0/24 to 10.20.30.1 port 8080",
		"pass quick proto icmp from 10.20.30.0/24 to 10.20.30.1",
		// Inbound host->guest SSH: from the gateway to the subnet (order inverted).
		"pass quick proto tcp from 10.20.30.1 to 10.20.30.0/24 port 22",
		// Deny inbound to the HTTP proxy port from outside the subnet.
		"block drop quick proto tcp from ! 10.20.30.0/24 to any port 8080",
		"block drop quick from 10.20.30.0/24 to any",
	}
	for _, line := range want {
		if !strings.Contains(rules, "\n"+line+"\n") && !strings.HasPrefix(rules, line+"\n") {
			t.Errorf("missing exact rule line: %q\n---\n%s", line, rules)
		}
	}

	// No double spaces in rule lines (single-space separated is required by the
	// token-for-token validator).
	for l := range strings.SplitSeq(rules, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
			continue
		}
		if strings.Contains(l, "  ") {
			t.Errorf("rule line has double space: %q", l)
		}
	}
}

func TestBuildPreBootDenyRules_Shape(t *testing.T) {
	rules := BuildPreBootDenyRules("10.20.30.0/24", 8080)

	// The pre-boot ruleset must contain exactly two non-comment lines, both
	// "block" rules the helper's validatePFRules accepts token-for-token: the
	// inbound HTTP-proxy confinement (closes the pre-boot open-proxy window) and
	// the IPv4 terminal default-deny. Both are a strict subset of the full ruleset
	// so Apply can replace them wholesale.
	proxyDeny := "block drop quick proto tcp from ! 10.20.30.0/24 to any port 8080"
	deny := "block drop quick from 10.20.30.0/24 to any"
	for _, want := range []string{proxyDeny, deny} {
		if !strings.Contains(rules, "\n"+want+"\n") && !strings.HasPrefix(rules, want+"\n") {
			t.Errorf("missing exact rule line: %q\n---\n%s", want, rules)
		}
	}
	for l := range strings.SplitSeq(rules, "\n") {
		line := strings.TrimSpace(l)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line != proxyDeny && line != deny {
			// The pre-boot ruleset must contain only the two block rules (no allow
			// rules) so it is genuinely fail-closed.
			t.Errorf("unexpected non-comment rule in pre-boot ruleset: %q", line)
		}
	}
}

func TestPreBootDenyRules_ValidatesInputs(t *testing.T) {
	if _, err := PreBootDenyRules("dev", "10.20.30.0/24", 8080); err != nil {
		t.Fatalf("valid inputs: unexpected error: %v", err)
	}
	if _, err := PreBootDenyRules("dev", "10.20.30.5/24", 8080); err == nil {
		t.Error("expected error for a non-network (.5) subnet address")
	}
	if _, err := PreBootDenyRules("bad name!", "10.20.30.0/24", 8080); err == nil {
		t.Error("expected error for an invalid instance name")
	}
	if _, err := PreBootDenyRules("dev", "10.20.30.0/24", 80); err == nil {
		t.Error("expected error for a privileged (out-of-range) HTTP port")
	}
}

func TestInstanceRules_Valid(t *testing.T) {
	rules, err := InstanceRules("dev", "10.20.30.0/24", "10.20.30.1", "bridge100", 5300, 8080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rules, "10.20.30.0/24") {
		t.Fatal("expected generated rules to contain the subnet")
	}
}

// TestInstanceRules_AcceptedBridges asserts both vfkit's bridgeN interfaces and
// VMware Fusion's vmnetN interfaces are accepted (bridgeNameRE widening).
func TestInstanceRules_AcceptedBridges(t *testing.T) {
	for _, bridge := range []string{"bridge100", "bridge0", "vmnet2", "vmnet19"} {
		t.Run(bridge, func(t *testing.T) {
			rules, err := InstanceRules("dev", "10.20.30.0/24", "10.20.30.1", bridge, 5300, 8080)
			if err != nil {
				t.Fatalf("expected bridge %q to be accepted, got: %v", bridge, err)
			}
			if !strings.Contains(rules, "block drop quick on "+bridge+" inet6 all") {
				t.Fatalf("expected generated rules to reference bridge %q", bridge)
			}
		})
	}
}

func TestInstanceRules_Rejects(t *testing.T) {
	tests := []struct {
		name     string
		instance string
		subnet   string
		gateway  string
		bridge   string
		dnsPort  int
		httpPort int
	}{
		{"empty instance", "", "10.20.30.0/24", "10.20.30.1", "bridge100", 5300, 8080},
		{"unsafe instance", "bad name", "10.20.30.0/24", "10.20.30.1", "bridge100", 5300, 8080},
		{"not a /24", "dev", "10.20.30.0/16", "10.20.30.1", "bridge100", 5300, 8080},
		{"non-network subnet", "dev", "10.20.30.5/24", "10.20.30.1", "bridge100", 5300, 8080},
		{"garbage subnet", "dev", "nope", "10.20.30.1", "bridge100", 5300, 8080},
		{"wrong gateway", "dev", "10.20.30.0/24", "10.20.30.254", "bridge100", 5300, 8080},
		{"bad bridge", "dev", "10.20.30.0/24", "10.20.30.1", "en0", 5300, 8080},
		{"bare bridge no digits", "dev", "10.20.30.0/24", "10.20.30.1", "bridge", 5300, 8080},
		{"bare vmnet no digits", "dev", "10.20.30.0/24", "10.20.30.1", "vmnet", 5300, 8080},
		{"vmnet non-digit suffix", "dev", "10.20.30.0/24", "10.20.30.1", "vmnetX", 5300, 8080},
		{"vmnet injection", "dev", "10.20.30.0/24", "10.20.30.1", "vmnet2; rm -rf", 5300, 8080},
		{"empty bridge", "dev", "10.20.30.0/24", "10.20.30.1", "", 5300, 8080},
		{"privileged dns port", "dev", "10.20.30.0/24", "10.20.30.1", "bridge100", 53, 8080},
		{"out-of-range http port", "dev", "10.20.30.0/24", "10.20.30.1", "bridge100", 5300, 70000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InstanceRules(tc.instance, tc.subnet, tc.gateway, tc.bridge, tc.dnsPort, tc.httpPort); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
