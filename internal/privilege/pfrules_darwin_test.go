//go:build darwin

package privilege

import (
	"fmt"
	"strings"
	"testing"
)

// genInstanceRules reproduces internal/firewall.buildInstanceRules verbatim so
// the validator is exercised against the exact bytes the legitimate client
// emits. If the generator changes shape, this test (and the templates in
// pfrules_darwin.go) must change with it — a deliberate tripwire.
func genInstanceRules(vmIP, gateway, bridge string, dnsPort, httpPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# abox instance traffic rules for %s\n", vmIP)
	fmt.Fprintf(&b, "# DNS redirect (VM queries to any :53 -> local dnsfilter)\n")
	fmt.Fprintf(&b, "rdr pass proto udp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "rdr pass proto tcp from %s to any port 53 -> 127.0.0.1 port %d\n", vmIP, dnsPort)
	fmt.Fprintf(&b, "# Block all IPv6 on this VM's bridge (vmnet has no flag to disable NAT66)\n")
	fmt.Fprintf(&b, "block drop quick on %s inet6 all\n", bridge)
	fmt.Fprintf(&b, "# Allowlisted outbound\n")
	fmt.Fprintf(&b, "pass quick proto udp from %s port 68 to any port 67\n", vmIP)
	fmt.Fprintf(&b, "pass quick proto tcp from %s to %s port %d\n", vmIP, gateway, httpPort)
	fmt.Fprintf(&b, "pass quick proto icmp from %s to %s\n", vmIP, gateway)
	fmt.Fprintf(&b, "# Default deny: everything else from the VM is dropped\n")
	fmt.Fprintf(&b, "block drop quick from %s to any\n", vmIP)
	return b.String()
}

// TestValidatePFRules_AcceptsGeneratedRulesets guarantees the validator never
// rejects a ruleset the legitimate generator produces, across a range of
// realistic per-instance parameter values.
func TestValidatePFRules_AcceptsGeneratedRulesets(t *testing.T) {
	cases := []struct {
		vmIP, gateway, bridge string
		dnsPort, httpPort     int
	}{
		{"192.168.128.5", "192.168.128.1", "bridge101", 5353, 8443},
		{"192.168.64.2", "192.168.64.1", "bridge100", 1024, 65535},
		{"10.0.0.42", "10.0.0.1", "bridge255", 49152, 49153},
		{"172.16.5.9", "172.16.5.1", "bridge100", 5300, 8080},
	}
	for _, c := range cases {
		rules := genInstanceRules(c.vmIP, c.gateway, c.bridge, c.dnsPort, c.httpPort)
		if err := validatePFRules(rules); err != nil {
			t.Errorf("validatePFRules rejected a legitimate ruleset (%+v): %v\n%s", c, err, rules)
		}
	}
}

func TestValidatePFRules_Malicious(t *testing.T) {
	base := genInstanceRules("192.168.128.5", "192.168.128.1", "bridge101", 5353, 8443)

	tests := []struct {
		name  string
		rules string
	}{
		{
			name:  "empty",
			rules: "",
		},
		{
			name:  "whitespace only",
			rules: "   \n\t\n",
		},
		{
			name:  "comments only, no rules",
			rules: "# just a comment\n# another\n",
		},
		{
			name:  "nested anchor",
			rules: base + "anchor \"evil\"\n",
		},
		{
			name:  "load anchor from file",
			rules: base + "load anchor abox from /tmp/evil.conf\n",
		},
		{
			name:  "include directive",
			rules: "include \"/etc/evil.conf\"\n",
		},
		{
			name:  "table file reference",
			rules: "table <bad> persist file \"/tmp/ips\"\n",
		},
		{
			name:  "rdr hijack of host traffic (foreign source)",
			rules: "rdr pass proto tcp from 10.9.9.9 to any port 443 -> 127.0.0.1 port 9999\n",
		},
		{
			name:  "rdr to a privileged local port",
			rules: "rdr pass proto tcp from 192.168.128.5 to any port 53 -> 127.0.0.1 port 22\n",
		},
		{
			name:  "pass all (default-allow injection)",
			rules: "pass all\n",
		},
		{
			name:  "pass to arbitrary host (exfil)",
			rules: base + "pass quick proto tcp from 192.168.128.5 to 8.8.8.8 port 443\n",
		},
		{
			name:  "block redirect rule targeting non-127 loopback",
			rules: "rdr pass proto tcp from 192.168.128.5 to any port 53 -> 10.0.0.1 port 5353\n",
		},
		{
			name:  "shell-ish garbage / command injection chars",
			rules: "rdr pass proto tcp from 192.168.128.5 to any port 53 -> 127.0.0.1 port 5353; pass all\n",
		},
		{
			name:  "semicolon separator splicing a second directive",
			rules: "block drop quick from 192.168.128.5 to any ; pass all\n",
		},
		{
			name:  "brace block",
			rules: "pass quick proto tcp from 192.168.128.5 to { 1.2.3.4 5.6.7.8 } port 8443\n",
		},
		{
			name:  "set directive",
			rules: base + "set skip on lo0\n",
		},
		{
			name:  "scrub directive",
			rules: "scrub in all\n",
		},
		{
			name:  "interface-scoped pass widening egress",
			rules: "pass out quick on en0 all\n",
		},
		{
			name:  "IPv6 source bypassing the inet6 block",
			rules: "pass quick proto tcp from fe80::1 to any port 8443\n",
		},
		{
			name:  "bridge name with injection",
			rules: "block drop quick on bridge101; pass all inet6 all\n",
		},
		{
			name:  "non-bridge interface in inet6 block",
			rules: "block drop quick on en0 inet6 all\n",
		},
		{
			name:  "port out of range (privileged)",
			rules: "pass quick proto tcp from 192.168.128.5 to 192.168.128.1 port 80\n",
		},
		{
			name:  "port out of range (overflow)",
			rules: "pass quick proto tcp from 192.168.128.5 to 192.168.128.1 port 70000\n",
		},
		{
			name:  "extra trailing token on otherwise valid rule",
			rules: "block drop quick from 192.168.128.5 to any keep state\n",
		},
		{
			name:  "NUL byte",
			rules: "rdr pass proto tcp from 192.168.128.5 to any port 53 -> 127.0.0.1\x00 port 5353\n",
		},
		{
			name:  "tab-smuggled second directive on rdr line",
			rules: "rdr pass proto tcp from 192.168.128.5 to any port 53 -> 127.0.0.1 port 5353\tpass all\n",
		},
		{
			name:  "inline comment hiding a directive is still validated",
			rules: "pass all # block drop quick from 192.168.128.5 to any\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePFRules(tt.rules); err == nil {
				t.Errorf("validatePFRules accepted malicious input %q", tt.rules)
			}
		})
	}
}

func TestValidatePFRules_CommentsAndBlanksTolerated(t *testing.T) {
	// Leading/trailing blank lines and comments interleaved with valid rules
	// must be accepted (the generator emits comments between rules).
	rules := "\n# header\n\n" +
		"rdr pass proto udp from 192.168.128.5 to any port 53 -> 127.0.0.1 port 5353\n" +
		"\n# mid comment\n" +
		"block drop quick from 192.168.128.5 to any\n\n"
	if err := validatePFRules(rules); err != nil {
		t.Errorf("validatePFRules rejected valid rules with comments/blanks: %v", err)
	}
}

func TestValidatePFToken(t *testing.T) {
	tests := []struct {
		kind, value string
		want        bool
	}{
		{"<ip>", "192.168.128.5", true},
		{"<ip>", "127.0.0.1", true},
		{"<ip>", "::1", false},
		{"<ip>", "fe80::1", false},
		{"<ip>", "not-an-ip", false},
		{"<ip>", "192.168.128.256", false},
		{"<bridge>", "bridge100", true},
		{"<bridge>", "bridge0", true},
		{"<bridge>", "en0", false},
		{"<bridge>", "bridge100; pass", false},
		{"<port>", "1024", true},
		{"<port>", "65535", true},
		{"<port>", "1023", false},
		{"<port>", "65536", false},
		{"<port>", "53", false},
		{"<port>", "abc", false},
		{"<unknown>", "x", false},
	}
	for _, tt := range tests {
		t.Run(tt.kind+"="+tt.value, func(t *testing.T) {
			if got := validatePFToken(tt.kind, tt.value); got != tt.want {
				t.Errorf("validatePFToken(%q, %q) = %v, want %v", tt.kind, tt.value, got, tt.want)
			}
		})
	}
}
