//go:build linux

package netroute

import (
	"errors"
	"testing"
)

func TestParseLinuxRouted(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"split-include VPN specific /24", "192.168.128.0/24 via 10.79.128.1 dev utun4 \n", true},
		{"full-tunnel default via utun", "default via 10.79.128.1 dev utun4 \n", false},
		{"plain LAN connected route", "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.20 \n", true},
		{"default before specific (ordering-independent)", "default via 192.168.1.1 dev eth0\n192.168.128.0/24 via 10.79.128.1 dev utun4\n", true},
		{"empty output (no matching route)", "", false},
		{"whitespace only", "   \n\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseLinuxRouted(tc.out); got != tc.want {
				t.Fatalf("parseLinuxRouted(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}

func TestSubnetRouted_FailOpenAndConflict(t *testing.T) {
	orig := runProbe
	t.Cleanup(func() { runProbe = orig })

	// A probe error must fail open (report not-routed) so allocation is never blocked.
	runProbe = func(string, ...string) (string, error) { return "", errors.New("boom") }
	if SubnetRouted("192.168.128.1") {
		t.Error("SubnetRouted should fail open (false) when the probe errors")
	}

	// A specific (non-default) route is a conflict.
	runProbe = func(string, ...string) (string, error) {
		return "192.168.128.0/24 via 10.79.128.1 dev utun4\n", nil
	}
	if !SubnetRouted("192.168.128.1") {
		t.Error("SubnetRouted should report a conflict for a specifically-routed subnet")
	}

	// A default-only match is not a conflict.
	runProbe = func(string, ...string) (string, error) {
		return "default via 192.168.1.1 dev eth0\n", nil
	}
	if SubnetRouted("192.168.129.1") {
		t.Error("SubnetRouted should not report a conflict for a default-only match")
	}
}
