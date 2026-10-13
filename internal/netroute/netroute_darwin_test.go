//go:build darwin

package netroute

import (
	"errors"
	"testing"
)

func TestParseDarwinRouted(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "split-include VPN specific /24",
			out:  "   route to: 192.168.128.1\ndestination: 192.168.128\n       mask: 255.255.255.0\n  interface: utun4\n",
			want: true,
		},
		{
			name: "full-tunnel default",
			out:  "   route to: 192.168.128.1\ndestination: default\n  interface: utun4\n",
			want: false,
		},
		{
			name: "plain LAN connected",
			out:  "   route to: 192.168.1.1\ndestination: 192.168.1\n       mask: 255.255.255.0\n  interface: en0\n",
			want: true,
		},
		{
			name: "host route (no mask line)",
			out:  "   route to: 192.168.128.1\ndestination: 192.168.128.1\n    gateway: 10.79.128.1\n  interface: utun4\n",
			want: true,
		},
		{
			name: "no destination line",
			out:  "   route to: 192.168.129.1\n",
			want: false,
		},
		{
			name: "empty output",
			out:  "",
			want: false,
		},
		{
			name: "full-tunnel VPN /1 half",
			out:  "   route to: 192.168.128.1\ndestination: 128.0.0.0\n       mask: 128.0.0.0\n    gateway: 10.79.128.1\n  interface: utun4\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n",
			want: false,
		},
		{
			name: "broad VPN split-include /16 (truncated destination)",
			out:  "   route to: 192.168.128.1\ndestination: 192.168\n       mask: 255.255.0.0\n    gateway: 10.79.128.1\n  interface: utun4\n",
			want: false,
		},
		{
			name: "/23 supernet",
			out:  "   route to: 192.168.128.1\ndestination: 192.168.128\n       mask: 255.255.254.0\n  interface: utun4\n",
			want: false,
		},
		{
			name: "/25 more-specific route",
			out:  "   route to: 192.168.128.1\ndestination: 192.168.128\n       mask: 255.255.255.128\n  interface: utun4\n",
			want: true,
		},
		{
			name: "unparseable mask fails open",
			out:  "   route to: 192.168.128.1\ndestination: 192.168.128\n       mask: bogus\n  interface: utun4\n",
			want: false,
		},
		{
			name: "stray later mask line does not override the route block",
			out:  "   route to: 192.168.128.1\ndestination: 128.0.0.0\n       mask: 128.0.0.0\n  interface: utun4\nmask: 255.255.255.0\n",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDarwinRouted(tc.out); got != tc.want {
				t.Fatalf("parseDarwinRouted(%q) = %v, want %v", tc.out, got, tc.want)
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

	// A covering route at /24 is a conflict.
	runProbe = func(string, ...string) (string, error) {
		return "destination: 192.168.128\n       mask: 255.255.255.0\n  interface: utun4\n", nil
	}
	if !SubnetRouted("192.168.128.1") {
		t.Error("SubnetRouted should report a conflict for a specifically-routed subnet")
	}

	// A default destination is not a conflict.
	runProbe = func(string, ...string) (string, error) {
		return "destination: default\n  interface: utun4\n", nil
	}
	if SubnetRouted("192.168.129.1") {
		t.Error("SubnetRouted should not report a conflict for a default destination")
	}

	// A full-tunnel VPN /1 covering route is broader than the /24 — not a conflict.
	runProbe = func(string, ...string) (string, error) {
		return "destination: 128.0.0.0\n       mask: 128.0.0.0\n  interface: utun4\n", nil
	}
	if SubnetRouted("192.168.130.1") {
		t.Error("SubnetRouted should not report a conflict for a covering route broader than /24")
	}
}
