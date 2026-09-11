package filterbase

import "testing"

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Loopback addresses
		{"loopback-127.0.0.1", loopbackAddr, true},
		{"loopback-127.255.255.255", "127.255.255.255", true},
		{"loopback-ipv6", "::1", true},

		// Private addresses (RFC 1918)
		{"private-10.0.0.1", "10.0.0.1", true},
		{"private-10.255.255.255", "10.255.255.255", true},
		{"private-172.16.0.1", "172.16.0.1", true},
		{"private-172.31.255.255", "172.31.255.255", true},
		{"private-192.168.0.1", "192.168.0.1", true},
		{"private-192.168.255.255", "192.168.255.255", true},

		// IPv6 private (fc00::/7)
		{"private-ipv6-fc00", "fc00::1", true},
		{"private-ipv6-fd00", "fd00::1", true},

		// Link-local addresses
		{"link-local-169.254.1.1", "169.254.1.1", true},
		{"link-local-169.254.254.254", "169.254.254.254", true},
		{"link-local-ipv6", "fe80::1", true},

		// IPv6 link-local with scope ID (SSRF bypass fix)
		{"link-local-ipv6-scope-eth0", "fe80::1%eth0", true},
		{"link-local-ipv6-scope-lo", "fe80::1%lo", true},
		{"link-local-ipv6-scope-numeric", "fe80::1%1", true},
		{"link-local-ipv6-scope-long", "fe80::dead:beef%enp0s3", true},

		// Broadcast
		{"broadcast-255.255.255.255", "255.255.255.255", true},

		// Unspecified
		{"unspecified-0.0.0.0", "0.0.0.0", true},
		{"unspecified-ipv6", "::", true},

		// Multicast
		{"multicast-224.0.0.1", "224.0.0.1", true},
		{"multicast-239.255.255.255", "239.255.255.255", true},
		{"multicast-ipv6", "ff02::1", true},

		// IPv6 site-local (deprecated but blocked)
		{"site-local-ipv6", "fec0::1", true},

		// NAT64 (RFC 6052 64:ff9b::/96) embedding a dangerous IPv4 must be blocked
		// by re-checking the embedded address; a public embedded IPv4 is allowed.
		{"nat64-loopback", "64:ff9b::7f00:1", true},         // 127.0.0.1
		{"nat64-private-10", "64:ff9b::a00:1", true},        // 10.0.0.1
		{"nat64-metadata", "64:ff9b::a9fe:a9fe", true},      // 169.254.169.254
		{"nat64-public-8.8.8.8", "64:ff9b::808:808", false}, // 8.8.8.8

		// CGNAT / RFC 6598 shared address space (100.64.0.0/10)
		{"cgnat-100.64.0.1", "100.64.0.1", true},
		{"cgnat-100.127.255.255", "100.127.255.255", true},
		{"cgnat-boundary-below-100.63", "100.63.255.255", false},
		{"cgnat-boundary-above-100.128", "100.128.0.0", false},

		// Public addresses (should NOT be blocked)
		{"public-8.8.8.8", "8.8.8.8", false},
		{"public-1.1.1.1", "1.1.1.1", false},
		{"public-203.0.113.4", "203.0.113.4", false},
		{"public-203.0.113.34", "203.0.113.34", false},
		{"public-ipv6", "2001:db8::8888", false},

		// Edge cases
		{"non-ip-domain", "github.com", false},
		{"non-ip-empty", "", false},
		{"non-ip-garbage", "not-an-ip", false},

		// 172.x boundary cases (only 172.16-31 is private)
		{"private-boundary-172.15", "172.15.255.255", false},
		{"private-boundary-172.16", "172.16.0.0", true},
		{"private-boundary-172.31", "172.31.255.255", true},
		{"private-boundary-172.32", "172.32.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBlockedIP(tt.ip)
			if result != tt.blocked {
				t.Errorf("IsBlockedIP(%q) = %v, want %v", tt.ip, result, tt.blocked)
			}
		})
	}
}

func TestNewTargetCheckerInvalidCIDR(t *testing.T) {
	for _, c := range []string{"10.0.0.0/33", "not-a-cidr", "10.0.0.1", "10.0.0.0/8/8"} {
		if _, err := NewTargetChecker([]string{c}); err == nil {
			t.Errorf("NewTargetChecker(%q) = nil error, want error", c)
		}
	}
	// Empty/whitespace entries are skipped, not errors.
	if _, err := NewTargetChecker([]string{"", "  ", "10.0.0.0/8"}); err != nil {
		t.Errorf("NewTargetChecker with blank entries returned error: %v", err)
	}
}

// TestNewTargetCheckerRejectsDefaultRoute guards against the footgun where a
// default route would silently disable all SSRF protection.
func TestNewTargetCheckerRejectsDefaultRoute(t *testing.T) {
	for _, c := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := NewTargetChecker([]string{c}); err == nil {
			t.Errorf("NewTargetChecker(%q) = nil error, want rejection of default route", c)
		}
	}
	// A /8 (broad but not a default route) is allowed.
	if _, err := NewTargetChecker([]string{"10.0.0.0/8"}); err != nil {
		t.Errorf("NewTargetChecker(10.0.0.0/8) returned error: %v", err)
	}
}

func TestTargetCheckerIsBlocked(t *testing.T) {
	tc, err := NewTargetChecker([]string{"10.0.5.0/24", "192.168.1.10/32", "fd00::/8"})
	if err != nil {
		t.Fatalf("NewTargetChecker: %v", err)
	}
	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		// Permitted private ranges.
		{"in-allowed-cidr", "10.0.5.7", false},
		{"allowed-cidr-network-addr", "10.0.5.0", false},
		{"allowed-host-32", "192.168.1.10", false},
		{"allowed-ipv6", "fd00::1", false},
		// Dangerous IPs NOT covered by the allow-list stay blocked — notably the
		// cloud metadata address, the SSRF scenario M1 closes.
		{"metadata-not-allowed", "169.254.169.254", true},
		{"other-private-not-allowed", "10.0.6.1", true},
		{"host-outside-32", "192.168.1.11", true},
		{"loopback-not-allowed", loopbackAddr, true},
		// Public IPs and hostnames are never blocked by this layer.
		{"public", "8.8.8.8", false},
		{"hostname", "github.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tc.IsBlocked(tt.host); got != tt.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.host, got, tt.blocked)
			}
		})
	}
}

func TestTargetCheckerNilAndZeroDenyAll(t *testing.T) {
	// A nil *TargetChecker and the zero value both deny all dangerous ranges
	// (fail-closed default) while allowing public IPs.
	var nilTC *TargetChecker
	zeroTC := &TargetChecker{}
	for _, tc := range []*TargetChecker{nilTC, zeroTC} {
		if !tc.IsBlocked("169.254.169.254") {
			t.Error("metadata IP must be blocked by empty checker")
		}
		if !tc.IsBlocked("10.0.0.1") {
			t.Error("private IP must be blocked by empty checker")
		}
		if tc.IsBlocked("8.8.8.8") {
			t.Error("public IP must not be blocked")
		}
	}
}
