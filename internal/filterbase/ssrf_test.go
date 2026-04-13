package filterbase

import "testing"

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Loopback addresses
		{"loopback-127.0.0.1", "127.0.0.1", true},
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

		// Public addresses (should NOT be blocked)
		{"public-8.8.8.8", "8.8.8.8", false},
		{"public-1.1.1.1", "1.1.1.1", false},
		{"public-140.82.121.4", "140.82.121.4", false},
		{"public-93.184.216.34", "93.184.216.34", false},
		{"public-ipv6", "2001:4860:4860::8888", false},

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
