package filterbase

import (
	"net"
	"strings"
)

// IsBlockedIP checks if an IP address should be blocked (SSRF protection).
// Blocks loopback, private, link-local, and other dangerous addresses.
func IsBlockedIP(host string) bool {
	// Strip IPv6 zone/scope ID (e.g., "fe80::1%eth0" -> "fe80::1")
	// Go's net.ParseIP doesn't handle zone IDs and returns nil
	if idx := strings.Index(host, "%"); idx != -1 {
		host = host[:idx]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false // Not an IP, will be checked via domain allowlist
	}

	// Block loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Block private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	if ip.IsPrivate() {
		return true
	}

	// Block link-local unicast (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// Block link-local multicast (224.0.0.0/24, ff02::/16)
	if ip.IsLinkLocalMulticast() {
		return true
	}

	// Block unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// Block broadcast (255.255.255.255)
	if ip.Equal(net.IPv4bcast) {
		return true
	}

	// Block IPv6 site-local (deprecated, fec0::/10)
	if ip.To4() == nil && len(ip) == 16 && ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
		return true
	}

	// Block multicast
	if ip.IsMulticast() {
		return true
	}

	return false
}
