package filterbase

import (
	"fmt"
	"net"
	"strings"
)

// loopbackAddr is the IPv4 loopback address. It is defined here (an untagged
// file) rather than in listen_darwin.go so it is visible to every OS build,
// including the untagged ssrf_test.go.
const loopbackAddr = "127.0.0.1"

// cgNAT is RFC 6598 carrier-grade-NAT shared address space (100.64.0.0/10). It
// is not globally routable and never a legitimate public target, so — like the
// RFC 1918 ranges — it is treated as dangerous for SSRF purposes by default.
var cgNAT = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// nat64WKP is the RFC 6052 NAT64 well-known prefix (64:ff9b::/96). An IPv4
// address embedded in the low 32 bits of this prefix is reachable through a
// NAT64 translator, so it must be classified by its embedded IPv4 rather than
// treated as a benign global IPv6 (e.g. 64:ff9b::7f00:1 encodes 127.0.0.1).
var nat64WKP = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("64:ff9b::/96")
	return n
}()

// dangerousIP reports whether ip falls in a range that must never be reached
// through the proxy by default (SSRF protection): loopback, private, CGNAT,
// link-local unicast/multicast (incl. the cloud metadata address
// 169.254.169.254), unspecified, broadcast, IPv6 site-local, and multicast.
func dangerousIP(ip net.IP) bool {
	switch {
	case ip.IsLoopback(), // 127.0.0.0/8, ::1
		ip.IsPrivate(),            // 10/8, 172.16/12, 192.168/16, fc00::/7
		ip.IsLinkLocalUnicast(),   // 169.254.0.0/16 (metadata), fe80::/10
		ip.IsLinkLocalMulticast(), // 224.0.0.0/24, ff02::/16
		ip.IsUnspecified(),        // 0.0.0.0, ::
		ip.Equal(net.IPv4bcast),   // 255.255.255.255
		ip.IsMulticast(),
		cgNAT.Contains(ip): // 100.64.0.0/10 (RFC 6598 CGNAT)
		return true
	}
	// IPv6 site-local (deprecated, fec0::/10)
	if ip.To4() == nil && len(ip) == 16 && ip[0] == 0xfe && (ip[1]&0xc0) == 0xc0 {
		return true
	}
	// NAT64 (RFC 6052 64:ff9b::/96): re-check the embedded IPv4 (low 32 bits) so a
	// dangerous target smuggled through the well-known prefix — e.g.
	// 64:ff9b::7f00:1 (127.0.0.1) — is caught where a NAT64 gateway would route it.
	// IPv4-mapped IPv6 (::ffff:a.b.c.d) is already handled because Go normalizes it.
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil && nat64WKP.Contains(ip) {
		return dangerousIP(net.IPv4(v6[12], v6[13], v6[14], v6[15]))
	}
	return false
}

// parseHostIP strips an IPv6 zone/scope id (e.g. "fe80::1%eth0" -> "fe80::1",
// which net.ParseIP does not accept) and parses host as an IP literal, returning
// nil when host is a hostname rather than an IP.
func parseHostIP(host string) net.IP {
	if idx := strings.Index(host, "%"); idx != -1 {
		host = host[:idx]
	}
	return net.ParseIP(host)
}

// IsBlockedIP reports whether host (an IP literal) is in a dangerous range.
// Hostnames (non-IP) return false — they are resolved and checked at dial time.
// This is the zero-allowance case: equivalent to a TargetChecker permitting no
// CIDRs. Prefer TargetChecker where an operator allow-list may apply.
func IsBlockedIP(host string) bool {
	ip := parseHostIP(host)
	if ip == nil {
		return false
	}
	return dangerousIP(ip)
}

// TargetChecker decides whether a connection target IP must be blocked for SSRF
// protection, honoring an opt-in allow-list of otherwise-dangerous CIDRs that the
// operator has explicitly permitted (config: http.allow_private_targets).
//
// The zero value (and a nil *TargetChecker) denies all dangerous ranges, matching
// IsBlockedIP — so an unconfigured filter is fail-closed by default.
type TargetChecker struct {
	allowed []*net.IPNet
}

// NewTargetChecker builds a checker permitting the given CIDRs. An empty/nil list
// yields the default deny-all-dangerous behavior. Each entry must be valid CIDR
// notation (a single host is "x.x.x.x/32"); an invalid entry is an error.
func NewTargetChecker(cidrs []string) (*TargetChecker, error) {
	tc := &TargetChecker{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid allow_private_targets CIDR %q: %w", c, err)
		}
		// Reject a default route: 0.0.0.0/0 or ::/0 would permit every dangerous
		// range (incl. loopback and the cloud metadata address), silently disabling
		// SSRF protection. Require operators to name the specific ranges they trust.
		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("allow_private_targets CIDR %q is a default route; list specific ranges instead (it would disable SSRF protection entirely)", c)
		}
		tc.allowed = append(tc.allowed, ipnet)
	}
	return tc, nil
}

// IsBlocked reports whether a connection to host (an IP literal or hostname) must
// be blocked. Hostnames return false (resolution-time checks at dial handle them).
// A dangerous-range IP is permitted only if it falls within an allowed CIDR.
func (t *TargetChecker) IsBlocked(host string) bool {
	ip := parseHostIP(host)
	if ip == nil {
		return false
	}
	if !dangerousIP(ip) {
		return false
	}
	if t == nil {
		return true
	}
	for _, n := range t.allowed {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
