//go:build linux

package netroute

import (
	"net"
	"strings"

	"github.com/sandialabs/abox/internal/logging"
)

// SubnetRouted reports whether the host already has a route covering gatewayIP
// (the .1 of a candidate /24) at /24 or narrower — i.e. one that would shadow
// the connected /24. On Linux it consults `ip route show match`. Best-effort:
// any error resolves to false (no conflict) so a flaky probe never blocks
// allocation.
func SubnetRouted(gatewayIP string) bool {
	out, err := runProbe("ip", "-o", "route", "show", "match", gatewayIP)
	if err != nil {
		logging.Debug("host-route probe failed; treating subnet as unrouted", "gateway", gatewayIP, "error", err)
		return false
	}
	return parseLinuxRouted(out)
}

// parseLinuxRouted reports a conflict when any route matching gatewayIP is at
// least as specific as the candidate /24. `ip route show match` lists every
// route whose prefix covers the address, so each line genuinely covers it —
// but only a route at /24 or narrower (a VPN split-include /24, the host's own
// LAN, a leftover bridge, a host route) can shadow the connected /24. Broader
// covering routes (default, a full-tunnel VPN's 0.0.0.0/1 halves, a
// 192.168.0.0/16 split-include) lose longest-prefix match to the connected /24
// and are not conflicts; zero output means no matching route at all. Scanning
// every line (rather than just the first) matters: the conflicting /24 may be
// listed after broader supernets.
// blackholingRouteTypes are `ip route` type prefixes that drop traffic for
// their destination just like a shadowing route would, so they count toward
// conflicts. `throw` is deliberately absent: it only falls through to the next
// routing table and cannot shadow a connected /24.
var blackholingRouteTypes = map[string]bool{
	"unreachable": true,
	"blackhole":   true,
	"prohibit":    true,
}

func parseLinuxRouted(out string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "default" {
			continue
		}
		dst := fields[0]
		if blackholingRouteTypes[dst] && len(fields) >= 2 {
			// `unreachable 192.168.128.0/24` etc.: destination is the second token.
			dst = fields[1]
		}
		n := destPrefixLen(dst)
		if n < 0 {
			logging.Debug("unrecognized route line; ignoring (fail-open)", "line", strings.TrimSpace(line))
			continue
		}
		if n >= conflictPrefixLen {
			return true
		}
	}
	return false
}

// destPrefixLen returns the prefix length of an `ip route` destination token:
// a CIDR as written, a bare IPv4 address as /32 (host route), and -1 for
// anything unrecognized so the caller fails open.
func destPrefixLen(dst string) int {
	if _, ipnet, err := net.ParseCIDR(dst); err == nil {
		ones, _ := ipnet.Mask.Size()
		return ones
	}
	if ip := net.ParseIP(dst); ip != nil && ip.To4() != nil {
		return 32
	}
	return -1
}
