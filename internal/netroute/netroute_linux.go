//go:build linux

package netroute

import (
	"strings"

	"github.com/sandialabs/abox/internal/logging"
)

// SubnetRouted reports whether the host already has a route covering gatewayIP
// (the .1 of a candidate /24). On Linux it consults `ip route show match`, which
// lists matching routes most-specific first. Best-effort: any error resolves to
// false (no conflict) so a flaky probe never blocks allocation.
func SubnetRouted(gatewayIP string) bool {
	out, err := runProbe("ip", "-o", "route", "show", "match", gatewayIP)
	if err != nil {
		logging.Debug("host-route probe failed; treating subnet as unrouted", "gateway", gatewayIP, "error", err)
		return false
	}
	return parseLinuxRouted(out)
}

// parseLinuxRouted reports a conflict when any route matching gatewayIP is a
// specific (non-default) one. `ip route show match` lists only routes whose prefix
// covers the address, so every non-`default` line genuinely covers it: a VPN
// split-include /24, the host's own LAN, or a leftover bridge. A `default` route
// cannot shadow a connected /24, so it is not a conflict; zero output means no
// matching route at all. Scanning every line (rather than just the first) avoids
// relying on iproute2's undocumented most-specific-first ordering.
func parseLinuxRouted(out string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "default") {
			continue
		}
		return true
	}
	return false
}
