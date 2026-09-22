//go:build darwin

package netroute

import (
	"strings"

	"github.com/sandialabs/abox/internal/logging"
)

// SubnetRouted reports whether the host already has a route covering gatewayIP
// (the .1 of a candidate /24). On macOS it consults `route -n get`. Best-effort:
// any error resolves to false (no conflict) so a flaky probe never blocks
// allocation.
func SubnetRouted(gatewayIP string) bool {
	out, err := runProbe("route", "-n", "get", "-inet", gatewayIP)
	if err != nil {
		logging.Debug("host-route probe failed; treating subnet as unrouted", "gateway", gatewayIP, "error", err)
		return false
	}
	return parseDarwinRouted(out)
}

// parseDarwinRouted reports a conflict when `route -n get` resolves gatewayIP to
// a specific (non-default) destination. `route get` always resolves to something;
// a "default" destination is the fallthrough route, which cannot shadow a
// connected /24, so it is not a conflict. Any other destination (a VPN
// split-include /24, the host's own LAN, a leftover bridge) is.
func parseDarwinRouted(out string) bool {
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "destination:")
		if !ok {
			continue
		}
		dest := strings.TrimSpace(rest)
		return dest != "" && dest != "default"
	}
	return false
}
