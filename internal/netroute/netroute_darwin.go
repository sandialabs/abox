//go:build darwin

package netroute

import (
	"net"
	"strings"

	"github.com/sandialabs/abox/internal/logging"
)

// SubnetRouted reports whether the host already has a route covering gatewayIP
// (the .1 of a candidate /24) at /24 or narrower — i.e. one that would shadow
// the connected /24. On macOS it consults `route -n get`. Best-effort: any
// error resolves to false (no conflict) so a flaky probe never blocks
// allocation.
func SubnetRouted(gatewayIP string) bool {
	out, err := runProbe("route", "-n", "get", "-inet", gatewayIP)
	if err != nil {
		logging.Debug("host-route probe failed; treating subnet as unrouted", "gateway", gatewayIP, "error", err)
		return false
	}
	return parseDarwinRouted(out)
}

// parseDarwinRouted reports a conflict when `route -n get` resolves gatewayIP
// to a route at least as specific as the candidate /24. `route get` always
// resolves to something, so the decision keys off the `mask:` line, never the
// destination (macOS truncates trailing-zero octets: `destination: 192.168`):
//   - a "default" destination is the fallthrough route — never a conflict;
//   - a specific destination with no `mask:` line is an RTF_HOST route
//     (`route get` omits the mask for host routes), i.e. /32 — always a conflict;
//   - otherwise, conflict iff the mask prefix is >= /24. Broader covering
//     routes (a full-tunnel VPN's 0.0.0.0/1 halves, a 192.168.0.0/16
//     split-include) lose longest-prefix match to the connected /24.
//
// An unparseable or non-contiguous mask fails open (no conflict): a false
// conflict can repeat across the whole pool and spuriously exhaust it, while a
// false pass affects one subnet and is caught by the boot-time gateway
// reconciliation guard.
func parseDarwinRouted(out string) bool {
	// First occurrence wins: `route get` prints one route block, so any later
	// line that happens to share a prefix must not override the real values.
	var dest, mask string
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "destination:"); ok && dest == "" {
			dest = strings.TrimSpace(rest)
		} else if rest, ok := strings.CutPrefix(line, "mask:"); ok && mask == "" {
			mask = strings.TrimSpace(rest)
		}
		if dest != "" && mask != "" {
			break
		}
	}
	switch {
	case dest == "" || dest == "default":
		return false
	case mask == "":
		return true // host route: no mask line means /32
	}
	m := net.ParseIP(mask)
	if m == nil || m.To4() == nil {
		logging.Debug("unparseable route mask; treating as no conflict", "mask", mask)
		return false
	}
	ones, bits := net.IPMask(m.To4()).Size()
	if bits == 0 {
		logging.Debug("non-contiguous route mask; treating as no conflict", "mask", mask)
		return false
	}
	return ones >= conflictPrefixLen
}
