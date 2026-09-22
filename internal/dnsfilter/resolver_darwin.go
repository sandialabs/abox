//go:build darwin

package dnsfilter

import (
	"net"
	"os/exec"
	"strings"
)

// On macOS the host resolver lives in SystemConfiguration, not /etc/resolv.conf
// (which is frequently absent, or a stale snapshot that lags VPN/split-DNS
// changes). Reading resolv.conf there would silently forward to the public
// fallback and break internal/corp/VPN domains. Prefer `scutil --dns` — the
// authoritative view of the active resolver — and fall back to the resolv.conf
// reader (then the caller's public fallback) only if scutil yields nothing.
func init() {
	systemUpstreamFn = darwinSystemUpstream
}

// scutilCommand runs `scutil --dns`. It is a package variable so tests can
// substitute deterministic output instead of shelling out.
var scutilCommand = func() ([]byte, error) {
	return exec.Command("scutil", "--dns").Output()
}

func darwinSystemUpstream() (string, bool) {
	if up, ok := scutilUpstream(); ok {
		return up, true
	}
	return resolvConfUpstream()
}

// scutilUpstream parses `scutil --dns` and returns the first IPv4 nameserver as
// "ip:53". scutil prints the primary resolver (resolver #1) first, so the first
// "nameserver[N] : <ip>" line with an IPv4 value is the host's active upstream.
// IPv6 nameservers are skipped for the same reason as resolvConfUpstream.
func scutilUpstream() (string, bool) {
	out, err := scutilCommand()
	if err != nil {
		return "", false
	}
	for raw := range strings.SplitSeq(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		_, after, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val := strings.TrimSpace(after)
		if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
			return net.JoinHostPort(val, "53"), true
		}
	}
	return "", false
}
