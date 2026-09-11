//go:build linux

package doctor

// Platform labels for egress-enforcement diagnostics. On Linux/libvirt egress is
// enforced by a libvirt nwfilter plus host iptables (DNS REDIRECT + NAT).
const (
	egressFilterName     = "nwfilter"
	dnsRedirectMechanism = "host iptables rules"
	natRulesDesc         = "iptables NAT rules"
	filterRulesDesc      = "nwfilter rules"
)
