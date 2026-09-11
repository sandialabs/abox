//go:build !linux && !darwin

package doctor

// Neutral egress-diagnostic labels for platforms without a VM backend of their
// own (e.g. Windows): avoid naming a mechanism (iptables/pf) that does not apply.
const (
	egressFilterName     = "egress filter"
	dnsRedirectMechanism = "host firewall rules"
	natRulesDesc         = "firewall NAT rules"
	filterRulesDesc      = "firewall rules"
)
