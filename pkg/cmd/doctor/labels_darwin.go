//go:build darwin

package doctor

// Platform labels for egress-enforcement diagnostics. On macOS/vfkit egress is
// enforced entirely by a per-instance pf anchor (abox/<name>) — there is no
// libvirt nwfilter and no iptables. Inspect it with `pfctl -a abox/<name> -sr`.
const (
	egressFilterName     = "pf anchor"
	dnsRedirectMechanism = "pf rules"
	natRulesDesc         = "pf DNS redirect (rdr) rules"
	filterRulesDesc      = "pf anchor rules"
)
