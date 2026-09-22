package backend

import (
	"errors"

	"github.com/sandialabs/abox/internal/logging"
)

// errEnforcerNotConfigured is the fail-closed error returned when an
// EgressController was constructed without a privileged enforcer provider (e.g.
// provider injection was skipped). Shared so every backend reports it
// identically.
var errEnforcerNotConfigured = errors.New("egress enforcer not configured (no privileged provider injected)")

// ResolveEnforcer yields the enforcer from a provider, or the shared
// fail-closed error when no provider was injected. The iptables controllers
// resolve through egress.IptablesBase.Enforcer, which delegates here so the nil
// check and error text stay identical across backends.
func ResolveEnforcer(p EgressEnforcerProvider) (EgressEnforcer, error) {
	if p == nil {
		return nil, errEnforcerNotConfigured
	}
	return p()
}

// WarnEgressLeak logs the "host rules may remain" warning shared by every
// backend's Remove path. Orphaned host iptables rules outlive the interface they
// were scoped to, so a teardown failure here is a security-relevant leak and is
// surfaced loudly (with the interface name and a copy-pasteable cleanup command)
// rather than swallowed.
//
// The wording that differs between backends is passed in: msg (the failure
// summary, e.g. bridge vs. vmnet phrasing), ifaceKey/iface (the structured field
// naming the leaked interface), and manualCleanup (the exact command to remove
// the leftover rules). The instance name is always included.
func WarnEgressLeak(msg, instance, ifaceKey, iface, manualCleanup string, cause error) {
	logging.Warn(msg,
		"error", cause, "instance", instance, ifaceKey, iface,
		"manual_cleanup", manualCleanup)
}
