//go:build !darwin

package egress

import (
	"github.com/sandialabs/abox/internal/backend"
)

// IptablesBase is the shared, embeddable state of an iptables egress controller
// (libvirt + vmware on Linux/Windows). A backend's EgressController embeds it (as
// a value field) and adds its own Define/Apply/Remove/Verify/VerifyEnforced, which
// legitimately differ between backends (libvirt has an nwfilter half and verifies
// via nwfilter existence; vmware has no nwfilter and verifies via the vmnet
// registry).
//
// Mirrors PfBase: the privileged iptables surface is obtained lazily via the
// injected Provider so read-only paths never spawn the helper. The factory injects
// Provider after construction via each backend's SetEgressProvider
// (backend.EgressProviderSetter).
type IptablesBase struct {
	Provider backend.EgressEnforcerProvider
}

// Enforcer resolves the injected privileged enforcer, or the shared fail-closed
// error when no provider was injected. Mirrors PfBase.Enforcer().
func (b *IptablesBase) Enforcer() (backend.EgressEnforcer, error) {
	return backend.ResolveEnforcer(b.Provider)
}
