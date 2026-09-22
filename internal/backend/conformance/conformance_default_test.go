//go:build !darwin

package conformance

// vmwareExpectsEgressProviderSetter is the per-OS expectation for the vmware
// backend's privileged-provider injection hook. On Linux/Windows the vmware
// backend enforces egress via iptables and therefore implements
// backend.EgressProviderSetter. On darwin it uses pf and implements
// backend.PfProviderSetter instead (see conformance_darwin_test.go).
const vmwareExpectsEgressProviderSetter = true
