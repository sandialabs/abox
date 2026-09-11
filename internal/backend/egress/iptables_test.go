//go:build !darwin

package egress

import "testing"

// TestIptablesEnforcerFailsClosed: like the pf side, resolving the enforcer with
// no provider injected must return a clear error (never nil, nil), so read-only and
// privileged paths alike fail closed rather than silently skipping enforcement.
func TestIptablesEnforcerFailsClosed(t *testing.T) {
	var b IptablesBase
	if enf, err := b.Enforcer(); err == nil || enf != nil {
		t.Fatalf("Enforcer with no provider = (%v, %v), want (nil, error)", enf, err)
	}
}
