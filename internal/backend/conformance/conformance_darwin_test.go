//go:build darwin

package conformance

import (
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/vfkit"
	"github.com/sandialabs/abox/internal/backend/vmware"
)

// vmwareExpectsEgressProviderSetter is the per-OS expectation for the vmware
// backend's privileged-provider injection hook. On darwin the vmware/Fusion
// backend enforces egress via pf, so it implements backend.PfProviderSetter (NOT
// EgressProviderSetter). The non-darwin value lives in
// conformance_default_test.go. TestVmwareImplementsPfProviderSetter asserts the
// pf hook directly (the shared Expectations struct does not model it).
const vmwareExpectsEgressProviderSetter = false

// TestVfkitConformance runs the shared backend contract against the macOS/vfkit
// backend. It lives in a darwin-only file (not the portable conformance_test.go)
// because the vfkit package carries a //go:build darwin tag and does not compile
// on Linux. The backend is constructed directly via vfkit.New() rather than
// backend.Get(), so the suite stays hermetic (no vfkit binary required).
//
// The expectations MATCH this batch's reality: no snapshots, no monitor
// transport, and no custom-template support. vfkit DOES advertise a pfctl-backed
// EgressController (Batch 4) and declares RequiredTools (ToolRequirer). It does
// NOT implement EgressProviderSetter — its privileged half is pf, injected via
// the separate PfProviderSetter interface (asserted directly below).
func TestVfkitConformance(t *testing.T) {
	RunBackendContract(t, vfkit.New(), Expectations{
		Name:                  "vfkit",
		Snapshot:              false,
		EgressController:      true,
		MonitorTransport:      false,
		ToolRequirer:          true,
		TemplateValidator:     false,
		EgressProviderSetter:  false,
		StorageProviderSetter: false, // no host-side storage enforcer on macOS
		NetworkDefaulter:      true,  // supplies the vmnet host-mode subnet pool
	})
}

// TestVfkitImplementsPfProviderSetter asserts the vfkit backend exposes the pf
// provider injection hook the factory uses (backend.PfProviderSetter). This is
// the pf analogue of EgressProviderSetter; the shared conformance Expectations
// does not model it, so it is asserted here directly.
func TestVfkitImplementsPfProviderSetter(t *testing.T) {
	if _, ok := vfkit.New().(backend.PfProviderSetter); !ok {
		t.Fatal("vfkit.New() must implement backend.PfProviderSetter (factory injects the pf provider via it)")
	}
}

// TestVmwareImplementsPfProviderSetter asserts that on darwin the vmware backend
// exposes the pf provider injection hook (backend.PfProviderSetter), not the
// iptables EgressProviderSetter. On darwin the vmware backend enforces egress via
// pf (iptables is absent), so the factory injects the pf provider via this hook.
// Mirrors TestVfkitImplementsPfProviderSetter.
func TestVmwareImplementsPfProviderSetter(t *testing.T) {
	b := vmware.New()
	if _, ok := b.(backend.PfProviderSetter); !ok {
		t.Fatal("vmware.New() must implement backend.PfProviderSetter on darwin (factory injects the pf provider via it)")
	}
	if _, ok := b.(backend.EgressProviderSetter); ok {
		t.Fatal("vmware.New() must NOT implement backend.EgressProviderSetter on darwin (its privileged half is pf, not iptables)")
	}
}
