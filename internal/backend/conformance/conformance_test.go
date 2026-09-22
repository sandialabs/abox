package conformance

import (
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/backend/mock"
	"github.com/sandialabs/abox/internal/backend/vmware"
)

// TestPortableBackendsConformance runs the shared contract against every backend
// that is portable (compiles on all GOOS): the test-only mock and the
// experimental vmware backend. The linux-only libvirt backend is covered by the
// //go:build linux runner in conformance_linux_test.go.
//
// Backends are constructed directly via their package New()/struct rather than
// via backend.Get(): Get() calls IsAvailable(), which requires the vmrun/virsh
// binaries to be installed and would make this suite non-hermetic. Direct
// construction is exactly how each backend's own unit tests build it. A future
// portable backend should be added to this table so the contract picks it up.
func TestPortableBackendsConformance(t *testing.T) {
	cases := []struct {
		name string
		b    backend.Backend
		exp  Expectations
	}{
		{
			name: "mock",
			b:    &mock.Backend{},
			exp: Expectations{
				Name: "mock",
				// mock's accessors always return non-nil defaults.
				Snapshot:         true,
				EgressController: true,
				MonitorTransport: true,
				// The bare mock.Backend implements none of the free-standing
				// optional interfaces (TemplateValidator is a separate type meant
				// to be embedded; mock declares no RequiredTools/SetEgressProvider).
				ToolRequirer:         false,
				TemplateValidator:    false,
				EgressProviderSetter: false,
			},
		},
		{
			name: "vmware",
			b:    vmware.New(),
			exp: Expectations{
				Name:              "vmware",
				Snapshot:          true,
				EgressController:  true,
				MonitorTransport:  true,
				ToolRequirer:      true,  // declares vmrun
				TemplateValidator: false, // vmware has no custom-template support
				// vmware's privileged half is OS-specific: iptables (implements
				// EgressProviderSetter) on Linux/Windows, pf (implements
				// PfProviderSetter, NOT EgressProviderSetter) on darwin. The
				// expected value is set per-OS in the build-tagged
				// conformance_{default,darwin}_test.go files; the darwin file also
				// asserts PfProviderSetter directly (Expectations does not model it,
				// mirroring the vfkit conformance test).
				EgressProviderSetter: vmwareExpectsEgressProviderSetter,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			RunBackendContract(t, tc.b, tc.exp)
		})
	}
}
