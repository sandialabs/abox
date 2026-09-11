//go:build linux

package conformance

import (
	"testing"

	"github.com/sandialabs/abox/internal/backend/libvirt"
)

// TestLibvirtConformance runs the shared contract against the libvirt backend,
// which is linux-only (the package carries a //go:build linux tag). It lives in
// a linux-tagged file so the portable conformance package still builds cleanly
// for GOOS=darwin/windows (where libvirt is not compiled).
//
// The backend is constructed via libvirt.New() — the same way libvirt's own
// unit tests build it — rather than backend.Get("libvirt"), which would call
// IsAvailable() and require virsh on the host, breaking hermeticity.
func TestLibvirtConformance(t *testing.T) {
	RunBackendContract(t, libvirt.New(), Expectations{
		Name:                  "libvirt",
		Snapshot:              true,
		EgressController:      true,
		MonitorTransport:      true,
		ToolRequirer:          true,  // declares virsh + setfacl
		TemplateValidator:     true,  // libvirt supports custom domain XML templates
		EgressProviderSetter:  true,  // privileged host-side enforcement (iptables)
		StorageProviderSetter: true,  // factory injects the storage enforcer provider
		NetworkDefaulter:      false, // uses the default subnet pool, not a backend pool
	})
}
