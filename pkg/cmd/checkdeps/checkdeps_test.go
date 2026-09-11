package checkdeps

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/pkg/cmd/factory"
)

// fakeToolBackend is a minimal backend that declares required tools, used to
// exercise the backend-aware merge without depending on a real (linux-only)
// backend package.
type fakeToolBackend struct {
	name  string
	tools []backend.Tool
}

func (f *fakeToolBackend) Name() string                               { return f.name }
func (f *fakeToolBackend) IsAvailable() error                         { return nil }
func (f *fakeToolBackend) VM() backend.VMManager                      { return nil }
func (f *fakeToolBackend) Network() backend.NetworkManager            { return nil }
func (f *fakeToolBackend) Disk() backend.DiskManager                  { return nil }
func (f *fakeToolBackend) Snapshot() backend.SnapshotManager          { return nil }
func (f *fakeToolBackend) EgressController() backend.EgressController { return nil }
func (f *fakeToolBackend) MonitorTransport() backend.MonitorTransport { return nil }
func (f *fakeToolBackend) DryRun(_ *config.Instance, _ *config.Paths, _ io.Writer, _ backend.VMCreateOptions) error {
	return nil
}
func (f *fakeToolBackend) ResourceNames(name string) backend.ResourceNames {
	return backend.ResourceNames{Instance: name}
}
func (f *fakeToolBackend) GenerateMAC() string           { return "00:00:00:00:00:00" }
func (f *fakeToolBackend) StorageDir() string            { return "/tmp/fake" }
func (f *fakeToolBackend) RequiredTools() []backend.Tool { return f.tools }

// TestInstallHint verifies the install hints name the correct package per distro
// family. These caught real gaps for the RHEL/Fedora family (the package is
// fuse-sshfs, openssh-clients, and several deps live in EPEL), so guard them.
func TestInstallHint(t *testing.T) {
	cases := []struct {
		name        string
		mustContain []string
	}{
		{"sshfs", []string{"sshfs", "fuse-sshfs", "EPEL"}},
		{"ssh", []string{"openssh-client", "openssh-clients"}},
		{"scp", []string{"openssh-client", "openssh-clients"}},
		{"ssh-keygen", []string{"openssh-client", "openssh-clients"}},
		{"genisoimage", []string{"genisoimage", "EPEL", "xorriso"}},
		{"qemu-img", []string{"qemu-utils", "qemu-img"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := installHint(tc.name)
			for _, want := range tc.mustContain {
				if !strings.Contains(got, want) {
					t.Errorf("installHint(%q) = %q; want it to contain %q", tc.name, got, want)
				}
			}
		})
	}
}

// TestInstallHintBackendTools asserts backend-declared tool hints (virsh,
// setfacl) resolve via the backend-tool fallback in installHint. A fake
// libvirt-named backend supplies the tools so the test stays cross-platform.
func TestInstallHintBackendTools(t *testing.T) {
	backend.ResetForTesting()
	defer backend.ResetForTesting()

	backend.Register("libvirt", 10, func() backend.Backend {
		return &fakeToolBackend{
			name: "libvirt",
			tools: []backend.Tool{
				{Name: "virsh", UsedBy: "all VM/network operations", Hint: "install libvirt-clients (Debian/Ubuntu) or libvirt-client (Fedora/RHEL/Arch)"},
				{Name: "setfacl", UsedBy: "create", Hint: "install the acl package"},
			},
		}
	})

	if got := installHint("setfacl"); !strings.Contains(got, "acl") {
		t.Errorf("installHint(setfacl) = %q; want it to contain %q", got, "acl")
	}
	if got := installHint("virsh"); !strings.Contains(got, "libvirt-client") {
		t.Errorf("installHint(virsh) = %q; want it to contain %q", got, "libvirt-client")
	}
}

// TestCheckAllDependenciesBackendMerge verifies the selected backend's tools are
// treated as required while other registered backends' tools are optional.
func TestCheckAllDependenciesBackendMerge(t *testing.T) {
	backend.ResetForTesting()
	defer backend.ResetForTesting()

	backend.Register("selected", 10, func() backend.Backend {
		return &fakeToolBackend{
			name:  "selected",
			tools: []backend.Tool{{Name: "abox-fake-selected-tool", UsedBy: "selected backend"}},
		}
	})
	backend.Register("other", 20, func() backend.Backend {
		return &fakeToolBackend{
			name:  "other",
			tools: []backend.Tool{{Name: "abox-fake-other-tool", UsedBy: "other backend"}},
		}
	})

	t.Setenv(factory.EnvBackend, "selected")

	var buf bytes.Buffer
	missing := checkAllDependencies(&buf, false)

	// The selected backend's (non-existent) tool is required -> collected.
	if !containsStr(missing, "abox-fake-selected-tool") {
		t.Errorf("selected backend tool not treated as required; missing = %v", missing)
	}
	// The other backend's tool is optional -> not collected.
	if containsStr(missing, "abox-fake-other-tool") {
		t.Errorf("other backend tool must be optional; missing = %v", missing)
	}

	out := buf.String()
	if !strings.Contains(out, "abox-fake-selected-tool missing") {
		t.Errorf("expected selected tool reported as required missing; output:\n%s", out)
	}
	if !strings.Contains(out, "abox-fake-other-tool missing (optional") {
		t.Errorf("expected other tool reported as optional; output:\n%s", out)
	}
}

// TestLibvirtAccessGatedByBackend verifies the libvirt-only host checks run only
// when libvirt is the selected backend and are skipped for another backend, so a
// vmware user is not wrongly failed for missing libvirt-group membership.
func TestLibvirtAccessGatedByBackend(t *testing.T) {
	backend.ResetForTesting()
	defer backend.ResetForTesting()

	backend.Register(libvirtBackendName, 10, func() backend.Backend {
		return &fakeToolBackend{name: libvirtBackendName}
	})
	backend.Register("vmware", 20, func() backend.Backend {
		return &fakeToolBackend{name: "vmware"}
	})

	t.Setenv(factory.EnvBackend, libvirtBackendName)
	if !libvirtAccessRelevant() {
		t.Error("libvirt selected: libvirt access checks must be relevant")
	}

	t.Setenv(factory.EnvBackend, "vmware")
	if libvirtAccessRelevant() {
		t.Error("vmware selected: libvirt access checks must be skipped")
	}
}

// TestDependenciesForGOOS verifies Linux-only tools are dropped on non-Linux
// hosts (macOS has no fusermount/iptables/pkexec and uses xorriso rather than
// genisoimage) while Linux keeps the full table. sshfs is cross-platform (macOS
// has it via macFUSE) but is optional on darwin — asserted separately below.
func TestDependenciesForGOOS(t *testing.T) {
	linuxOnlyTools := []string{"iptables", "fusermount", "pkexec", "genisoimage"}
	crossPlatform := []string{"qemu-img", "ssh", "scp", "ssh-keygen", "xorriso", "sudo", "tcpdump", "sshfs"}

	names := func(deps []dependency) []string {
		out := make([]string, 0, len(deps))
		for _, d := range deps {
			out = append(out, d.name)
		}
		return out
	}

	linux := names(dependenciesForGOOS("linux"))
	if len(linux) != len(dependencies) {
		t.Errorf("linux should keep the full dependency table: got %d, want %d", len(linux), len(dependencies))
	}
	for _, tool := range linuxOnlyTools {
		if !slices.Contains(linux, tool) {
			t.Errorf("linux dependencies missing expected tool %q", tool)
		}
	}

	darwin := names(dependenciesForGOOS("darwin"))
	for _, tool := range linuxOnlyTools {
		if slices.Contains(darwin, tool) {
			t.Errorf("darwin dependencies must not include Linux-only tool %q", tool)
		}
	}
	for _, tool := range crossPlatform {
		if !slices.Contains(darwin, tool) {
			t.Errorf("darwin dependencies missing cross-platform tool %q", tool)
		}
	}

	// sshfs is required on Linux (mount needs it) but optional on macOS, where
	// mounting is a convenience feature layered on macFUSE.
	requiredOf := func(deps []dependency, name string) (required, found bool) {
		for _, d := range deps {
			if d.name == name {
				return d.required, true
			}
		}
		return false, false
	}
	if req, ok := requiredOf(dependenciesForGOOS("linux"), "sshfs"); !ok || !req {
		t.Errorf("sshfs on linux: required=%v found=%v; want required", req, ok)
	}
	if req, ok := requiredOf(dependenciesForGOOS("darwin"), "sshfs"); !ok || req {
		t.Errorf("sshfs on darwin: required=%v found=%v; want optional", req, ok)
	}
}

func containsStr(ss []string, want string) bool {
	return slices.Contains(ss, want)
}

// TestInstallHintUnknown falls back to a generic message for unknown tools.
func TestInstallHintUnknown(t *testing.T) {
	if got := installHint("totally-unknown-tool"); got != "check your package manager" {
		t.Errorf("installHint(unknown) = %q; want generic fallback", got)
	}
}
