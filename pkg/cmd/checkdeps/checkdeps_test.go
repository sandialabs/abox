package checkdeps

import (
	"strings"
	"testing"
)

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
		{"virsh", []string{"libvirt-clients", "libvirt-client"}},
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

// TestInstallHintUnknown falls back to a generic message for unknown tools.
func TestInstallHintUnknown(t *testing.T) {
	if got := installHint("totally-unknown-tool"); got != "check your package manager" {
		t.Errorf("installHint(unknown) = %q; want generic fallback", got)
	}
}
