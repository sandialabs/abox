//go:build darwin

package checkdeps

import (
	"strings"
	"testing"
)

// TestInstallHintDarwin verifies the install hints name the correct Homebrew
// formula (or note that the tool ships with macOS) for the macOS dependency
// table.
func TestInstallHintDarwin(t *testing.T) {
	cases := []struct {
		name        string
		mustContain []string
	}{
		{"vfkit", []string{"brew install vfkit"}},
		{"vmnet-helper", []string{"brew", "vmnet-helper"}},
		{"qemu-img", []string{"brew install qemu"}},
		{"ssh", []string{"macOS"}},
		{"pfctl", []string{"macOS"}},
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

// TestInstallHintUnknownDarwin falls back to a generic message for unknown tools.
func TestInstallHintUnknownDarwin(t *testing.T) {
	if got := installHint("totally-unknown-tool"); got != "check your package manager" {
		t.Errorf("installHint(unknown) = %q; want generic fallback", got)
	}
}
