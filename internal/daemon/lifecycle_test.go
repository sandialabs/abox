package daemon

import "testing"

// TestSameExe covers the platform-agnostic executable-identity helper used by the
// Linux isAboxProcess path (and, via sameExeDarwin, the darwin one): an exact
// match is ours, a kernel " (deleted)" suffix (in-place upgrade) is tolerated,
// and an unrelated path is not.
func TestSameExe(t *testing.T) {
	const self = "/home/user/.local/bin/abox"
	tests := []struct {
		name     string
		observed string
		want     bool
	}{
		{"exact match", self, true},
		{"deleted suffix tolerated", self + " (deleted)", true},
		{"different binary", "/usr/bin/other", false},
		{"empty", "", false},
		{"prefix but not equal", "/home/user/.local/bin/abo", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameExe(tt.observed, self); got != tt.want {
				t.Errorf("sameExe(%q, %q) = %v, want %v", tt.observed, self, got, tt.want)
			}
		})
	}
}
