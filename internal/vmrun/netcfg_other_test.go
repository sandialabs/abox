//go:build !linux && !darwin && !windows

package vmrun

import "testing"

// TestActiveProvisioner_Unsupported asserts the fail-loud fallback errors on a
// platform with no VMware host-only mechanism (replacing the old
// provisionerForGOOS("plan9") assertion). It is compiled by the freebsd step in
// cross-compile.sh; it executes only when the tests are actually run on such a
// platform.
func TestActiveProvisioner_Unsupported(t *testing.T) {
	if _, err := activeProvisioner(); err == nil {
		t.Error("activeProvisioner() = nil error on unsupported platform, want a not-supported error")
	}
	if got := hostOnlyToolCandidates(); got != nil {
		t.Errorf("hostOnlyToolCandidates() = %v, want nil on unsupported platform", got)
	}
}
