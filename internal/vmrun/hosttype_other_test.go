//go:build !darwin

package vmrun

import "testing"

// TestHostTypeDefault_Other pins the non-macOS host driver to Workstation ("ws"),
// used on Linux and Windows.
func TestHostTypeDefault_Other(t *testing.T) {
	if got := hostTypeDefault(); got != "ws" {
		t.Errorf("hostTypeDefault() = %q, want ws", got)
	}
}
