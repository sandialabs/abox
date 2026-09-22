//go:build darwin

package vmrun

import "testing"

// TestHostTypeDefault_Darwin pins the macOS host driver to Fusion. A regression
// (e.g. reverting to a hardcoded "ws") breaks every vmrun call on Fusion.
func TestHostTypeDefault_Darwin(t *testing.T) {
	if got := hostTypeDefault(); got != "fusion" {
		t.Errorf("hostTypeDefault() = %q, want fusion", got)
	}
}
