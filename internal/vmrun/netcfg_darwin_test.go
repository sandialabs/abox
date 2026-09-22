//go:build darwin

package vmrun

import (
	"path/filepath"
	"testing"
)

// TestHostOnlyToolCandidates_Darwin pins the Fusion tool order: the Fusion.app
// helper (absolute path) first, then a bare name on PATH.
func TestHostOnlyToolCandidates_Darwin(t *testing.T) {
	got := hostOnlyToolCandidates()
	if !filepath.IsAbs(got[0]) || filepath.Base(got[0]) != "vmnet-cli" {
		t.Errorf("darwin first candidate = %q, want an absolute .../vmnet-cli", got[0])
	}
}
