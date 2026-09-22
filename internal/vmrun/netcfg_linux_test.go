//go:build linux

package vmrun

import "testing"

// TestHostOnlyToolCandidates_Linux pins the Linux tool order used by both the
// provisioner and the checkdeps preflight.
func TestHostOnlyToolCandidates_Linux(t *testing.T) {
	if got := hostOnlyToolCandidates(); got[0] != "vmware-networks" {
		t.Errorf("linux first candidate = %q, want vmware-networks", got[0])
	}
}
