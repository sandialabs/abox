//go:build !linux && !darwin && !windows

package vmrun

import (
	"fmt"
	"runtime"
)

// activeProvisioner fails loudly on unsupported platforms so a stray VMware
// network create errors clearly rather than silently issuing wrong-shaped
// commands. VMware host-only networking has a mechanism only on linux, darwin
// (Fusion), and windows.
func activeProvisioner() (hostOnlyProvisioner, error) {
	return nil, fmt.Errorf("VMware host-only networking is not supported on %s "+
		"(supported: linux, darwin/Fusion, windows)", runtime.GOOS)
}

// hostOnlyToolCandidates returns no candidates on unsupported platforms;
// ResolveHostOnlyTool then reports that no VMware network tool was found.
func hostOnlyToolCandidates() []string { return nil }
