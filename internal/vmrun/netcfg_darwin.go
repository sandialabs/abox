//go:build darwin

package vmrun

import (
	"os"
	"path/filepath"
)

// activeProvisioner returns the macOS/Fusion host-only provisioner: it edits the
// Fusion networking answer-file (the engine in netcfg_answerfile.go) and applies
// with the Fusion.app `vmnet-cli --configure` / `--stop` / `--start`.
func activeProvisioner() (hostOnlyProvisioner, error) {
	return fileProvisioner{
		networkingPath: networkingPathOr("/Library/Preferences/VMware Fusion/networking"),
		toolCandidates: hostOnlyToolCandidates(),
		applyArgs:      [][]string{{"--configure"}, {applyStop}, {applyStart}},
	}, nil
}

// hostOnlyToolCandidates returns the Fusion host-only network tools to try, in
// order (the Fusion.app helper first, then a bare name on PATH). Single source of
// truth for the provisioner and the checkdeps preflight (ResolveHostOnlyTool).
func hostOnlyToolCandidates() []string {
	return []string{filepath.Join(fusionLibraryDir(), "vmnet-cli"), "vmnet-cli"}
}

// fusionLibraryDir resolves the Fusion.app helper directory, honoring a
// VMWARE_FUSION_APP override for non-default install locations.
func fusionLibraryDir() string {
	app := os.Getenv("VMWARE_FUSION_APP")
	if app == "" {
		app = "/Applications/VMware Fusion.app"
	}
	return filepath.Join(app, "Contents", "Library")
}
