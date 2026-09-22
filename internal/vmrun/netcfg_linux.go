//go:build linux

package vmrun

// activeProvisioner returns the Linux host-only provisioner: it edits
// /etc/vmware/networking (the answer-file engine in netcfg_answerfile.go) and
// applies the change with `vmware-networks --stop` then `--start`.
//
// TODO(real-host): confirm stop→start alone re-reads the edited
// /etc/vmware/networking on the target Workstation version. If a live host shows
// stop→start does not pick up the file, add a
// `vmware-networks --migrate-network-settings <file>` step to applyArgs.
func activeProvisioner() (hostOnlyProvisioner, error) {
	return fileProvisioner{
		networkingPath: networkingPathOr("/etc/vmware/networking"),
		toolCandidates: hostOnlyToolCandidates(),
		applyArgs:      [][]string{{applyStop}, {applyStart}},
	}, nil
}

// toolVMwareNetworks is the Linux VMware Workstation host-only network CLI.
const toolVMwareNetworks = "vmware-networks"

// hostOnlyToolCandidates returns the Linux host-only network tools to try, in
// order. Single source of truth for the provisioner and the checkdeps preflight
// (ResolveHostOnlyTool).
func hostOnlyToolCandidates() []string {
	return []string{toolVMwareNetworks, "vnetlib"}
}
