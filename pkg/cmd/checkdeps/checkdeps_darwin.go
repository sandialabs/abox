//go:build darwin

package checkdeps

import (
	"io"

	"github.com/sandialabs/abox/internal/vmnethelper"
)

// hintPreinstalledMacOS is shared by the tools that ship with macOS.
const hintPreinstalledMacOS = "preinstalled on macOS"

// External command names, referenced from the dependency table and validation
// logic. Named constants keep these in sync — a mismatch between any two would
// otherwise be a silent bug.
const (
	depVfkit       = "vfkit"
	depVmnetHelper = "vmnet-helper"
	depQemuImg     = "qemu-img"
	depSSH         = "ssh"
	depSCP         = "scp"
	depSSHKeygen   = "ssh-keygen"
	depXorriso     = "xorriso"
	depSudo        = "sudo"
	depPfctl       = "pfctl"
	depTCPdump     = "tcpdump"
)

var dependencies = []dependency{
	{name: depVfkit, required: true, usedBy: "all VM operations", hint: "brew install vfkit"},
	// vmnet-helper installs to libexec (off PATH), so it carries a custom
	// check that resolves the binary the same way the backend does at runtime.
	{
		name:     depVmnetHelper,
		required: true,
		usedBy:   "per-VM networking",
		hint:     "brew tap nirs/vmnet-helper && brew install vmnet-helper",
		check:    vmnetHelperInstalled,
	},
	{name: depQemuImg, required: true, usedBy: "base image conversion (qcow2 → raw)", hint: "brew install qemu"},
	{name: depSSH, required: true, usedBy: "ssh, provision, scp", hint: hintPreinstalledMacOS},
	{name: depSCP, required: true, usedBy: "scp command", hint: hintPreinstalledMacOS},
	{name: depSSHKeygen, required: true, usedBy: "create (key generation)", hint: hintPreinstalledMacOS},
	{name: depXorriso, required: true, usedBy: "create (cloud-init ISO)", hint: "brew install xorriso"},
	{name: depSudo, required: true, usedBy: "privilege helper escalation", hint: hintPreinstalledMacOS},
	{name: depPfctl, required: true, usedBy: "packet filter rules (ships with macOS)", hint: "ships with macOS; ensure /sbin is on PATH"},
	{name: depTCPdump, required: false, usedBy: "tap (packet capture)", hint: hintPreinstalledMacOS},
}

// vmnetHelperInstalled reports whether the vmnet-helper binary can be resolved.
func vmnetHelperInstalled() error {
	_, err := vmnethelper.ResolveBinaryPath()
	return err
}

// macOS has no either-or tool pairs (only sudo, only xorriso), so there is
// nothing extra to validate here.
func validateToolPairs(_ io.Writer, _ bool) error { return nil }

// No libvirt on macOS; the backend uses vfkit + vmnet-helper.
func validateLibvirtAccess(_ io.Writer, _ bool) error { return nil }

// No firewalld on macOS; pf is configured separately. No-op for parity with
// the Linux check called from runCheckDeps.
func warnFirewalld(_ io.Writer) {}

// No group membership to verify on macOS.
func platformQuickCheck() bool { return true }
