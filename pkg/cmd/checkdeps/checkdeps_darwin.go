//go:build darwin

package checkdeps

import (
	"io"

	"github.com/sandialabs/abox/internal/vmnethelper"
)

var dependencies = []dependency{
	{name: "vfkit", required: true, usedBy: "all VM operations"},
	// vmnet-helper installs to libexec (off PATH), so it carries a custom
	// check that resolves the binary the same way the backend does at runtime.
	{name: "vmnet-helper", required: true, usedBy: "per-VM networking", check: vmnetHelperInstalled},
	{name: "qemu-img", required: true, usedBy: "base image conversion (qcow2 → raw)"},
	{name: "ssh", required: true, usedBy: "ssh, provision, scp"},
	{name: "scp", required: true, usedBy: "scp command"},
	{name: "sshfs", required: true, usedBy: "mount command (requires macFUSE)"},
	{name: "ssh-keygen", required: true, usedBy: "create (key generation)"},
	{name: "xorriso", required: true, usedBy: "create (cloud-init ISO)"},
	{name: "sudo", required: true, usedBy: "privilege helper escalation"},
	{name: "pfctl", required: true, usedBy: "packet filter rules (ships with macOS)"},
	{name: "tcpdump", required: false, usedBy: "tap (packet capture)"},
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

// No group membership to verify on macOS.
func platformQuickCheck() bool { return true }

func installHint(name string) string {
	hints := map[string]string{
		"vfkit":        "brew install vfkit",
		"qemu-img":     "brew install qemu",
		"ssh":          "preinstalled on macOS",
		"scp":          "preinstalled on macOS",
		"sshfs":        "brew install --cask macfuse && brew install gromgit/fuse/sshfs-mac",
		"ssh-keygen":   "preinstalled on macOS",
		"xorriso":      "brew install xorriso",
		"sudo":         "preinstalled on macOS",
		"pfctl":        "ships with macOS; ensure /sbin is on PATH",
		"tcpdump":      "preinstalled on macOS",
		"vmnet-helper": "brew tap nirs/vmnet-helper && brew install vmnet-helper",
	}
	if hint, ok := hints[name]; ok {
		return hint
	}
	return "check your package manager (brew)"
}
