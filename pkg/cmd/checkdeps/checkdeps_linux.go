//go:build linux

package checkdeps

import (
	"errors"
	"fmt"
	"io"

	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

var dependencies = []dependency{
	{name: "virsh", required: true, usedBy: "all VM/network operations"},
	{name: "qemu-img", required: true, usedBy: "create, base pull"},
	{name: "ssh", required: true, usedBy: "ssh, provision, scp"},
	{name: "scp", required: true, usedBy: "scp command"},
	{name: "sshfs", required: true, usedBy: "mount command"},
	{name: "ssh-keygen", required: true, usedBy: "create (key generation)"},
	{name: "genisoimage", required: false, usedBy: "create (cloud-init ISO, required if xorriso not installed)"},
	{name: "xorriso", required: false, usedBy: "create (cloud-init ISO, required if genisoimage not installed)"},
	{name: "pkexec", required: false, usedBy: "iptables rules (preferred)"},
	{name: "sudo", required: false, usedBy: "iptables rules (fallback)"},
	{name: "iptables", required: true, usedBy: "DNS redirect"},
	{name: "fusermount", required: true, usedBy: "unmount command"},
	{name: "tcpdump", required: false, usedBy: "tap (packet capture)"},
}

func validateToolPairs(w io.Writer, quiet bool) error {
	// Check that at least one privilege escalation method is available
	if checkExecutable("pkexec") != nil && checkExecutable("sudo") != nil {
		if quiet {
			return &cmdutil.ErrSilent{}
		}
		fmt.Fprintln(w, "Error: no privilege escalation tool available (need pkexec or sudo)")
		return errors.New("no privilege escalation tool available")
	}

	// Check that at least one ISO creation tool is available
	if checkExecutable("genisoimage") != nil && checkExecutable("xorriso") != nil {
		if quiet {
			return &cmdutil.ErrSilent{}
		}
		fmt.Fprintln(w, "Error: no ISO creation tool available (need genisoimage or xorriso)")
		fmt.Fprintln(w, "  Install: apt install genisoimage  (or: apt install xorriso)")
		return errors.New("no ISO creation tool available")
	}
	return nil
}

func validateLibvirtAccess(w io.Writer, quiet bool) error {
	if !privilege.InLibvirtGroup() {
		if quiet {
			return &cmdutil.ErrSilent{}
		}
		fmt.Fprintln(w, "Error: user is not in the libvirt group")
		fmt.Fprintln(w, "  Fix: sudo usermod -aG libvirt $USER")
		fmt.Fprintln(w, "  Then log out and back in for the change to take effect.")
		return errors.New("user not in libvirt group")
	}

	if !quiet {
		fmt.Fprintln(w, "  libvirt group: member")
		if privilege.InLibvirtQemuGroup() {
			fmt.Fprintln(w, "  libvirt-qemu/kvm group: member")
		} else {
			fmt.Fprintln(w, "  libvirt-qemu/kvm group: not a member")
		}
		if err := privilege.CanAccessLibvirtImages(); err != nil {
			fmt.Fprintf(w, "  libvirt images access: %v\n", err)
		} else {
			fmt.Fprintln(w, "  libvirt images access: ok")
		}
		fmt.Fprintln(w)
	}
	return nil
}

func platformQuickCheck() bool {
	// At least one privilege-escalation tool must exist.
	if checkExecutable("pkexec") != nil && checkExecutable("sudo") != nil {
		return false
	}
	// At least one ISO creation tool must exist.
	if checkExecutable("genisoimage") != nil && checkExecutable("xorriso") != nil {
		return false
	}
	return privilege.InLibvirtGroup()
}

func installHint(name string) string {
	hints := map[string]string{
		"virsh":       "install libvirt-clients (Debian/Ubuntu) or libvirt (Fedora/Arch)",
		"qemu-img":    "install qemu-utils (Debian/Ubuntu) or qemu-img (Fedora/Arch)",
		"ssh":         "install openssh-client",
		"scp":         "install openssh-client",
		"sshfs":       "install sshfs",
		"ssh-keygen":  "install openssh-client",
		"genisoimage": "install genisoimage (Debian/Ubuntu) or cdrkit (Fedora/Arch)",
		"xorriso":     "install xorriso",
		"pkexec":      "install polkit (usually pre-installed)",
		"sudo":        "install sudo",
		"iptables":    "install iptables",
		"fusermount":  "install fuse or fuse3",
	}
	if hint, ok := hints[name]; ok {
		return hint
	}
	return "check your package manager"
}
