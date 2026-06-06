//go:build linux

package checkdeps

import (
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/pkg/cmdutil"
)

// hintOpenSSH is shared by the OpenSSH client tools (ssh, scp, ssh-keygen).
const hintOpenSSH = "install openssh-client (Debian/Ubuntu) or openssh-clients (Fedora/RHEL)"

// External command names, referenced from the dependency table and the
// validation logic. Named constants keep these in sync — a mismatch between
// any two would otherwise be a silent bug.
const (
	depVirsh       = "virsh"
	depQemuImg     = "qemu-img"
	depSSH         = "ssh"
	depSCP         = "scp"
	depSSHFS       = "sshfs"
	depSSHKeygen   = "ssh-keygen"
	depGenisoimage = "genisoimage"
	depXorriso     = "xorriso"
	depPkexec      = "pkexec"
	depSudo        = "sudo"
	depIptables    = "iptables"
	depFusermount  = "fusermount"
	depTCPdump     = "tcpdump"
)

var dependencies = []dependency{
	{
		name:     depVirsh,
		required: true,
		usedBy:   "all VM/network operations",
		hint:     "install libvirt-clients (Debian/Ubuntu) or libvirt-client (Fedora/RHEL/Arch)",
	},
	{
		name:     depQemuImg,
		required: true,
		usedBy:   "create, base pull",
		hint:     "install qemu-utils (Debian/Ubuntu) or qemu-img (Fedora/RHEL/Arch)",
	},
	{
		name:     depSSH,
		required: true,
		usedBy:   "ssh, provision, scp",
		hint:     hintOpenSSH,
	},
	{
		name:     depSCP,
		required: true,
		usedBy:   "scp command",
		hint:     hintOpenSSH,
	},
	{
		name:     depSSHFS,
		required: true,
		usedBy:   "mount command",
		// On Fedora/RHEL the package is fuse-sshfs, and on RHEL/AlmaLinux/Rocky it
		// lives in EPEL rather than the base repos.
		hint: "install sshfs (Debian/Ubuntu) or fuse-sshfs (Fedora; needs EPEL on RHEL/AlmaLinux/Rocky)",
	},
	{
		name:     depSSHKeygen,
		required: true,
		usedBy:   "create (key generation)",
		hint:     hintOpenSSH,
	},
	{
		name:     depGenisoimage,
		required: false,
		usedBy:   "create (cloud-init ISO, required if xorriso not installed)",
		// genisoimage is EPEL-only on RHEL; xorriso is in the base repos everywhere,
		// so prefer it when EPEL is unavailable.
		hint: "install genisoimage (Debian/Ubuntu/Fedora; EPEL on RHEL) or install xorriso instead",
	},
	{
		name:     depXorriso,
		required: false,
		usedBy:   "create (cloud-init ISO, required if genisoimage not installed)",
		hint:     "install xorriso",
	},
	{
		name:     depPkexec,
		required: false,
		usedBy:   "iptables rules (preferred)",
		hint:     "install polkit (usually pre-installed)",
	},
	{
		name:     depSudo,
		required: false,
		usedBy:   "iptables rules (fallback)",
		hint:     "install sudo",
	},
	{
		name:     depIptables,
		required: true,
		usedBy:   "DNS redirect",
		hint:     "install iptables",
	},
	{
		name:     depFusermount,
		required: true,
		usedBy:   "unmount command",
		hint:     "install fuse or fuse3",
	},
	{
		name:     depTCPdump,
		required: false,
		usedBy:   "tap (packet capture)",
	},
}

func validateToolPairs(w io.Writer, quiet bool) error {
	// Check that at least one privilege escalation method is available
	if checkExecutable(depPkexec) != nil && checkExecutable(depSudo) != nil {
		if quiet {
			return &cmdutil.ErrSilent{}
		}
		fmt.Fprintln(w, "Error: no privilege escalation tool available (need pkexec or sudo)")
		return errors.New("no privilege escalation tool available")
	}

	// Check that at least one ISO creation tool is available
	if checkExecutable(depGenisoimage) != nil && checkExecutable(depXorriso) != nil {
		if quiet {
			return &cmdutil.ErrSilent{}
		}
		fmt.Fprintln(w, "Error: no ISO creation tool available (need genisoimage or xorriso)")
		fmt.Fprintf(w, "  Install: %s  (or: %s)\n", installHint(depGenisoimage), installHint(depXorriso))
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
			fmt.Fprintln(w, "  qemu disk access group: member")
		} else {
			fmt.Fprintln(w, "  qemu disk access group: not a member")
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

// warnFirewalld prints a warning if firewalld is active, since it can
// interfere with the iptables NAT rules abox creates for DNS redirection.
func warnFirewalld(w io.Writer) {
	path, err := exec.LookPath("firewall-cmd")
	if err != nil {
		return
	}
	cmd := exec.Command(path, "--state")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return // not running
	}
	fmt.Fprintln(w, "  Warning: firewalld is active")
	fmt.Fprintln(w, "  abox uses iptables NAT rules that may conflict with firewalld.")
	fmt.Fprintln(w, "  See 'abox docs requirements' or docs/requirements.md for firewalld setup.")
	fmt.Fprintln(w)
}

func platformQuickCheck() bool {
	// At least one privilege-escalation tool must exist.
	if checkExecutable(depPkexec) != nil && checkExecutable(depSudo) != nil {
		return false
	}
	// At least one ISO creation tool must exist.
	if checkExecutable(depGenisoimage) != nil && checkExecutable(depXorriso) != nil {
		return false
	}
	return privilege.InLibvirtGroup()
}
