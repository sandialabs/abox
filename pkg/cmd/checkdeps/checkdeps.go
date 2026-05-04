package checkdeps

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/internal/version"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

type dependency struct {
	name     string
	required bool
	usedBy   string
}

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

// Options holds the options for the check-deps command.
type Options struct {
	Factory *factory.Factory
	Quiet   bool
}

// NewCmdCheckDeps creates a new check-deps command.
func NewCmdCheckDeps(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "check-deps",
		Short: "Check for required external dependencies",
		Long: `Check that all required external dependencies are installed and accessible.

This command verifies that tools like virsh, qemu-img, ssh, and others
are available in your PATH.`,
		Example: `  abox check-deps                          # Check all dependencies
  abox check-deps -q                       # Quiet mode (exit code only)`,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return runCheckDeps(opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.Quiet, "quiet", "q", false, "Suppress output, exit code only")

	return cmd
}

func runCheckDeps(opts *Options) error {
	w := opts.Factory.IO.Out

	if !opts.Quiet {
		fmt.Fprintln(w, "Checking dependencies...")
	}

	missingRequired := checkAllDependencies(w, opts.Quiet)

	if len(missingRequired) > 0 {
		if opts.Quiet {
			return &cmdutil.ErrSilent{}
		}
		fmt.Fprintf(w, "Error: missing required dependencies: %v\n", missingRequired)
		fmt.Fprintln(w, "\nInstall hints:")
		for _, name := range missingRequired {
			fmt.Fprintf(w, "  %s: %s\n", name, installHint(name))
		}
		return fmt.Errorf("missing required dependencies: %v", missingRequired)
	}

	if err := validateToolPairs(w, opts.Quiet); err != nil {
		return err
	}

	if err := validateLibvirtAccess(w, opts.Quiet); err != nil {
		return err
	}

	if !opts.Quiet {
		fmt.Fprintln(w, "All required dependencies are installed.")
	}

	return nil
}

func checkAllDependencies(w io.Writer, quiet bool) []string {
	var missingRequired []string
	for _, dep := range dependencies {
		found := checkExecutable(dep.name) == nil

		if !quiet {
			status := "ok"
			if !found {
				if dep.required {
					status = "missing"
				} else {
					status = fmt.Sprintf("missing (optional, needed for '%s')", dep.usedBy)
				}
			}
			fmt.Fprintf(w, "  %-12s %s\n", dep.name, status)
		}

		if !found && dep.required {
			missingRequired = append(missingRequired, dep.name)
		}
	}
	if !quiet {
		fmt.Fprintln(w)
	}
	return missingRequired
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

// checkExecutable verifies an executable exists, with fallback to common system paths.
// This handles cases where /sbin is not in the user's PATH.
func checkExecutable(name string) error {
	if _, err := exec.LookPath(name); err == nil {
		return nil
	}
	// Fallback to common system paths not always in user PATH
	for _, dir := range []string{"/sbin", "/usr/sbin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return nil
		}
	}
	return fmt.Errorf("%s: executable file not found", name)
}

func installHint(name string) string {
	const hintOpenSSHClient = "install openssh-client"
	hints := map[string]string{
		"virsh":       "install libvirt-clients (Debian/Ubuntu) or libvirt (Fedora/Arch)",
		"qemu-img":    "install qemu-utils (Debian/Ubuntu) or qemu-img (Fedora/Arch)",
		"ssh":         hintOpenSSHClient,
		"scp":         hintOpenSSHClient,
		"sshfs":       "install sshfs",
		"ssh-keygen":  hintOpenSSHClient,
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

// RunQuiet runs dependency checks without output, returns true if all pass.
func RunQuiet() bool {
	// Check required dependencies
	for _, dep := range dependencies {
		if dep.required {
			if err := checkExecutable(dep.name); err != nil {
				return false
			}
		}
	}

	// Check that at least one privilege escalation method is available
	pkexecErr := checkExecutable("pkexec")
	sudoErr := checkExecutable("sudo")
	if pkexecErr != nil && sudoErr != nil {
		return false
	}

	// Check that at least one ISO creation tool is available
	genisoimageErr := checkExecutable("genisoimage")
	xorrisoErr := checkExecutable("xorriso")
	if genisoimageErr != nil && xorrisoErr != nil {
		return false
	}

	// Check libvirt group membership
	if !privilege.InLibvirtGroup() {
		return false
	}

	return true
}

// getMarkerPath returns the path to the version marker file.
func getMarkerPath() string {
	paths, err := config.GetPaths("")
	if err != nil {
		return ""
	}
	return filepath.Join(paths.Base, ".version")
}

// ShouldAutoCheck returns true if auto-check should run.
// This happens when the marker file is missing or contains a different version.
func ShouldAutoCheck() bool {
	path := getMarkerPath()
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return true // File missing or unreadable, should check
	}
	return strings.TrimSpace(string(data)) != version.Version
}

// MarkCheckDone writes current version to marker file.
func MarkCheckDone() {
	path := getMarkerPath()
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(version.Version), 0o600)
}
