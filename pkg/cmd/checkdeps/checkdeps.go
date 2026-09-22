package checkdeps

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/backend"
	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/privilege"
	"github.com/sandialabs/abox/internal/version"
	"github.com/sandialabs/abox/internal/vmrun"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

type dependency struct {
	name     string
	required bool
	usedBy   string
	hint     string // install instructions; empty falls back to a generic message
	// linuxOnly marks tools that only exist / are only used on Linux, so they are
	// skipped on other platforms. Examples: unmount uses fusermount on Linux
	// (darwin uses umount/diskutil), iptables does DNS redirect on Linux (darwin
	// uses pf), pkexec is polkit, and genisoimage is a Debian/EPEL tool (darwin
	// uses xorriso). Checking them elsewhere would wrongly report them missing.
	linuxOnly bool
	// optionalOnDarwin downgrades a dependency from required to optional on macOS.
	// Used for sshfs: the mount command works on macOS via a FUSE install (we
	// recommend the kext-less fuse-t), but it is a convenience feature rather than
	// something core VM operations need.
	optionalOnDarwin bool
}

// hintOpenSSH is shared by the OpenSSH client tools (ssh, scp, ssh-keygen).
const hintOpenSSH = "install openssh-client (Debian/Ubuntu) or openssh-clients (Fedora/RHEL)"

// External command names, referenced from the dependency table and the
// validation logic. Named constants keep these in sync — a mismatch between
// any two would otherwise be a silent bug.
const (
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
		// lives in EPEL rather than the base repos. On macOS sshfs needs a FUSE
		// install — we recommend the kext-less fuse-t (resolveSSHFS in
		// checkdeps_darwin.go emits the install commands) — where it is optional
		// since mounting is a convenience feature.
		hint:             "install sshfs (Debian/Ubuntu) or fuse-sshfs (Fedora; needs EPEL on RHEL/AlmaLinux/Rocky)",
		optionalOnDarwin: true,
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
		// so prefer it when EPEL is unavailable. On macOS only xorriso is used.
		hint:      "install genisoimage (Debian/Ubuntu/Fedora; EPEL on RHEL) or install xorriso instead",
		linuxOnly: true,
	},
	{
		name:     depXorriso,
		required: false,
		usedBy:   "create (cloud-init ISO, required if genisoimage not installed)",
		hint:     "install xorriso",
	},
	{
		name:      depPkexec,
		required:  false,
		usedBy:    "iptables rules (preferred)",
		hint:      "install polkit (usually pre-installed)",
		linuxOnly: true,
	},
	{
		name:     depSudo,
		required: false,
		usedBy:   "iptables rules (fallback)",
		hint:     "install sudo",
	},
	{
		name:      depIptables,
		required:  true,
		usedBy:    "DNS redirect",
		hint:      "install iptables",
		linuxOnly: true,
	},
	{
		name:      depFusermount,
		required:  true,
		usedBy:    "unmount command",
		hint:      "install fuse or fuse3",
		linuxOnly: true,
	},
	{
		name:     depTCPdump,
		required: false,
		usedBy:   "tap (packet capture)",
	},
}

// applicableDependencies returns the common dependencies that apply to the
// current platform: linuxOnly tools are dropped on non-Linux hosts (macOS has no
// fusermount/iptables/pkexec and uses xorriso rather than genisoimage). sshfs
// still applies on macOS (via a FUSE install; fuse-t recommended) but is
// downgraded to optional there.
// Keeping the full table intact means installHint still resolves every tool.
func applicableDependencies() []dependency {
	return dependenciesForGOOS(runtime.GOOS)
}

// dependenciesForGOOS filters the dependency table for a given GOOS. Split out
// from applicableDependencies so it can be unit-tested on any host platform.
func dependenciesForGOOS(goos string) []dependency {
	if goos == "linux" {
		return dependencies
	}
	out := make([]dependency, 0, len(dependencies))
	for _, dep := range dependencies {
		if dep.linuxOnly {
			continue
		}
		if goos == "darwin" && dep.optionalOnDarwin {
			dep.required = false
		}
		out = append(out, dep)
	}
	return out
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

	// The libvirt group / qemu-image ACL checks only apply when libvirt is the
	// selected backend; other backends (e.g. vmware) never touch the libvirt
	// group, so running them would wrongly fail check-deps for those users.
	if libvirtAccessRelevant() {
		if err := validateLibvirtAccess(w, opts.Quiet); err != nil {
			return err
		}
	}

	// VMware readiness checks that go beyond tool presence (host-only network CLI
	// resolvable; vmrun actually working) — only when vmware is selected.
	if vmwarePreflightRelevant() {
		if err := validateVMwarePreflight(w, opts.Quiet); err != nil {
			return err
		}
	}

	if !opts.Quiet {
		warnFirewalld(w)
		fmt.Fprintln(w, "All required dependencies are installed.")
	}

	return nil
}

// vmwareBackendName is the identifier of the vmware backend, kept as a string
// literal (not imported) so check-deps compiles on every platform.
const vmwareBackendName = "vmware"

// vmwarePreflightRelevant reports whether the VMware-specific readiness checks
// apply — i.e. vmware is the selected backend.
func vmwarePreflightRelevant() bool {
	return selectedBackendName() == vmwareBackendName
}

// validateVMwarePreflight runs VMware readiness checks beyond tool presence: the
// host-only network CLI must be resolvable (on macOS Fusion it lives inside the
// .app, off PATH, so a plain PATH check would misreport it), and vmrun must
// actually work (`vmrun list`), not merely exist — catching a present-but-broken
// or wrong-host-type install before it fails mid-create.
func validateVMwarePreflight(w io.Writer, quiet bool) error {
	tool, err := vmrun.ResolveHostOnlyTool()
	if err != nil {
		fmt.Fprintf(w, "Error: %v\n", err)
		return err
	}
	if !quiet {
		fmt.Fprintf(w, "  vmware network tool: %s\n", tool)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := vmrun.CheckVMRun(ctx); err != nil {
		fmt.Fprintf(w, "Error: vmrun is present but not working (%v)\n", err)
		return fmt.Errorf("vmrun not functional: %w", err)
	}
	if !quiet {
		fmt.Fprintln(w, "  vmrun: working")
	}
	return nil
}

// selectedBackendName resolves the backend check-deps should treat as primary:
// an explicit, registered ABOX_BACKEND selection, else the registry default.
func selectedBackendName() string {
	name := os.Getenv(factory.EnvBackend)
	if name == "" || !backend.IsRegistered(name) {
		name = backend.DefaultName()
	}
	return name
}

// libvirtBackendName is the identifier of the libvirt backend. It is kept as a
// string literal here (not imported from internal/backend/libvirt) because that
// package is linux-only and check-deps must compile on every platform.
const libvirtBackendName = "libvirt"

// libvirtAccessRelevant reports whether the libvirt-specific host checks (group
// membership, qemu image ACLs) apply to the run — i.e. libvirt is the selected
// backend. Skipping them for other backends is what keeps check-deps honest for
// a vmware (or future) backend that never uses the libvirt group.
func libvirtAccessRelevant() bool {
	return selectedBackendName() == libvirtBackendName
}

// resolveTool reports whether a tool is available, consulting the
// platform-specific resolver first (for tools that install off PATH or need
// special handling, e.g. vmnet-helper on macOS) and falling back to the generic
// PATH check otherwise — keeping non-darwin behavior byte-identical. It also
// returns any platform note (install/upgrade guidance).
//
// Both the interactive check (checkOne) and the quiet startup check (RunQuiet)
// route through this so the two paths can never diverge on where a tool lives.
// Note: platformResolveTool may return ok=true with an empty path to mean
// "handled, but not installed" (vmnet-helper/sshfs), so an empty path counts as
// NOT found.
func resolveTool(name string) (found bool, note string) {
	if path, ok, n := platformResolveTool(name); ok {
		return path != "", n
	}
	return checkExecutable(name) == nil, ""
}

// toolFound reports tool availability without the note, for the quiet path.
func toolFound(name string) bool {
	found, _ := resolveTool(name)
	return found
}

// checkOne probes a single tool, prints its status line (unless quiet), and
// returns true when a required tool is missing (so callers can collect it).
// Shared by the common dependency loop and the per-backend tool loop so both
// use identical formatting and missing-collection logic.
func checkOne(w io.Writer, quiet bool, name string, required bool, usedBy string) (missing bool) {
	found, note := resolveTool(name)

	if !quiet {
		status := "ok"
		if !found {
			if required {
				status = "missing"
			} else {
				status = fmt.Sprintf("missing (optional, needed for '%s')", usedBy)
			}
		}
		fmt.Fprintf(w, "  %-12s %s\n", name, status)
		if note != "" {
			fmt.Fprintf(w, "               %s\n", note)
		}
	}

	return !found && required
}

func checkAllDependencies(w io.Writer, quiet bool) []string {
	var missingRequired []string
	for _, dep := range applicableDependencies() {
		if checkOne(w, quiet, dep.name, dep.required, dep.usedBy) {
			missingRequired = append(missingRequired, dep.name)
		}
	}

	// Merge in each backend's uniquely-required tools: the selected backend's
	// tools are required, other registered backends' tools are optional. Sort
	// the backend names (selected first, then alphabetical) for deterministic
	// output.
	byBackend := backend.RequiredToolsByBackend()
	selected := selectedBackendName()
	for _, name := range sortedBackendNames(byBackend, selected) {
		required := name == selected
		for _, tool := range byBackend[name] {
			if checkOne(w, quiet, tool.Name, required, tool.UsedBy) {
				missingRequired = append(missingRequired, tool.Name)
			}
		}
	}

	if !quiet {
		fmt.Fprintln(w)
	}
	return missingRequired
}

// sortedBackendNames returns the keys of byBackend with selected first (when
// present) followed by the rest alphabetically, for deterministic output.
func sortedBackendNames(byBackend map[string][]backend.Tool, selected string) []string {
	names := make([]string, 0, len(byBackend))
	for name := range byBackend {
		if name != selected {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if _, ok := byBackend[selected]; ok {
		names = append([]string{selected}, names...)
	}
	return names
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
	for _, dep := range dependencies {
		if dep.name == name && dep.hint != "" {
			return dep.hint
		}
	}
	// Fall back to backend-declared tools (virsh/setfacl/vmrun) so their hints
	// resolve even though they no longer live in the common dependency table.
	for _, tools := range backend.RequiredToolsByBackend() {
		for _, tool := range tools {
			if tool.Name == name && tool.Hint != "" {
				return tool.Hint
			}
		}
	}
	return "check your package manager"
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

// RunQuiet runs dependency checks without output, returns true if all pass.
//
// It routes every tool probe through toolFound (not raw checkExecutable) so the
// quiet startup check resolves off-PATH, platform-specific tools identically to
// the interactive `abox check-deps` — otherwise, e.g., a correctly-installed
// macOS vmnet-helper (in a Homebrew libexec dir, off PATH) would be reported
// missing here while check-deps reports it OK.
func RunQuiet() bool {
	// Check required dependencies
	for _, dep := range applicableDependencies() {
		if dep.required {
			if !toolFound(dep.name) {
				return false
			}
		}
	}

	// Check that at least one privilege escalation method is available
	if !toolFound(depPkexec) && !toolFound(depSudo) {
		return false
	}

	// Check that at least one ISO creation tool is available
	if !toolFound(depGenisoimage) && !toolFound(depXorriso) {
		return false
	}

	// Check the selected backend's uniquely-required tools (not other backends').
	byBackend := backend.RequiredToolsByBackend()
	for _, tool := range byBackend[selectedBackendName()] {
		if !toolFound(tool.Name) {
			return false
		}
	}

	// Check libvirt group membership — only when libvirt is the selected backend.
	// Other backends (vmware, vfkit on macOS) never touch the libvirt group, and
	// on non-Linux hosts there is no libvirt group at all, so an unconditional
	// check here would make the startup auto-check always fail on those systems.
	if libvirtAccessRelevant() && !privilege.InLibvirtGroup() {
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
