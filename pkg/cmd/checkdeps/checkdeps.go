package checkdeps

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/version"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

type dependency struct {
	name     string
	required bool
	usedBy   string
	// check, when non-nil, replaces the default PATH lookup. Used for tools
	// that are not on PATH (e.g. vmnet-helper, which installs to libexec).
	check func() error
}

// checkDep verifies a single dependency, using its custom check if present
// and otherwise falling back to a PATH lookup.
func checkDep(dep dependency) error {
	if dep.check != nil {
		return dep.check()
	}
	return checkExecutable(dep.name)
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

This command verifies that the external tools required by abox on this
platform are available in your PATH.`,
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
		found := checkDep(dep) == nil

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

// RunQuiet runs dependency checks without output, returns true if all pass.
func RunQuiet() bool {
	// Check required dependencies
	for _, dep := range dependencies {
		if dep.required {
			if err := checkDep(dep); err != nil {
				return false
			}
		}
	}
	return platformQuickCheck()
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
