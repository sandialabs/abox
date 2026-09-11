package unmount

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/mountutil"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount"
	"github.com/sandialabs/abox/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// Options holds the options for the unmount command.
type Options struct {
	Factory *factory.Factory
	Force   bool
	All     bool
	Path    string // Target path or instance name (positional arg)
}

// NewCmdUnmount creates a new unmount command.
func NewCmdUnmount(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "unmount [flags] <local-mount-point|instance>",
		Short: "Unmount an abox SSHFS mount",
		Long: `Unmount a previously mounted SSHFS filesystem.

You can specify either a local mount point path or an instance name.
When specifying an instance name, all mounts for that instance are unmounted.`,
		Example: `  abox unmount ~/mnt/dev           # unmount specific path
  abox unmount dev                 # unmount all mounts for instance
  abox unmount -f ~/mnt/dev        # force unmount (lazy)
  abox unmount --all               # unmount all abox mounts`,
		Args: func(cmd *cobra.Command, args []string) error {
			if opts.All {
				if len(args) > 0 {
					return cmdutil.FlagErrorf("--all flag does not take arguments")
				}
				return nil
			}
			if len(args) != 1 {
				return cmdutil.FlagErrorf("requires exactly one argument: <local-mount-point|instance>")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.All {
				opts.Path = args[0]
			}
			if runF != nil {
				return runF(opts)
			}
			if opts.All {
				return opts.UnmountAll()
			}
			return opts.Run(opts.Path)
		},
	}

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Force unmount (lazy unmount on Linux; diskutil force on macOS)")
	cmd.Flags().BoolVar(&opts.All, "all", false, "Unmount all abox mounts")

	return cmd
}

// doUnmountFn is the mount-teardown seam, overridable in tests. It defaults to
// the platform doUnmount (fusermount on Linux, diskutil on macOS).
var doUnmountFn = doUnmount

// Run executes the unmount command for a single target.
func (o *Options) Run(target string) error {
	// Determine if target is a path or instance name
	// If it contains a path separator or starts with ~, treat as path
	if strings.Contains(target, string(os.PathSeparator)) || strings.HasPrefix(target, "~") || strings.HasPrefix(target, ".") {
		return o.unmountPath(target)
	}

	// Check if it's an instance name
	if config.Exists(target) {
		return o.unmountInstance(target)
	}

	// Try as path (might be a relative path that exists)
	return o.unmountPath(target)
}

// unmountPath unmounts a specific path.
func (o *Options) unmountPath(localPath string) error {
	// Expand and resolve path
	if strings.HasPrefix(localPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		localPath = filepath.Join(home, localPath[2:])
	}

	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Check if mounted. --force must still attempt teardown even when the mount
	// looks absent: a dead FUSE/SSHFS endpoint can defeat detection, and lazy
	// unmount (Linux -z) / `diskutil unmount force` (macOS) both tolerate an
	// already-gone mount. Refusing here is what made --force unable to clean the
	// exact stale mount it exists for.
	if !o.Force && !mountutil.IsMounted(absPath) {
		return fmt.Errorf("path %q is not mounted", absPath)
	}

	// Unmount (fusermount on Linux, umount/diskutil on macOS)
	if err := doUnmountFn(absPath, o.Force); err != nil {
		return err
	}

	// Try to remove mount record from all instances
	// We don't know which instance it belongs to, so try all
	o.removeMountFromAllInstances(absPath)

	fmt.Fprintf(o.Factory.IO.Out, "Unmounted %s\n", absPath)

	logging.Audit("unmount by path", "action", logging.ActionUnmount, "path", absPath)

	return nil
}

// unmountMounts tears down every recorded mount for one instance, honoring
// --force. --force still attempts teardown even when a mount looks absent: a dead
// FUSE/SSHFS endpoint can defeat detection, and lazy unmount (Linux -z) /
// `diskutil unmount force` (macOS) tolerate an already-gone mount — this gate
// mirrors unmountPath's. It returns the number unmounted and any per-path errors;
// suffix is appended to each success line (the --all view labels the instance).
func (o *Options) unmountMounts(instanceName, instanceDir string, mounts []mount.MountEntry, suffix string) (int, []string) {
	w := o.Factory.IO.Out
	var errs []string
	unmounted := 0

	for _, m := range mounts {
		if !o.Force && !mountutil.IsMounted(m.LocalPath) {
			// Not mounted, just remove the record.
			_ = mount.RemoveMountRecord(instanceDir, m.LocalPath)
			continue
		}

		if err := doUnmountFn(m.LocalPath, o.Force); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", m.LocalPath, err))
			continue
		}

		if err := mount.RemoveMountRecord(instanceDir, m.LocalPath); err != nil {
			logging.Warn("failed to remove mount record", "error", err, "path", m.LocalPath)
		}

		fmt.Fprintf(w, "Unmounted %s%s\n", m.LocalPath, suffix)
		unmounted++

		logging.AuditInstance(instanceName, logging.ActionUnmount, "path", m.LocalPath)
	}

	return unmounted, errs
}

// unmountInstance unmounts all mounts for an instance.
func (o *Options) unmountInstance(instanceName string) error {
	_, paths, err := config.Load(instanceName)
	if err != nil {
		return err
	}

	mounts, err := mount.GetMounts(paths.Instance)
	if err != nil {
		return fmt.Errorf("failed to load mounts: %w", err)
	}

	w := o.Factory.IO.Out
	if len(mounts) == 0 {
		fmt.Fprintf(w, "No mounts found for instance %q\n", instanceName)
		return nil
	}

	unmounted, errs := o.unmountMounts(instanceName, paths.Instance, mounts, "")

	if len(errs) > 0 {
		return &cmdutil.ErrHint{
			Err:  errors.New("failed to unmount some paths"),
			Hint: strings.Join(errs, "\n  "),
		}
	}

	if unmounted == 0 {
		fmt.Fprintln(w, "No active mounts to unmount")
	}

	return nil
}

// UnmountAll unmounts all abox mounts.
func (o *Options) UnmountAll() error {
	instances, err := config.List()
	if err != nil {
		return fmt.Errorf("failed to list instances: %w", err)
	}

	w := o.Factory.IO.Out
	if len(instances) == 0 {
		fmt.Fprintln(w, "No instances found")
		return nil
	}

	var errs []string
	unmounted := 0

	for _, instanceName := range instances {
		_, paths, err := config.Load(instanceName)
		if err != nil {
			continue
		}

		mounts, err := mount.GetMounts(paths.Instance)
		if err != nil {
			continue
		}

		n, e := o.unmountMounts(instanceName, paths.Instance, mounts, fmt.Sprintf(" (instance: %s)", instanceName))
		unmounted += n
		errs = append(errs, e...)
	}

	if len(errs) > 0 {
		return &cmdutil.ErrHint{
			Err:  errors.New("failed to unmount some paths"),
			Hint: strings.Join(errs, "\n  "),
		}
	}

	if unmounted == 0 {
		fmt.Fprintln(w, "No active mounts to unmount")
	}

	return nil
}

// removeMountFromAllInstances tries to remove a mount record from all instances.
func (o *Options) removeMountFromAllInstances(localPath string) {
	instances, err := config.List()
	if err != nil {
		return
	}

	for _, instanceName := range instances {
		_, paths, err := config.Load(instanceName)
		if err != nil {
			continue
		}
		_ = mount.RemoveMountRecord(paths.Instance, localPath)
	}
}
