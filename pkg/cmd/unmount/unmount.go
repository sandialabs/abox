package unmount

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandialabs/abox/internal/config"
	"github.com/sandialabs/abox/internal/logging"
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

	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "Force unmount (lazy unmount if busy)")
	cmd.Flags().BoolVar(&opts.All, "all", false, "Unmount all abox mounts")

	return cmd
}

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

	// Check if mounted
	if !isMounted(absPath) {
		return fmt.Errorf("path %q is not mounted", absPath)
	}

	// Unmount using fusermount
	if err := doUnmount(absPath, o.Force); err != nil {
		return err
	}

	// Try to remove mount record from all instances
	// We don't know which instance it belongs to, so try all
	o.removeMountFromAllInstances(absPath)

	fmt.Fprintf(o.Factory.IO.Out, "Unmounted %s\n", absPath)

	logging.Audit("unmount by path", "action", logging.ActionUnmount, "path", absPath)

	return nil
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

	var errs []string
	unmounted := 0

	for _, m := range mounts {
		if !isMounted(m.LocalPath) {
			// Not mounted, just remove the record
			_ = mount.RemoveMountRecord(paths.Instance, m.LocalPath)
			continue
		}

		if err := doUnmount(m.LocalPath, o.Force); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", m.LocalPath, err))
			continue
		}

		if err := mount.RemoveMountRecord(paths.Instance, m.LocalPath); err != nil {
			logging.Warn("failed to remove mount record", "error", err, "path", m.LocalPath)
		}

		fmt.Fprintf(w, "Unmounted %s\n", m.LocalPath)
		unmounted++

		logging.AuditInstance(instanceName, logging.ActionUnmount, "path", m.LocalPath)
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

		for _, m := range mounts {
			if !isMounted(m.LocalPath) {
				// Not mounted, just remove the record
				_ = mount.RemoveMountRecord(paths.Instance, m.LocalPath)
				continue
			}

			if err := doUnmount(m.LocalPath, o.Force); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", m.LocalPath, err))
				continue
			}

			if err := mount.RemoveMountRecord(paths.Instance, m.LocalPath); err != nil {
				logging.Warn("failed to remove mount record", "error", err, "path", m.LocalPath)
			}

			fmt.Fprintf(w, "Unmounted %s (instance: %s)\n", m.LocalPath, instanceName)
			unmounted++

			logging.AuditInstance(instanceName, logging.ActionUnmount, "path", m.LocalPath)
		}
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

// isMounted checks if a path is a mount point.
func isMounted(path string) bool {
	cmd := exec.Command("mountpoint", "-q", path)
	return cmd.Run() == nil
}

// doUnmount performs the actual unmount operation.
func doUnmount(path string, force bool) error {
	args := []string{"-u"}
	if force {
		args = append(args, "-z") // lazy unmount
	}
	args = append(args, path)

	cmd := exec.Command("fusermount", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unmount: %s: %w", strings.TrimSpace(string(output)), err)
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
