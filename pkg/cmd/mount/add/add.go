package add

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/mountutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"
	"github.com/sandialabs/abox/pkg/cmd/mount/shared"

	"github.com/spf13/cobra"
)

// Options holds the options for the mount add command.
type Options struct {
	Factory    *factory.Factory
	ReadOnly   bool
	AllowOther bool
	Name       string // Instance spec (positional arg, e.g. "dev" or "dev:/var/log")
	MountPoint string // Local mount point (positional arg)
}

// NewCmdAdd creates a new mount add command.
func NewCmdAdd(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "add [flags] <instance>[:<remote-path>] <local-mount-point>",
		Short: "Mount an abox instance filesystem via SSHFS",
		Long: `Mount a running instance's filesystem locally using SSHFS.

The mount is recorded so it can be listed with 'abox mount list' and cleaned up
with 'abox mount remove' (or 'abox unmount'). Specify a remote path with the
instance:path syntax, or omit it to mount the home directory.`,
		Example: `  abox mount add dev ~/mnt/dev                      # mount home dir
  abox mount add dev:/var/log ~/mnt/dev-logs        # specific path
  abox mount add --read-only dev:/etc ~/mnt/dev-etc # read-only`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completion.Sequence(completion.AllInstances()),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Name = args[0]
			opts.MountPoint = args[1]
			if runF != nil {
				return runF(opts)
			}
			return opts.Run(opts.Name, opts.MountPoint)
		},
	}

	cmd.Flags().BoolVarP(&opts.ReadOnly, "read-only", "r", false, "Mount as read-only")
	cmd.Flags().BoolVarP(&opts.AllowOther, "allow-other", "o", false, "Allow other users to access the mount")

	return cmd
}

// parseInstanceSpec parses <instance>[:<path>] format.
// Returns (instance, remotePath). If no path specified, remotePath is empty.
func parseInstanceSpec(spec string) (string, string) {
	if idx := strings.Index(spec, ":"); idx > 0 {
		return spec[:idx], spec[idx+1:]
	}
	// No path specified - will default to user's home directory
	return spec, ""
}

// Run executes the mount command.
func (o *Options) Run(instanceSpec, localPath string) error {
	// Check if sshfs is installed
	if _, err := exec.LookPath("sshfs"); err != nil {
		return errors.New(sshfsMissingHint())
	}

	instanceName, remotePath := parseInstanceSpec(instanceSpec)

	factory.Ensure(&o.Factory)
	be, err := o.Factory.BackendFor(instanceName)
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	inst, paths, err := instance.LoadRunning(instanceName, be.VM())
	if err != nil {
		return err
	}

	// Note: SSH user is validated at config load time
	sshUser := inst.GetUser()

	// Default remote path to user's home directory
	if remotePath == "" {
		remotePath = "/home/" + sshUser
	}

	ip, err := instance.GetIP(inst, be.VM())
	if err != nil {
		return err
	}

	// Expand and resolve local path
	if strings.HasPrefix(localPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		localPath = filepath.Join(home, localPath[2:])
	}

	absLocalPath, err := filepath.Abs(localPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Create mount point if needed (mode 0o700 restricts access to owner only)
	if err := os.MkdirAll(absLocalPath, 0o700); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}

	// Check if already mounted
	if mountutil.IsMounted(absLocalPath) {
		return fmt.Errorf("path %q is already mounted", absLocalPath)
	}

	entry := shared.MountEntry{
		LocalPath:  absLocalPath,
		RemotePath: remotePath,
		ReadOnly:   o.ReadOnly,
		AllowOther: o.AllowOther,
	}

	if err := shared.Mount(paths, sshUser, ip, entry); err != nil {
		return err
	}

	// Record mount in mounts.json (flags included so `abox start` can
	// re-establish the mount with the same semantics)
	if err := shared.AddMountRecord(paths.Instance, entry); err != nil {
		// Mount succeeded but recording failed - warn but don't fail
		logging.Warn("failed to record mount", "error", err, "instance", instanceName)
	}

	fmt.Fprintf(o.Factory.IO.Out, "Mounted %s:%s at %s\n", instanceName, remotePath, absLocalPath)

	logging.AuditInstance(instanceName, logging.ActionMount, "local_path", absLocalPath, "remote_path", remotePath)

	return nil
}

// sshfsMissingHint returns a platform-appropriate error message when the sshfs
// binary is not found. On macOS we recommend fuse-t, a kext-less FUSE
// implementation (no System Extension approval or reboot), over macFUSE.
func sshfsMissingHint() string {
	if runtime.GOOS == "darwin" {
		return "sshfs not found; install the kext-less fuse-t (recommended over macFUSE): " +
			"brew tap macos-fuse-t/homebrew-cask && brew install fuse-t fuse-t-sshfs"
	}
	return "sshfs not found; please install sshfs (see 'abox check-deps')"
}
