package mount

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sandialabs/abox/internal/instance"
	"github.com/sandialabs/abox/internal/logging"
	"github.com/sandialabs/abox/internal/mountutil"
	"github.com/sandialabs/abox/internal/procutil"
	"github.com/sandialabs/abox/internal/sshutil"
	"github.com/sandialabs/abox/pkg/cmd/completion"
	"github.com/sandialabs/abox/pkg/cmd/factory"

	"github.com/spf13/cobra"
)

// MountEntry represents a single mount record.
type MountEntry struct {
	LocalPath  string    `json:"local_path"`
	RemotePath string    `json:"remote_path"`
	MountedAt  time.Time `json:"mounted_at"`
}

// MountsFile represents the mounts.json structure.
type MountsFile struct {
	Mounts []MountEntry `json:"mounts"`
}

// Options holds the options for the mount command.
type Options struct {
	Factory    *factory.Factory
	ReadOnly   bool
	AllowOther bool
	Name       string // Instance spec (positional arg, e.g. "dev" or "dev:/var/log")
	MountPoint string // Local mount point (positional arg)
}

// NewCmdMount creates a new mount command.
func NewCmdMount(f *factory.Factory, runF func(*Options) error) *cobra.Command {
	opts := &Options{
		Factory: f,
	}

	cmd := &cobra.Command{
		Use:   "mount [flags] <instance>[:<remote-path>] <local-mount-point>",
		Short: "Mount an abox instance filesystem via SSHFS",
		Long: `Mount a running instance's filesystem locally using SSHFS.

The mount is recorded so it can be cleaned up with 'abox unmount'. Specify
a remote path with the instance:path syntax, or omit it to mount the home
directory.`,
		Example: `  abox mount dev ~/mnt/dev                      # mount home dir
  abox mount dev:/var/log ~/mnt/dev-logs        # specific path
  abox mount --read-only dev:/etc ~/mnt/dev-etc # read-only`,
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

	// Build sshfs command
	// Use TOFU model matching sshutil.CommonOptions
	sshfsArgs := []string{
		sshutil.RemotePath(sshUser, ip, remotePath),
		absLocalPath,
		"-o", "IdentityFile=" + paths.SSHKey,
		"-o", "IdentitiesOnly=yes",
		// Pre-8.5 keyword name; a permanent alias on newer OpenSSH. See the
		// sshOptPubkeyAlgos comment in internal/sshutil for why not the
		// PubkeyAcceptedAlgorithms spelling.
		"-o", "PubkeyAcceptedKeyTypes=+ssh-ed25519",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + paths.KnownHosts,
		"-o", "LogLevel=ERROR",
	}

	if o.ReadOnly {
		sshfsArgs = append(sshfsArgs, "-o", "ro")
	}
	if o.AllowOther {
		sshfsArgs = append(sshfsArgs, "-o", "allow_other")
	}

	if err := runSSHFS(paths.LogsDir, absLocalPath, sshfsArgs); err != nil {
		return err
	}

	// Record mount in mounts.json
	if err := addMountRecord(paths.Instance, absLocalPath, remotePath); err != nil {
		// Mount succeeded but recording failed - warn but don't fail
		logging.Warn("failed to record mount", "error", err, "instance", instanceName)
	}

	fmt.Fprintf(o.Factory.IO.Out, "Mounted %s:%s at %s\n", instanceName, remotePath, absLocalPath)

	logging.AuditInstance(instanceName, logging.ActionMount, "local_path", absLocalPath, "remote_path", remotePath)

	return nil
}

// runSSHFS launches sshfs detached, sending its output to logsDir/mount.log, and
// waits for the mount at localPath to appear. It returns nil once mounted, or an
// error if sshfs fails or the mount never materializes within the timeout.
//
// sshfs must run detached rather than via a blocking Run(): on macOS macFUSE's
// sshfs stays in the FOREGROUND for the life of the mount, so Run() would never
// return; on Linux sshfs self-daemonizes. Wiring its output to the caller's stdio
// would also let a foreground sshfs hold the caller's pipes open, hanging anything
// reading them (this is what deadlocked the e2e harness). mountutil.IsMounted is
// therefore the source of truth: on Linux the foreground helper exits ~immediately
// after forking the real daemon, so an early clean exit is NOT a failure — only a
// non-zero exit or the mount never appearing is.
func runSSHFS(logsDir, localPath string, sshfsArgs []string) error {
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logPath := filepath.Join(logsDir, "mount.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open mount log: %w", err)
	}
	defer logFile.Close()

	cmd := exec.Command("sshfs", sshfsArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	procutil.Detach(cmd) // own process group so the daemon outlives this command

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sshfs: %w", err)
	}

	// Reap the child so a foreground sshfs that exits early doesn't linger as a
	// zombie, and so we can distinguish an sshfs error from a clean daemonize.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	const (
		mountTimeout  = 10 * time.Second
		mountInterval = 100 * time.Millisecond
	)
	deadline := time.Now().Add(mountTimeout)
	var exitErr error
	sshfsExited := false
	for !mountutil.IsMounted(localPath) {
		if sshfsExited && exitErr != nil {
			// sshfs is gone with an error and nothing is mounted -> real failure.
			return fmt.Errorf("sshfs failed to mount (see %s): %w", logPath, exitErr)
		}
		if time.Now().After(deadline) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return fmt.Errorf("sshfs did not mount %s within %s; see %s", localPath, mountTimeout, logPath)
		}
		select {
		case werr := <-exited:
			exitErr = werr
			sshfsExited = true
		case <-time.After(mountInterval):
		}
	}
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

// getMountsFilePath returns the path to mounts.json for an instance.
func getMountsFilePath(instanceDir string) string {
	return filepath.Join(instanceDir, "mounts.json")
}

// loadMounts loads the mounts file for an instance.
func loadMounts(instanceDir string) (*MountsFile, error) {
	path := getMountsFilePath(instanceDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &MountsFile{Mounts: []MountEntry{}}, nil
	}
	if err != nil {
		return nil, err
	}

	var mounts MountsFile
	if err := json.Unmarshal(data, &mounts); err != nil {
		return nil, err
	}
	return &mounts, nil
}

// saveMounts saves the mounts file for an instance.
func saveMounts(instanceDir string, mounts *MountsFile) error {
	path := getMountsFilePath(instanceDir)
	data, err := json.MarshalIndent(mounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// addMountRecord adds a mount to the mounts file.
func addMountRecord(instanceDir, localPath, remotePath string) error {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return err
	}

	mounts.Mounts = append(mounts.Mounts, MountEntry{
		LocalPath:  localPath,
		RemotePath: remotePath,
		MountedAt:  time.Now(),
	})

	return saveMounts(instanceDir, mounts)
}

// RemoveMountRecord removes a mount from the mounts file (exported for unmount command).
func RemoveMountRecord(instanceDir, localPath string) error {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return err
	}

	filtered := make([]MountEntry, 0, len(mounts.Mounts))
	for _, m := range mounts.Mounts {
		if m.LocalPath != localPath {
			filtered = append(filtered, m)
		}
	}
	mounts.Mounts = filtered

	return saveMounts(instanceDir, mounts)
}

// GetMounts returns all mounts for an instance (exported for unmount command).
func GetMounts(instanceDir string) ([]MountEntry, error) {
	mounts, err := loadMounts(instanceDir)
	if err != nil {
		return nil, err
	}
	return mounts.Mounts, nil
}
